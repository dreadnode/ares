#!/usr/bin/env bash
# Reproducibly build the `ares-golden-image` AMI: a tool-complete Kali attacker
# box with a WORKING GPU (NVIDIA driver + hashcat OpenCL, ~40 GH/s NTLM on a T4).
#
# Why this and not the warpgate template: the NVIDIA driver must be installed
# against the in-repo cloud kernel and the box MUST reboot into it before GPU
# compute works (otherwise hashcat enumerates the T4 but hangs on kernel build).
# EC2 Image Builder can't reboot the Kali builder mid-build (its SSM workflow
# doesn't rejoin -> CANCELLED), so we build on a plain instance that handles its
# own reboot (see ares-golden-userdata.sh) and snapshot it here.
#
# Usage: BUCKET=<your-staging-bucket> SUBNET=subnet-... SG=sg-... \
#        PROFILE_NAME=<your-instance-profile> \
#        AWS_PROFILE=<your-aws-profile> \
#        scripts/build-ares-golden-ami.sh
set -euo pipefail
: "${AWS_PROFILE:?set AWS_PROFILE (e.g. personal)}"
export AWS_PROFILE
export AWS_REGION="${AWS_REGION:-us-east-1}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

: "${BUCKET:?set BUCKET to an S3 bucket you can write to in $AWS_REGION}"
PFX="s3://$BUCKET/ares-golden-build"
: "${SUBNET:?set SUBNET to a public subnet-id in $AWS_REGION}"
: "${SG:?set SG to a security-group-id with egress in $AWS_REGION}"
: "${PROFILE_NAME:?set PROFILE_NAME to an instance profile granting SSM + S3 + EC2RO}"

echo "[1/6] upload ares ansible collection to S3"
tar -czf /tmp/ares-ansible.tar.gz -C "$HERE/../ansible" .
aws s3 cp /tmp/ares-ansible.tar.gz "$PFX/ares-ansible.tar.gz"
aws s3 rm "$PFX/TOOLS_INSTALL_DONE" 2>/dev/null || true

USERDATA=$(mktemp /tmp/ares-golden-userdata.XXXXXX)
trap 'rm -f "$USERDATA"' EXIT
sed -e "s|__BUCKET__|$BUCKET|g" -e "s|__AWS_REGION__|$AWS_REGION|g" \
	"$HERE/ares-golden-userdata.sh" >"$USERDATA"
grep -q '__BUCKET__\|__AWS_REGION__' "$USERDATA" &&
	{
		echo "unrendered placeholder left in $USERDATA"
		exit 1
	}

echo "[2/6] resolve latest Kali base AMI + launch builder (g4dn.xlarge)"
KALI=$(aws ec2 describe-images --owners 679593333241 \
	--filters "Name=name,Values=debian-kali-last-snapshot-amd64-*" "Name=architecture,Values=x86_64" \
	--query 'sort_by(Images,&CreationDate)[-1].ImageId' --output text)
IID=$(aws ec2 run-instances --image-id "$KALI" --instance-type g4dn.xlarge \
	--subnet-id "$SUBNET" --security-group-ids "$SG" --associate-public-ip-address \
	--iam-instance-profile Name="$PROFILE_NAME" \
	--block-device-mappings '[{"DeviceName":"/dev/xvda","Ebs":{"VolumeSize":100,"VolumeType":"gp3"}}]' \
	--user-data "file://$USERDATA" \
	--tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=ares-golden-builder}]' \
	--query 'Instances[0].InstanceId' --output text)
echo "      builder=$IID base=$KALI"

echo "[3/6] wait for build (driver install -> reboot -> toolset install), ~30-45min"
RC=""
for _ in $(seq 1 100); do
	RC=$(aws s3 cp "$PFX/TOOLS_INSTALL_DONE" - 2>/dev/null || true)
	[ -n "$RC" ] && break
	sleep 30
done
[ -n "$RC" ] || {
	echo "TIMEOUT waiting for build; see $PFX/build.log and instance $IID"
	exit 1
}
echo "      toolset install rc=$RC"
[ "$RC" = "0" ] || {
	echo "playbook FAILED (rc=$RC); inspect $PFX/build.log (builder left running: $IID)"
	exit 1
}

echo "[4/6] create AMI from the validated builder"
AMI=$(aws ec2 create-image --instance-id "$IID" \
	--name "ares-golden-image-$(date -u +%Y%m%d-%H%M%S)" \
	--description "Kali + NVIDIA driver (rebooted/validated) + full ares toolset + hashcat GPU (~40 GH/s T4)" \
	--tag-specifications 'ResourceType=image,Tags=[{Key=Name,Value=ares-golden-image},{Key=Project,Value=ares},{Key=ManagedBy,Value=build-ares-golden-ami.sh}]' \
	--query 'ImageId' --output text)
echo "      AMI=$AMI"

echo "[5/6] wait for AMI available"
aws ec2 wait image-available --image-ids "$AMI"

echo "[6/6] terminate builder $IID"
aws ec2 terminate-instances --instance-ids "$IID" >/dev/null

echo "DONE. ares-golden-image = $AMI (tool-complete + GPU-verified)"
echo "$AMI"
