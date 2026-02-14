"""Password hash cracking tools.

This module provides toolsets for cracking password hashes using
hashcat (GPU-accelerated) and John the Ripper (CPU-based).
"""

import asyncio
import re
import time
from pathlib import Path

import dreadnode as dn
from dreadnode.agent.tools.base import Toolset
from loguru import logger

from ares.tools.red.common import (
    AnyRedTeamState,
    run_tool,
)


class CrackingTools(Toolset):
    """Tools for password hash cracking."""

    state: AnyRedTeamState | None = None

    def set_state(self, state: AnyRedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

    def _build_user_wordlist(self) -> str | None:
        if not self.state:
            return None

        usernames = self._collect_usernames_from_state()
        words = self._generate_password_candidates(usernames)

        if not words:
            return None

        import tempfile

        wordlist_path = f"{tempfile.gettempdir()}/ares_users_{int(time.time())}.txt"
        with open(wordlist_path, "w", encoding="ascii") as handle:
            handle.writelines(f"{word}\n" for word in sorted(words))

        return wordlist_path

    def _collect_usernames_from_state(self) -> set[str]:
        """Collect usernames from state objects."""
        usernames: set[str] = set()
        if not self.state:
            return usernames
        state = self.state
        if hasattr(state, "all_users"):
            for user in state.all_users:
                if user.username:
                    usernames.add(user.username)
        if hasattr(state, "all_credentials"):
            for cred in state.all_credentials:
                if cred.username:
                    usernames.add(cred.username)
        if hasattr(state, "all_hashes"):
            for hash_obj in state.all_hashes:
                if hash_obj.username:
                    usernames.add(hash_obj.username)
        return usernames

    def _generate_password_candidates(self, usernames: set[str]) -> set[str]:
        """Generate password candidates from usernames."""
        words: set[str] = set()
        suffixes = ("", "1", "123", "!", "2024", "2025")

        for username_raw in sorted(usernames):
            username = (username_raw or "").strip()
            if not username or username.lower() == "guest":
                continue
            if "/" in username or "\\" in username or username.endswith(".txt"):
                continue

            base = username.lower()
            parts = [p for p in re.split(r"[^a-z0-9]+", base) if p]

            candidates = {base}
            candidates.update(parts)
            if len(parts) >= 2:
                first, last = parts[0], parts[-1]
                candidates.update(
                    {first + last, last + first, f"{first[0]}{last}", f"{first}{last[0]}"}
                )

            for cand in candidates:
                for variant in (cand, cand.capitalize(), cand.upper()):
                    for suffix in suffixes:
                        words.add(f"{variant}{suffix}")

        return words

    @dn.tool_method
    async def crack_with_hashcat(
        self,
        hash_value: str,
        hashcat_mode: int = 13100,
        wordlist_path: str = "/usr/share/wordlists/rockyou.txt",
        max_time_minutes: int | None = 10,
        use_dynamic_wordlist: bool = True,
    ) -> str:
        """
        Attempt to crack a password hash using hashcat (GPU-accelerated).

        Hashcat is faster than John the Ripper when GPU is available. Use this FIRST.
        Common hash modes: NTLM (1000), Kerberos TGS (13100), Kerberos AS-REP (18200).

        **IMMEDIATELY report any successful cracks - don't wait for completion.**

        Args:
            hash_value: Hash to crack
            hashcat_mode: Hashcat mode (-m parameter). Common modes:
                - 1000: NTLM
                - 13100: Kerberos TGS ($krb5tgs$)
                - 18200: Kerberos AS-REP ($krb5asrep$)
            wordlist_path: Path to wordlist file (default: rockyou.txt)
            max_time_minutes: Maximum time to spend cracking (default: 10 minutes, None=unlimited)

        Returns:
            Cracked passwords if successful, otherwise error message

        Example:
            >>> crack_with_hashcat("aad3b435b51404ee...", 1000)  # NTLM
            >>> crack_with_hashcat("$krb5tgs$23$*user$...", 13100)  # Kerberos TGS
        """
        output = "[*] Starting hashcat...\n"

        hash_file_path = f"/tmp/hash_{time.time()}.hash"  # noqa: S108  # nosec B108
        dynamic_wordlist = self._build_user_wordlist() if use_dynamic_wordlist else None
        if dynamic_wordlist:
            wordlist_path = dynamic_wordlist
            output += f"[*] Using wordlist: {wordlist_path}\n"
            logger.info("[*] Using dynamic user-based wordlist for cracking")

        try:
            # Build runtime flag only if time limit is specified
            runtime_flag = f"--runtime {max_time_minutes * 60}" if max_time_minutes else ""
            cmd = f"""
echo '{hash_value}' > {hash_file_path}
hashcat -m {hashcat_mode} -a 0 {hash_file_path} {wordlist_path} {runtime_flag} --force 2>&1 || true
hashcat -m {hashcat_mode} {hash_file_path} --show 2>&1
rm -f {hash_file_path}
"""
            # Use 30 min default timeout if no time limit specified
            timeout = (max_time_minutes * 60 + 60) if max_time_minutes else 1800
            stdout, stderr, _ = await asyncio.to_thread(
                run_tool,
                ["bash", "-c", cmd],
                timeout_seconds=timeout,
            )

            if stdout and ":" in stdout:
                output += "\n\u2713 CRACKED PASSWORDS:\n" + stdout
                logger.info("[+] Hashcat successfully cracked hash")
            else:
                output += "\n\u2717 No passwords cracked\n" + (stdout or stderr)

            return output

        except Exception as e:
            return output + f"\nError: {e!s}"
        finally:
            if dynamic_wordlist:
                try:
                    Path(dynamic_wordlist).unlink()
                except Exception:
                    pass

    @dn.tool_method
    async def crack_with_john(
        self,
        hash_value: str,
        hash_format: str = "krb5tgs",
        wordlist_path: str = "/usr/share/wordlists/rockyou.txt",
        max_time_minutes: int = 10,
        use_dynamic_wordlist: bool = True,
    ) -> str:
        """
        Attempt to crack a password hash using John the Ripper.

        John is reliable and works on all systems without GPU. Use when hashcat fails
        or on systems without GPU support.

        Common hash formats: krb5tgs (Kerberos TGS), krb5asrep (AS-REP), nt (NTLM).

        Args:
            hash_value: Hash to crack
            hash_format: John format (--format parameter)
            wordlist_path: Path to wordlist file (default: rockyou.txt)
            max_time_minutes: Maximum time to spend cracking (default: 10 minutes)

        Returns:
            Cracked passwords if successful, otherwise error message

        Example:
            >>> crack_with_john("$krb5tgs$23$*user$...", "krb5tgs")
        """
        output = "[*] Starting John the Ripper...\n"

        hash_file_path = f"/tmp/john_hash_{time.time()}.hash"  # noqa: S108  # nosec B108
        dynamic_wordlist = self._build_user_wordlist() if use_dynamic_wordlist else None
        if dynamic_wordlist:
            wordlist_path = dynamic_wordlist
            output += f"[*] Using wordlist: {wordlist_path}\n"
            logger.info("[*] Using dynamic user-based wordlist for cracking")

        try:
            cmd = f"""
echo '{hash_value}' > {hash_file_path}
timeout {max_time_minutes * 60}s john --format={hash_format} --wordlist={wordlist_path} {hash_file_path} 2>&1 || true
john --show --format={hash_format} {hash_file_path} 2>&1
rm -f {hash_file_path}
"""
            stdout, stderr, _ = await asyncio.to_thread(
                run_tool,
                ["bash", "-c", cmd],
                timeout_seconds=(max_time_minutes * 60) + 60,
            )

            if stdout and ":" in stdout:
                output += "\n\u2713 CRACKED PASSWORDS:\n" + stdout
                logger.info("[+] John successfully cracked hash")
            else:
                output += "\n\u2717 No passwords cracked\n" + (stdout or stderr)

            return output

        except Exception as e:
            return output + f"\nError: {e!s}"
        finally:
            if dynamic_wordlist:
                try:
                    Path(dynamic_wordlist).unlink()
                except Exception:
                    pass
