# GOAD Deployment & Attack Readiness Checklist

Comprehensive checklist for GOAD lab provisioning, user/group creation, vulnerability configuration, and attack surface validation. Use this on every fresh op — tick items as you confirm provisioning, enumerate, or exploit.

**How to use:**

- Each item is `[ ]` until validated. Mark `[x]` when confirmed (enumerated, exploited, or otherwise verified for the current op).
- Categories progress roughly in attack-chain order: provisioning → enumeration → poisoning/coercion → Kerberos → ADCS → MSSQL → privesc → lateral → trust → CVE → post-ex.
- "Configured in Ansible" notes name the role under `ansible/roles/` (DreadGOAD repo) for cross-reference.
- Source of truth: `ad/GOAD/data/config.json` and `docs/GOAD-vulnerabilities-comprehensive.md` in DreadGOAD.

---

## 1. Infrastructure & Domain Setup

### Hosts

- [ ] DC01 (kingslanding) — sevenkingdoms.local Domain Controller (parent)
- [ ] DC02 (winterfell) — north.sevenkingdoms.local Domain Controller (child)
- [ ] DC03 (meereen) — essos.local Domain Controller
- [ ] SRV02 (castelblack) — north.sevenkingdoms.local Member Server
- [ ] SRV03 (braavos) — essos.local Member Server

### Domains & Trusts

- [ ] sevenkingdoms.local forest root created
- [ ] north.sevenkingdoms.local child domain created
- [ ] essos.local forest root created
- [ ] Bidirectional forest trust: sevenkingdoms.local <-> essos.local (no SID filtering by default)
- [ ] Parent-child trust: sevenkingdoms.local <-> north.sevenkingdoms.local
- [ ] Parent-child DNS conditional forwarder configured (Ansible role: `parent_child_dns`)

### Services per Host

- [ ] DC01: ADCS Web Enrollment, Defender ON
- [ ] DC02: LLMNR enabled, NBT-NS enabled, SMB shares, Defender ON
- [ ] DC03: ADCS custom templates, LAPS DC, NTLM downgrade, Defender ON
- [ ] SRV02: IIS (with upload folder), MSSQL (+SSMS), WebDAV, SMB shares, Defender OFF
- [ ] SRV03: MSSQL, WebDAV, LAPS, SMB shares, RunAsPPL, Defender ON

---

## 2. Users

### sevenkingdoms.local

- [ ] robert.baratheon / `iamthekingoftheworld` — Baratheon, Domain Admins, Small Council, Protected Users
- [ ] cersei.lannister / `il0vejaime` — Lannister, Baratheon, Domain Admins, Small Council
- [ ] tywin.lannister / `powerkingftw135` — Lannister
- [ ] jaime.lannister / `cersei` — Lannister
- [ ] tyron.lannister / `Alc00L&S3x` — Lannister
- [ ] joffrey.baratheon / `1killerlion` — Baratheon, Lannister
- [ ] renly.baratheon / `lorastyrell` — Baratheon, Small Council
- [ ] stannis.baratheon / `Drag0nst0ne` — Baratheon, Small Council
- [ ] petyer.baelish / `@littlefinger@` — Small Council
- [ ] lord.varys / `_W1sper_$` — Small Council
- [ ] maester.pycelle / `MaesterOfMaesters` — Small Council

### north.sevenkingdoms.local

- [ ] eddard.stark / `FightP3aceAndHonor!` — Stark, Domain Admins
- [ ] catelyn.stark / `robbsansabradonaryarickon` — Stark
- [ ] robb.stark / `sexywolfy` — Stark (autologon creds on DC02)
- [ ] arya.stark / `Needle` — Stark
- [ ] sansa.stark / `345ertdfg` — Stark (Kerberoastable, unconstrained delegation)
- [ ] brandon.stark / `iseedeadpeople` — Stark (DoesNotRequirePreAuth)
- [ ] rickon.stark / `Winter2022` — Stark
- [ ] hodor / `hodor` — Stark (username == password)
- [ ] jon.snow / `iknownothing` — Stark, Night Watch (Kerberoastable, constrained delegation)
- [ ] samwell.tarly / `Heartsbane` — Night Watch (password in description field)
- [ ] jeor.mormont / `_L0ngCl@w_` — Night Watch, Mormont (MSSQL sysadmin on SRV02)
- [ ] sql_svc / `YouWillNotKerboroast1ngMeeeeee` — NORTH service account (Kerberoastable)

### essos.local

- [ ] daenerys.targaryen / `BurnThemAll!` — Targaryen, Domain Admins
- [ ] viserys.targaryen / `GoldCrown` — Targaryen (ManageCA on ESSOS-CA)
- [ ] khal.drogo / `horse` — Dothraki (MSSQL sysadmin on SRV03)
- [ ] jorah.mormont / `H0nnor!` — Targaryen (LAPS reader, Spys group)
- [ ] missandei / `fr3edom` — DoesNotRequirePreAuth, GenericAll on khal.drogo
- [ ] drogon / `Dracarys` — Dragons
- [ ] sql_svc / `YouWillNotKerboroast1ngMeeeeee` — ESSOS service account (Kerberoastable)

### gMSA Accounts

- [ ] gmsaDragon / gmsaDragon.essos.local — SPNs: HTTP/braavos, HTTP/braavos.essos.local
- [ ] gmsaDragon$ has GenericAll on drogon (cross-account ACL primitive)

---

## 3. Groups

### sevenkingdoms.local

- [ ] Lannister (Global, managed by tywin.lannister) — Joffrey/Tyron/Cersei/Jaime/Tywin
- [ ] Baratheon (Global, managed by robert.baratheon) — Stannis, Renly, Joffrey, Robert, Cersei
- [ ] Small Council (Global) — Pycelle, Varys, Baelish, Stannis/Renly/Robert, Cersei
- [ ] DragonStone (Global, empty)
- [ ] KingsGuard (Global, empty)
- [ ] DragonRider (Global, adminCount=1, nested in Administrators — privileged)
- [ ] AcrossTheNarrowSea (Universal) — contains FSP for essos.local member

### north.sevenkingdoms.local

- [ ] Stark (Global, managed by eddard.stark)
- [ ] Night Watch (Global, managed by jeor.mormont)
- [ ] Mormont (Global, managed by jeor.mormont)
- [ ] AcrossTheSea (Domain Local)
- [ ] Domain Admins (eddard, catelyn, robb + standard members)
- [ ] Administrators — contains Enterprise Admins (cross-domain), Domain Admins, Stark members
- [ ] Remote Desktop Users — contains Stark group
- [ ] Backup/Server/Account/Print Operators, DnsAdmins (adminCount=true)

### essos.local

- [ ] Targaryen (Global, managed by viserys.targaryen)
- [ ] Dothraki (Global, managed by khal.drogo)
- [ ] Dragons (Global)
- [ ] QueenProtector (Global, members: Dragons -> Domain Admins)
- [ ] DragonsFriends (Domain Local, managed by daenerys.targaryen)
- [ ] Spys (Domain Local, LAPS reader)

### Cross-Domain Memberships

- [ ] Administrators (north) contains Enterprise Admins from sevenkingdoms.local (FSP)
- [ ] Users (north) contains FSP S-1-5-11 (Authenticated Users)
- [ ] IIS_IUSRS (north) contains FSP S-1-5-17
- [ ] DragonsFriends contains sevenkingdoms.local\tyron.lannister (FSP)
- [ ] DragonsFriends contains essos.local\daenerys.targaryen
- [ ] Spys contains sevenkingdoms.local\Small Council (FSP)
- [ ] AcrossTheNarrowSea (sevenkingdoms) contains essos.local\daenerys.targaryen (FSP)

---

## 4. ACL Attack Paths

### sevenkingdoms.local chain

- [ ] tywin.lannister --ForceChangePassword--> jaime.lannister
- [ ] jaime.lannister --GenericWrite--> joffrey.baratheon
- [ ] joffrey.baratheon --WriteDacl--> tyron.lannister
- [ ] tyron.lannister --Self-Membership--> Small Council
- [ ] Small Council --WriteMembership--> DragonStone
- [ ] DragonStone --WriteOwner--> KingsGuard
- [ ] KingsGuard --GenericAll--> stannis.baratheon
- [ ] stannis.baratheon --GenericAll--> kingslanding$ (DC01) [RBCD path]
- [ ] lord.varys --GenericAll--> Domain Admins (shadow DA — also DA/EA/SA/krbtgt)
- [ ] AcrossTheNarrowSea --GenericAll--> kingslanding$ (DC01) [cross-forest FSP]
- [ ] renly.baratheon --WriteDACL--> OU=Crownlands

### north.sevenkingdoms.local

- [ ] NT AUTHORITY\ANONYMOUS LOGON --ReadProperty + GenericExecute--> DC=North (anonymous enum)
- [ ] jon.snow --GenericAll--> jon.snow (self)

### essos.local chain

- [ ] khal.drogo --GenericAll--> viserys.targaryen
- [ ] khal.drogo --GenericAll--> ESC4 certificate template (config.json: `GenericAll_khal_esc4`)
- [ ] viserys.targaryen --WriteProperty--> jorah.mormont
- [ ] missandei --GenericAll--> khal.drogo
- [ ] DragonsFriends --GenericWrite--> braavos$ (SRV03)
- [ ] Spys --GenericAll--> jorah.mormont
- [ ] gmsaDragon$ --GenericAll--> drogon (config.json: `GenericAll_gmsaDragon_drogo`)

---

## 5. Credential Discovery Vulnerabilities

- [ ] Password in description field: samwell.tarly (`Heartsbane`)
- [ ] Username == password: hodor / `hodor`
- [ ] Username == password: localuser (across all 3 domains, has DA privs — reuse path)
- [ ] Weak password policy in NORTH domain (no complexity, 5-attempt lockout)
- [ ] NULL session / anonymous logon enumeration on WINTERFELL (DC02)
- [ ] Autologon credentials in registry (DC02 HKLM\…\Winlogon, plaintext) — Ansible: `vulns_autologon`
- [ ] Credentials stored in Credential Manager via cmdkey (DC02: TERMSRV/castelblack with NORTH\robb.stark) — Ansible: `vulns_credentials`
- [ ] Plaintext file drops on shares (e.g., `C:\shares\all\arya.txt` on SRV02) — Ansible: `vulns_files`
- [ ] SYSVOL plaintext credentials (`sysvol_fake_script`, `sysvol_secret`) on DC02 — Ansible: `vulns_directory` + `vulns_files`
- [ ] Permissive shares directory permissions on SRV02 (`C:\shares` ACL) — Ansible: `vulns_directory` + `vulns_permissions`
- [ ] Administrator folder exposure (`C:\users\administrator` structure) — Ansible: `vulns_administrator_folder`

---

## 6. Network Poisoning & Relay Vulnerabilities

### LLMNR / NBT-NS Poisoning

- [ ] LLMNR explicitly enabled on DC02 — Ansible: `vulns_enable_llmnr`
- [ ] NBT-NS explicitly enabled on DC02 — Ansible: `vulns_enable_nbt_ns`
- [ ] Scheduled task on Winterfell: robb.stark connects to non-existent share every 1 min — Ansible: `vulns_schedule` / `roles/vulns/responder`
- [ ] robb.stark password (`sexywolfy`) crackable with rockyou.txt
- [ ] robb.stark is local admin on Winterfell (post-capture lateral)

### NTLM Relay

- [ ] Scheduled task on Kingslanding: eddard.stark (DA) connects to non-existent share every 5 min — Ansible: `roles/vulns/ntlm_relay`
- [ ] SMB signing disabled on CASTELBLACK (SRV02) — "signing enabled but not required"
- [ ] SMB signing disabled on BRAAVOS (SRV03) — "message signing disabled"

### LDAP Hardening Bypasses

- [ ] LDAP signing not enforced (LDAPServerSigningRequirements=0) — Ansible: `vulns_no_ldap_signing`
- [ ] LDAP channel binding disabled (LdapEnforceChannelBindings=0) — Ansible: `vulns_no_ldap_channel_binding`
- [ ] LDAP integrity disabled (LDAPServerIntegrity=0) — Ansible: `vulns_no_ldap_integrity`

### Other Network Attacks

- [ ] NTLMv1 downgrade on DC03 (meereen) — Ansible: `vulns_ntlmdowngrade`
- [ ] SMBv1 enabled (legacy protocol) — Ansible: `vulns_smbv1`
- [ ] IPv6 / DHCPv6 poisoning (MITM6) — possible against DCs
- [ ] CVE-2019-1040 (Remove-MIC) NTLM bypass

### Host Hardening Bypasses

- [ ] Windows Defender Firewall disabled on all 5 hosts — Ansible: `vulns_disable_firewall`
- [ ] CredSSP server-side enabled — Ansible: `vulns_enable_credssp_server`
- [ ] CredSSP client-side enabled — Ansible: `vulns_enable_credssp_client`
- [ ] WebDAV-Redirector feature installed (enables HTTP-auth coercion bypass of SMB signing) — Ansible: `webdav`
- [ ] RunAsPPL enabled on SRV03 (LSASS protection — affects credential dumping)

---

## 7. Kerberos Attack Vulnerabilities

### AS-REP Roasting

- [ ] brandon.stark — DoesNotRequirePreAuth, password `iseedeadpeople`
- [ ] missandei — DoesNotRequirePreAuth

### Kerberoasting

- [ ] jon.snow — SPNs: CIFS/HTTP services, password `iknownothing`
- [ ] sansa.stark — SPN: HTTP/eyrie.north.sevenkingdoms.local
- [ ] sql_svc (NORTH) — SPN: MSSQLSvc/castelblack:1433
- [ ] sql_svc (ESSOS) — SPN: MSSQLSvc/braavos:1433

### Delegation

- [ ] Unconstrained delegation: sansa.stark
- [ ] Unconstrained delegation: WINTERFELL$
- [ ] Constrained delegation: jon.snow (with protocol transition / S4U)
- [ ] Constrained delegation: CASTELBLACK$ (HTTP/winterfell target)
- [ ] Machine Account Quota (MAQ) = 10 on all 3 domains
- [ ] RBCD path: stannis.baratheon -> kingslanding$ via GenericAll

---

## 8. ADCS Vulnerabilities

### ADCS Infrastructure

- [ ] ADCS Web Enrollment on DC01 (kingslanding) — `/certsrv` HTTP enrollment
- [ ] ESSOS-CA on SRV03 (braavos) with Web Enrollment + multi-ESC templates
- [ ] certipy_find with essos creds enumerates 40 templates / 18 enabled

### Per-Host ESC Configuration (config.json `vulns` arrays)

- [ ] DC01 (kingslanding): `adcs_esc10_case1`, `adcs_esc10_case2`
- [ ] DC03 (meereen): `adcs_esc7`, `adcs_esc13` (group=greatmaster, template=ESC13), `adcs_esc15`
- [ ] SRV03 (braavos): `adcs_esc6`, `adcs_esc11`
- [ ] SRV03 templates published (`vulns_adcs_templates`): ESC1, ESC2, ESC3, ESC3-CRA, ESC4, ESC9, ESC13, ESC14, ESC15

### ESC Vulnerability Exploitation

- [ ] ESC1 — "ESC1" template, enrollee supplies SAN, any essos user
- [ ] ESC2 — "ESC2" template, Any Purpose EKU
- [ ] ESC3 — "ESC3-CRA" + "ESC3" templates (enrollment agent chain via khal.drogo)
- [ ] ESC4 — "ESC4" template ACL (khal.drogo GenericAll on template)
- [ ] ESC5 — Golden Certificate via CA backup key (requires local admin on braavos, not configured by default)
- [ ] ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 flag on ESSOS-CA
- [ ] ESC7 — ManageCA abuse via viserys.targaryen
- [ ] ESC8 — NTLM relay to Web Enrollment (HTTP `/certsrv` on braavos + kingslanding)
- [ ] ESC9 — UPN spoofing (missandei via GenericAll on khal.drogo)
- [ ] ESC10 — Weak certificate mapping, Case 1 (StrongCertificateBindingEnforcement=0)
- [ ] ESC10 — Weak certificate mapping, Case 2 (CertificateMappingMethods=0x04)
- [ ] ESC11 — RPC relay (IF_ENFORCEENCRYPTICERTREQUEST disabled on ESSOS-CA)
- [ ] ESC13 — Issuance policy abuse (missandei → group via OID)
- [ ] ESC14 — AltSecurityIdentities manipulation (not configured by default in Ansible)
- [ ] ESC15 (CVE-2024-49019) — CRA via application policy OID

### Other ADCS Attacks

- [ ] Certifried (CVE-2022-26923) — computer DNS hostname spoofing → DC impersonation
- [ ] Shadow Credentials (msDS-KeyCredentialLink) — via GenericWrite/GenericAll on user/computer

---

## 9. MSSQL Vulnerabilities

### MSSQL Services

- [ ] MSSQL on SRV02 (castelblack) — SA password `Sup1_sa_P@ssw0rd!`
- [ ] MSSQL on SRV03 (braavos) — SA password `sa_P@ssw0rd!Ess0s`

### Linked Servers (config.json `mssql_link`)

- [ ] castelblack -> braavos (jon.snow → sa, password `sa_P@ssw0rd!Ess0s`) — cross-domain pivot
- [ ] braavos -> castelblack (khal.drogo → sa, password `Sup1_sa_P@ssw0rd!`) — cross-domain pivot
- [ ] Linked-server passwords stored plaintext in MSSQL metadata (post-sysadmin recovery)

### Impersonation Chains

- [ ] SRV02: samwell.tarly EXECUTE AS LOGIN sa
- [ ] SRV02: jeor.mormont (sysadmin) EXECUTE AS LOGIN sa + xp_cmdshell
- [ ] SRV02: brandon.stark EXECUTE AS LOGIN jon.snow
- [ ] SRV02: arya.stark EXECUTE AS USER dbo (master), dbo (msdb)
- [ ] SRV03: jorah.mormont EXECUTE AS LOGIN sa

### Sysadmins

- [ ] SRV02: NORTH\jon.snow is sysadmin
- [ ] SRV03: ESSOS\khal.drogo is sysadmin

### MSSQL Attack Vectors

- [ ] NTLM coercion via xp_dirtree / xp_fileexist
- [ ] xp_cmdshell for OS command execution (SeImpersonate → potato → SYSTEM)
- [ ] Trustworthy database / impersonation escalation
- [ ] Cross-domain pivoting via linked servers

---

## 10. Privilege Escalation Vulnerabilities

- [ ] SeImpersonatePrivilege on MSSQL service accounts (post-xp_cmdshell)
- [ ] IIS upload web shell on SRV02 — `IIS_IUSRS` granted FullControl on `C:\inetpub\wwwroot\upload` (Ansible: `iis` + `vulns_permissions`)
- [ ] PrintSpoofer / SweetPotato / BadPotato (SeImpersonate → SYSTEM)
- [ ] KrbRelayUp (Kerberos relay when LDAP signing not enforced)
- [ ] AMSI bypass (string fragmentation, .NET patching)
- [ ] In-memory .NET assembly execution (PowerSharpPack, Invoke-SharpLoader)
- [ ] Print Spooler service enabled (coercion + CVE vector)
- [ ] SCMUACBypass (medium → high integrity)

---

## 11. Lateral Movement Prerequisites

### Credential Extraction Points

- [ ] SAM database dump from compromised hosts
- [ ] LSA Secrets / cached domain credentials (secretsdump -just-dc)
- [ ] LSASS process dump (lsassy / mimikatz) — note RunAsPPL on SRV03
- [ ] LAPS password reading (jorah.mormont in Spys group, LAPS reader)

### Movement Techniques

- [ ] Pass-the-Hash (PTH) via SMB/WMI
- [ ] Over-Pass-the-Hash (NTLM → Kerberos TGT)
- [ ] Pass-the-Ticket (extracted Kerberos tickets)
- [ ] Evil-WinRM (port 5985/5986)
- [ ] RDP with Restricted Admin
- [ ] Impacket remote execution (psexec, wmiexec, smbexec, atexec, dcomexec)
- [ ] Certificate-based authentication (certipy auth → NTLM hash + ccache)

### Local Admin Access Map

- [ ] DC01 admins: robert.baratheon, cersei.lannister
- [ ] DC02 admins: eddard.stark, catelyn.stark, robb.stark
- [ ] SRV02 admin: jeor.mormont
- [ ] DC03 admin: daenerys.targaryen
- [ ] SRV03 admin: khal.drogo

---

## 12. Domain Trust Exploitation

### Child-to-Parent Escalation

- [ ] Golden Ticket + ExtraSid (north → sevenkingdoms via krbtgt + Enterprise Admins SID-519)
- [ ] Trust Ticket / Inter-Realm TGT (trust key extraction from NTDS)
- [ ] raiseChild.py automated escalation (or equivalent ticketer + secretsdump chain)
- [ ] Unconstrained delegation on DCs for parent DC TGT capture

### Forest-to-Forest Exploitation

- [ ] Password reuse across forests (NTDS dump + spray)
- [ ] Foreign group/user exploitation (FSP-based cross-forest membership)
- [ ] SID History abuse (RID >1000 cross-forest filtering bypass)
- [ ] MSSQL trusted links for cross-forest pivoting

---

## 13. CVE Exploits

- [ ] CVE-2021-42287 / CVE-2021-42278 (noPac / SamAccountName Spoofing) — computer account → DCSync
- [ ] CVE-2021-1675 (PrintNightmare) — Print Spooler DLL injection → SYSTEM
- [ ] CVE-2022-26923 (Certifried) — computer DNS hostname spoofing → DC impersonation
- [ ] CVE-2020-1472 (ZeroLogon) — Netlogon bypass (patched in hardened GOAD; check anyway)
- [ ] CVE-2024-49019 (ESC15) — see §8

---

## 14. User-Level / Coercion Attacks

### File-Based Coercion

- [ ] .lnk / .scf / .url coercion file drop on writable shares
- [ ] Writable share inventory: `10.1.2.254/Public`, `10.1.2.254/All`, `10.1.2.51/thewall`, `10.1.2.51/Public`, `10.1.2.51/All` (all RW)
- [ ] Admin share access: `10.1.2.51/ADMIN$`, `10.1.2.51/C$`, `10.1.2.150/ADMIN$`, `10.1.2.150/C$`

### WebDAV-Based Coercion

- [ ] .searchConnector-ms files on accessible shares
- [ ] WebClient service on workstations (HTTP-based auth bypasses SMB signing)

### Post-Exploitation

- [ ] Token impersonation (delegation/impersonation tokens)
- [ ] RDP session hijacking via tscon.exe (Server 2016)

---

## 15. Scheduled Tasks & Bot Configurations

| Config | Host | User | Frequency | Ansible Role |
| --- | --- | --- | --- | --- |
| [ ] Non-existent share (Responder bait) | Winterfell | robb.stark | 1 min | `vulns_schedule` / `roles/vulns/responder` |
| [ ] Non-existent share (NTLM relay bait) | Kingslanding | eddard.stark (DA) | 5 min | `roles/vulns/ntlm_relay` |

---

## 16. DNS, Trust & Audit Configuration

- [ ] Parent-child DNS conditional forwarder (`parent_child_dns`) — child→parent name resolution path; spoofable
- [ ] DC DNS conditional forwarder (`dc_dns_conditional_forwarder`) — cross-domain DNS path
- [ ] DC SACL audit policy (`dc_audit_sacl`) — defender visibility posture; check what's audited vs. silent
- [ ] LDAP diagnostic logging level (`ldap_diagnostic_logging`) — defender visibility into LDAP queries
- [ ] Forest trust direction + SID filtering posture (default: bidirectional, no filtering between sevenkingdoms ↔ essos)
- [ ] Windows ASR rules posture (`security_asr`) — what's blocked vs. allowed

---

## 17. GOAD Variants (alternate labs)

Each variant under `ad/` has its own `data/config.json` and inventory. Re-run sections 1–16 against the active variant.

- [ ] **GOAD** — canonical 4-host, 3-domain (sevenkingdoms / north / essos) — this checklist's default
- [ ] **GOAD-Light** — reduced 3-host variant (no essos)
- [ ] **GOAD-Mini** — minimal 2-host variant
- [ ] **GOAD-variant-1** — real-world naming (`deltasystems.local` + `hq.deltasystems.local`); team-based groups (ServicesTeam, ExecutiveUnit, AdministrationSquad)
- [ ] **DRACARYS** — single-domain (`dracarys.lab`) + Linux server (syrax); KeePass vault credential file; CredSSP enabled
- [ ] **MINILAB** — minimal lab variant
- [ ] **NHA** — network/hybrid architecture variant
- [ ] **SCCM** — System Center Configuration Manager exploitation variant (`sccm_*` roles: PXE, NAA, client push, MECM install)

---

## Validation Summary

Track progress per section. Coverage = checked / applicable.

| Category | Checked | Total | Applicable | Coverage | Notes |
| --- | --- | --- | --- | --- | --- |
| 1. Infrastructure & Domains | 0 | 16 | | | |
| 2. Users (all domains) | 0 | 32 | | | |
| 3. Groups & Memberships | 0 | 28 | | | |
| 4. ACL Attack Paths | 0 | 20 | | | |
| 5. Credential Discovery | 0 | 11 | | | |
| 6. Network Poisoning & Relay | 0 | 19 | | | |
| 7. Kerberos Attacks | 0 | 12 | | | |
| 8. ADCS (ESC1-15 + others) | 0 | 25 | | | |
| 9. MSSQL | 0 | 17 | | | |
| 10. Privilege Escalation | 0 | 8 | | | |
| 11. Lateral Movement | 0 | 16 | | | |
| 12. Domain Trust Exploitation | 0 | 8 | | | |
| 13. CVE Exploits | 0 | 5 | | | |
| 14. User-Level / Coercion | 0 | 7 | | | |
| 15. Scheduled Tasks | 0 | 2 | | | |
| 16. DNS, Trust & Audit | 0 | 6 | | | |
| 17. GOAD Variants | 0 | 8 | | | |
| **Total** | **0** | **240** | | | |
