# GOAD Deployment & Attack Readiness Checklist

Comprehensive tracking checklist for GOAD lab provisioning, user/group creation, vulnerability configuration, and attack surface validation.

---

## 1. Infrastructure & Domain Setup

### Hosts

- [ ] DC01 (kingslanding) - sevenkingdoms.local Domain Controller (parent)
- [ ] DC02 (winterfell) - north.sevenkingdoms.local Domain Controller (child)
- [ ] DC03 (meereen) - essos.local Domain Controller
- [ ] SRV02 (castelblack) - north.sevenkingdoms.local Member Server
- [ ] SRV03 (braavos) - essos.local Member Server

### Domains & Trusts

- [ ] sevenkingdoms.local forest root created
- [ ] north.sevenkingdoms.local child domain created
- [ ] essos.local forest root created
- [ ] Bidirectional forest trust: sevenkingdoms.local <-> essos.local
- [ ] Parent-child trust: sevenkingdoms.local <-> north.sevenkingdoms.local

### Services per Host

- [ ] DC01: ADCS, Defender ON
- [ ] DC02: LLMNR, NBT-NS, SMB shares, Defender ON
- [ ] DC03: ADCS custom templates, LAPS DC, NTLM downgrade, Defender ON
- [ ] SRV02: IIS, MSSQL (+SSMS), WebDAV, SMB shares, Defender OFF
- [ ] SRV03: MSSQL, WebDAV, LAPS, SMB shares, RunAsPPL, Defender ON

---

## 2. Users

### sevenkingdoms.local Users

- [ ] robert.baratheon / `iamthekingoftheworld` - Baratheon, Domain Admins, Small Council, Protected Users
- [ ] cersei.lannister / `il0vejaime` - Lannister, Baratheon, Domain Admins, Small Council
- [ ] tywin.lannister / `powerkingftw135` - Lannister
- [ ] jaime.lannister / `cersei` - Lannister
- [ ] tyron.lannister / `Alc00L&S3x` - Lannister
- [ ] joffrey.baratheon / `1killerlion` - Baratheon, Lannister
- [ ] renly.baratheon / `lorastyrell` - Baratheon, Small Council (sensitive, cannot be delegated)
- [ ] stannis.baratheon / `Drag0nst0ne` - Baratheon, Small Council
- [ ] petyer.baelish / `@littlefinger@` - Small Council
- [ ] lord.varys / `_W1sper_$` - Small Council
- [ ] maester.pycelle / `MaesterOfMaesters` - Small Council

### north.sevenkingdoms.local Users

- [ ] eddard.stark / `FightP3aceAndHonor!` - Stark, Domain Admins
- [ ] catelyn.stark / `robbsansabradonaryarickon` - Stark
- [ ] robb.stark / `sexywolfy` - Stark (autologon creds on DC02)
- [ ] arya.stark / `Needle` - Stark
- [ ] sansa.stark / `345ertdfg` - Stark
- [ ] brandon.stark / `iseedeadpeople` - Stark
- [ ] rickon.stark / `Winter2022` - Stark
- [ ] hodor / `hodor` - Stark
- [ ] jon.snow / `iknownothing` - Stark, Night Watch
- [ ] samwell.tarly / `Heartsbane` - Night Watch
- [ ] jeor.mormont / `_L0ngCl@w_` - Night Watch, Mormont
- [ ] sql_svc / `YouWillNotKerboroast1ngMeeeeee` - (NORTH)

### essos.local Users

- [ ] daenerys.targaryen / `BurnThemAll!` - Targaryen, Domain Admins
- [ ] viserys.targaryen / `GoldCrown` - Targaryen
- [ ] khal.drogo / `horse` - Dothraki
- [ ] jorah.mormont / `H0nnor!` - Targaryen
- [ ] missandei / `fr3edom`
- [ ] drogon / `Dracarys` - Dragons
- [ ] sql_svc / `YouWillNotKerboroast1ngMeeeeee` - (ESSOS)

### gMSA Accounts

- [ ] gmsaDragon / gmsaDragon.essos.local - SPNs: HTTP/braavos, HTTP/braavos.essos.local

---

## 3. Groups

### sevenkingdoms.local Groups

- [ ] Lannister (Global, managed by tywin.lannister)
- [ ] Baratheon (Global, managed by robert.baratheon)
- [ ] Small Council (Global)
- [ ] DragonStone (Global)
- [ ] KingsGuard (Global)
- [ ] DragonRider (Global)
- [ ] AcrossTheNarrowSea (Domain Local)

### north.sevenkingdoms.local Groups

- [ ] Stark (Global, managed by eddard.stark)
- [ ] Night Watch (Global, managed by jeor.mormont)
- [ ] Mormont (Global, managed by jeor.mormont)
- [ ] AcrossTheSea (Domain Local)

### essos.local Groups

- [ ] Targaryen (Global, managed by viserys.targaryen)
- [ ] Dothraki (Global, managed by khal.drogo)
- [ ] Dragons (Global)
- [ ] QueenProtector (Global, members: Dragons -> Domain Admins)
- [ ] DragonsFriends (Domain Local, managed by daenerys.targaryen)
- [ ] Spys (Domain Local, LAPS reader)

### Cross-Domain Memberships

- [ ] DragonsFriends contains sevenkingdoms.local\tyron.lannister
- [ ] DragonsFriends contains essos.local\daenerys.targaryen
- [ ] Spys contains sevenkingdoms.local\Small Council
- [ ] AcrossTheNarrowSea (sevenkingdoms) contains essos.local\daenerys.targaryen

---

## 4. ACL Attack Paths

### sevenkingdoms.local ACL Chain

- [ ] tywin.lannister --ForceChangePassword--> jaime.lannister
- [ ] jaime.lannister --GenericWrite--> joffrey.baratheon
- [ ] joffrey.baratheon --WriteDacl--> tyron.lannister
- [ ] tyron.lannister --Self-Membership--> Small Council
- [ ] Small Council --WriteMembership--> DragonStone
- [ ] DragonStone --WriteOwner--> KingsGuard
- [ ] KingsGuard --GenericAll--> stannis.baratheon
- [ ] stannis.baratheon --GenericAll--> kingslanding$ (DC01)
- [ ] lord.varys --GenericAll--> Domain Admins
- [ ] AcrossTheNarrowSea --GenericAll--> kingslanding$ (DC01)
- [ ] renly.baratheon --WriteDACL--> OU=Crownlands

### north.sevenkingdoms.local ACL

- [ ] NT AUTHORITY\ANONYMOUS LOGON --ReadProperty + GenericExecute--> DC=North (anonymous enumeration)

### essos.local ACL Chain

- [ ] khal.drogo --GenericAll--> viserys.targaryen
- [ ] Spys --GenericAll--> jorah.mormont
- [ ] khal.drogo --GenericAll--> ESC4 certificate template
- [ ] viserys.targaryen --WriteProperty--> jorah.mormont
- [ ] DragonsFriends --GenericWrite--> braavos$ (SRV03)
- [ ] missandei --GenericAll--> khal.drogo
- [ ] gmsaDragon$ --GenericAll--> drogon

---

## 5. Credential Discovery Vulnerabilities

- [ ] Password in description field: samwell.tarly (`Heartsbane`)
- [ ] Username=password: hodor / `hodor`
- [ ] Username=password: localuser (across all three domains)
- [ ] Weak password policy in NORTH domain (no complexity, 5-attempt lockout)
- [ ] Cross-domain password reuse: localuser with Domain Admin privs
- [ ] NULL session access on WINTERFELL DC

---

## 6. Network Poisoning & Relay Vulnerabilities

### LLMNR/NBT-NS Poisoning

- [ ] Scheduled task on Winterfell: robb.stark connects to non-existent share every 1 minute (Ansible role: `roles/vulns/responder`)
- [ ] robb.stark password (`sexywolfy`) crackable with rockyou.txt
- [ ] robb.stark is local admin on Winterfell

### NTLM Relay

- [ ] Scheduled task on Kingslanding: eddard.stark (Domain Admin) connects to non-existent share every 5 minutes (Ansible role: `roles/vulns/ntlm_relay`)
- [ ] SMB signing disabled on CASTELBLACK (SRV02) - "signing enabled but not required"
- [ ] SMB signing disabled on BRAAVOS (SRV03) - "message signing disabled"

### Other Network Attacks

- [ ] NTLMv1 downgrade possible (DC03 meereen config)
- [ ] LDAP signing not enforced
- [ ] IPv6/DHCPv6 poisoning possible (MITM6)
- [ ] CVE-2019-1040 (Remove-MIC) NTLM bypass

---

## 7. Kerberos Attack Vulnerabilities

### AS-REP Roasting

- [ ] brandon.stark - DoesNotRequirePreAuth enabled, password: `iseedeadpeople`
- [ ] missandei - DoesNotRequirePreAuth enabled

### Kerberoasting

- [ ] jon.snow - SPNs: CIFS/HTTP services, password: `iknownothing`
- [ ] sansa.stark - SPN: HTTP/eyrie.north.sevenkingdoms.local (unconstrained delegation)
- [ ] sql_svc (NORTH) - SPN: MSSQLSvc/castelblack:1433, password: `YouWillNotKerboroast1ngMeeeeee`
- [ ] sql_svc (ESSOS) - SPN: MSSQLSvc/braavos:1433, password: `YouWillNotKerboroast1ngMeeeeee`

### Delegation

- [ ] Unconstrained delegation: sansa.stark
- [ ] Constrained delegation: jon.snow (with protocol transition)
- [ ] Machine Account Quota (MAQ) = 10 on all domains
- [ ] RBCD attack path: stannis.baratheon -> kingslanding$ via GenericAll

---

## 8. ADCS Vulnerabilities

### ADCS Infrastructure

- [ ] ADCS installed on DC01 (kingslanding)
- [ ] ADCS custom templates on DC03 (meereen)
- [ ] ADCS on SRV03 (braavos) with Web Enrollment

### ESC Vulnerabilities

- [ ] ESC1 - Enrollee Supplies Subject (template allows SAN specification)
- [ ] ESC2 - Any Purpose EKU template
- [ ] ESC3 - Certificate Request Agent template
- [ ] ESC4 - Vulnerable template ACL (khal.drogo has GenericAll on template)
- [ ] ESC5 - Golden Certificate / PKI Object Access Control
- [ ] ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA
- [ ] ESC7 - ManageCA/ManageCertificate abuse
- [ ] ESC8 - NTLM Relay to AD CS HTTP Endpoints (Web Enrollment on braavos)
- [ ] ESC9 - UPN Spoofing with No Security Extension
- [ ] ESC10 - Weak Certificate Mapping
- [ ] ESC11 - RPC Encryption Weakness (ICPR without encryption)
- [ ] ESC13 - Group Membership via Issuance Policy
- [ ] ESC14 - AltSecurityIdentities Manipulation
- [ ] ESC15 (CVE-2024-49019) - Certificate Request Agent Abuse

### Other ADCS Attacks

- [ ] Certifried (CVE-2022-26923) - Computer account DNS hostname spoofing
- [ ] Shadow Credentials via GenericWrite/GenericAll on user/computer objects

---

## 9. MSSQL Vulnerabilities

### MSSQL Services

- [ ] MSSQL running on SRV02 (castelblack) - SA password: `Sup1_sa_P@ssw0rd!`
- [ ] MSSQL running on SRV03 (braavos) - SA password: `sa_P@ssw0rd!Ess0s`

### Linked Servers

- [ ] castelblack -> braavos (jon.snow -> sa, password: `sa_P@ssw0rd!Ess0s`)
- [ ] braavos -> castelblack (khal.drogo -> sa, password: `Sup1_sa_P@ssw0rd!`)

### Impersonation

- [ ] SRV02: samwell.tarly can impersonate sa
- [ ] SRV02: brandon.stark can impersonate jon.snow
- [ ] SRV02: arya.stark can impersonate dbo (master), dbo (msdb)
- [ ] SRV03: jorah.mormont can impersonate sa

### Sysadmins

- [ ] SRV02: NORTH\jon.snow is sysadmin
- [ ] SRV03: ESSOS\khal.drogo is sysadmin

### MSSQL Attack Vectors

- [ ] NTLM coercion via xp_dirtree / xp_fileexist
- [ ] xp_cmdshell for OS command execution
- [ ] Trustworthy database setting for impersonation escalation
- [ ] Cross-domain pivoting via linked servers

---

## 10. Privilege Escalation Vulnerabilities

- [ ] SeImpersonatePrivilege on IIS (SRV02) and MSSQL service accounts
- [ ] IIS upload vulnerability on SRV02 (192.168.56.22) - web shell upload
- [ ] PrintSpoofer / SweetPotato / BadPotato for SeImpersonate -> SYSTEM
- [ ] KrbRelayUp (Kerberos relay when LDAP signing not enforced)
- [ ] AMSI bypass possible (string fragmentation + .NET patching)
- [ ] In-memory .NET assembly execution (PowerSharpPack, Invoke-SharpLoader)
- [ ] Print Spooler service enabled (coercion + CVE vector)
- [ ] SCMUACBypass for medium -> high integrity

---

## 11. Lateral Movement Prerequisites

### Credential Extraction Points

- [ ] SAM database dump from compromised hosts
- [ ] LSA Secrets / cached domain credentials
- [ ] LSASS process dump (lsassy, mimikatz)
- [ ] LAPS password reading (jorah.mormont is LAPS reader, Spys group)

### Movement Techniques Available

- [ ] Pass-the-Hash (PTH) via SMB/WMI
- [ ] Over-Pass-the-Hash (NTLM -> Kerberos TGT)
- [ ] Pass-the-Ticket (extracted Kerberos tickets)
- [ ] Evil-WinRM (port 5985/5986)
- [ ] RDP with Restricted Admin
- [ ] Impacket remote execution (psexec, wmiexec, smbexec, atexec, dcomexec)
- [ ] Certificate-based authentication (certipy)

### Local Admin Access Map

- [ ] DC01: robert.baratheon, cersei.lannister
- [ ] DC02: eddard.stark, catelyn.stark, robb.stark
- [ ] SRV02: jeor.mormont
- [ ] DC03: daenerys.targaryen
- [ ] SRV03: khal.drogo

---

## 12. Domain Trust Exploitation

### Child-to-Parent Escalation

- [ ] Golden Ticket + ExtraSid (north -> sevenkingdoms via krbtgt + Enterprise Admins SID-519)
- [ ] Trust Ticket / Inter-Realm TGT (trust key extraction)
- [ ] raiseChild.py automated escalation
- [ ] Unconstrained delegation on DCs for parent DC TGT capture

### Forest-to-Forest Exploitation

- [ ] Password reuse across forests (NTDS dump + spray)
- [ ] Foreign group/user exploitation (cross-forest memberships)
- [ ] SID History abuse (golden tickets with foreign SIDs, RID >1000)
- [ ] MSSQL trusted links for cross-forest pivoting

---

## 13. CVE Exploits

- [ ] CVE-2021-42287 / CVE-2021-42278 (noPac / SamAccountName Spoofing) - computer account manipulation -> DCSync
- [ ] CVE-2021-1675 (PrintNightmare) - Print Spooler DLL injection -> SYSTEM
- [ ] CVE-2022-26923 (Certifried) - computer DNS hostname spoofing -> DC impersonation
- [ ] CVE-2024-49019 (ESC15) - Certificate Request Agent abuse
- [ ] CVE-2019-1040 (Remove-MIC) - NTLM MIC removal bypass for relay
- [ ] CVE-2020-1472 (ZeroLogon) - Netlogon bypass (patched in hardened GOAD)

---

## 14. User-Level / Coercion Attacks

### File-Based Coercion

- [ ] .lnk shortcut files (UNC path resolution -> hash capture)
- [ ] .scf shell command files (authentication trigger)
- [ ] .url internet shortcut files (UNC path -> hash capture)

### WebDAV-Based Coercion

- [ ] .searchConnector-ms files on accessible shares
- [ ] WebClient service on workstations (HTTP-based auth bypass SMB signing)
- [ ] HTTP-to-LDAP relay for shadow credentials / RBCD

### Post-Exploitation

- [ ] Token impersonation (delegation/impersonation tokens)
- [ ] RDP session hijacking via tscon.exe (Server 2016)

---

## 15. Scheduled Tasks & Bot Configurations

| Config | Host | User | Frequency | Ansible Role |
|--------|------|------|-----------|--------------|
| [ ] Non-existent share connection | Winterfell | robb.stark | Every 1 min | roles/vulns/responder |
| [ ] Non-existent share connection | Kingslanding | eddard.stark (DA) | Every 5 min | roles/vulns/ntlm_relay |

---

## Validation Summary

| Category | Check Count | Status |
|----------|-------------|--------|
| Infrastructure & Domains | 15 | |
| Users (all domains) | 31 | |
| Groups & Memberships | 21 | |
| ACL Attack Paths | 18 | |
| Credential Discovery | 6 | |
| Network Poisoning & Relay | 10 | |
| Kerberos Attacks | 10 | |
| ADCS (ESC1-15 + others) | 19 | |
| MSSQL | 14 | |
| Privilege Escalation | 8 | |
| Lateral Movement | 18 | |
| Domain Trust Exploitation | 8 | |
| CVE Exploits | 6 | |
| User-Level / Coercion | 8 | |
| Scheduled Tasks | 2 | |
| **Total** | **~194** | |
