=============================================================
Dreadnode Nimbus Range Ansible Collection 1.5.0 Release Notes
=============================================================

.. contents:: Topics

v1.5.0
======

Release Summary
---------------

This release adds native Kali security tool support, reorganizes agent roles for better modularity, improves build processes, and includes various dependency updates and bug fixes.

Added
-----

- /usr/bin symlinks for Python tools on Debian-based systems (#253)
- Docker provisioning playbooks for specialized Ares agents (#249)
- Native apt installation for Kali-specific security tools (#277)
- Option to preserve static libraries during build cleanup
- Role documentation links and descriptions for new ares and monitoring roles
- adidnsdump installation via pipx with configurable source and related options
- enum4linux-ng installation via pipx for non-Kali systems
- krbrelayx and PowerUpSQL tool support; enhanced NetExec module checks (#255)
- pipx and Rust toolchain support; improved NetExec and impacket installation reliability (#251)

Changed
-------

- Deduplicated base dependencies, added pipx isolation, and enforced role composition (#256)
- Improved Python PEP 668/externally-managed pip handling and updated Python version (#265)
- Improved Python package installation reliability and impacket source handling
- Improved hashcat build process and updated base package list (#274)
- Improved verification and compatibility for network and base tool checks
- Modernized tool installation and verification for improved reliability (#248)
- Reorganized and modularized agent roles and playbooks for improved clarity (#275)
- Updated actions/cache action to v5.0.2 (#267)
- Updated dependency amazon.aws to v11 (#269)
- Updated dependency ansible-lint to v26 (#250)
- Updated dependency ansible-lint to v26.1.1 (#268)
- Updated dependency renovatebot/github-action to v44.2.5 (#272)

Removed
-------

- In-role verification and redundant install checks (#263)

Fixed
-----

- Fixed issue ensuring certipy is symlinked correctly on Kali Linux (#254)

v1.4.1
======

Release Summary
---------------

This release adds a build cleanup role and improves dependency handling for mitm6/netifaces.

Added
-----

- ares_docker - Added build cleanup role

Changed
-------

- ares_docker - Refactored to use ansible_facts for distribution and os_family lookups

Fixed
-----

- ares_docker - Fixed missing build dependencies for mitm6/netifaces

v1.4.0
======

Release Summary
---------------

This release introduces new privilege escalation tools, expands lateral movement and offensive capabilities, and adds attack activity logging features.

Added
-----

- attack_activity - Added shell history log collection and permissions setup
- lateral_movement - Expanded capabilities for lateral movement operations
- offensive_tooling - Added new offensive tooling and expanded agent framework
- priv_esc_tools role - Added role for privilege escalation tooling

Changed
-------

- armada_agent roles - Migrated roles to ares framework and expanded offensive tooling

v1.3.0
======

Release Summary
---------------

This release adds new Ares agent roles for security tools provisioning, Docker installation improvements, and various dependency updates.

Added
-----

- Add ares agent roles for network and cracking tool provisioning
- Add docker provisioning playbooks for ares base, cracker, and full agents
- Add mythic role metadata and tests with improved docsible template robustness

Changed
-------

- Improve ansible-lint and prettier hook reliability and isolation
- Improve docker installation process and enhance molecule testing for mythic role
- Improve markdown table formatting and variable code styling in READMEs
- Standardize register variable names in mythic verify playbook

Fixed
-----

- Prevent git corruption in docsible hook by using subshell for cd
- Remove mythic from molecule action due to incomplete molecule tests

v1.2.0
======

Release Summary
---------------

Initial release of the Mythic C2 Ansible role with automated provisioning and agent deployment.

Added
-----

- mythic_c2 - Added Ansible role for Mythic C2 with automated provisioning and agent deployment

v1.1.0
======

Release Summary
---------------

This release introduces major improvements to log shipping with the migration to Grafana Alloy, adds new roles and playbooks, and enhances cross-platform support.

Added
-----

- alloy - Added role for Windows log shipping and improved cross-platform configuration
- changelog - Added automated release and changelog generation tasks
- docs - Added architecture diagram to README
- fluent_bit - Improved installation for Debian/Ubuntu
- sliver - Added playbook for sliver C2 with required dependencies
- zsh - Added setup role for zsh

Changed
-------

- fluent_bit - Updated Logstash_Prefix for OS-specific indices in configurations
- log_shipping - Migrated log shipping to Grafana Alloy with Loki integration

Removed
-------

- sliver - Removed unnecessary ssm role from sliver playbook
- windows - Removed Grafana Alloy log shipping configuration from Windows setup

Fixed
-----

- fluent_bit - Improved repository support for Kali Linux
- sliver - Updated playbook to set up systemd
- templatesyncignore - Added missing items and exclusions

v1.0.0
======

Release Summary
---------------

Released initial Nimbus Range telemetry collection roles and playbooks; removed legacy workflows, fixed badges, and modernized naming and documentation across the collection.

Added
-----

- Core telemetry roles `aws_ssm_agent`, `aws_cloudwatch_agent`, and `fluent_bit`.
- Fluent Bit config for Windows event and transcript logs.
- Lua script for parsing SSM session logs.
- Updated docs and metadata for Dreadnode Nimbus Range.
- Windows and Linux playbooks for agent provisioning and log collection.

Changed
-------

- Improved error handling, variable naming, and OS-specific templates.
- Pre-commit GitHub Action now supports merge queue via `merge_group`.
- Updated default Molecule examples to use `fluent_bit` and `linux`.

Removed
-------

- Galaxy deployment logic, as this is a private collection.
- Outdated links and references to the old public repository.
