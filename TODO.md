- Ensure ~/dreadnode/rigging/RIGGING_BEST_PRACTICES.md is followed
- Get more viable ways to domain admin - target essos
- Determine if there's a way to not have to code in specific vulns so this can
  be more applicable to a wide variety of targets:

      modified:   src/ares/core/dispatcher.py
      modified:   src/ares/core/models.py
      modified:   src/ares/tools/red/common.py
      modified:   src/ares/tools/red/credential_discovery.py
      modified:   src/ares/tools/red/kerberos_attacks.py
      modified:   src/ares/tools/red/lateral_movement.py
      modified:   src/ares/tools/red/reconnaissance.py

- Determine if VM is still viable with the pub/sub model (not having to require
  redis)
- Break up codebase to be more maintainable: ~1000 lines (time to refactor) -
  ideal: 200-500 lines per file
- Figure out how blue agent can create alert rules
based on stuff it sees
