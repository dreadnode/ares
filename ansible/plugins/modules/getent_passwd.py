#!/usr/bin/python3
# Author: Jayson Grace <jayson.e.grace@gmail.com>

from ansible.module_utils.basic import AnsibleModule
import pwd

DOCUMENTATION = r'''
---
module: getent_passwd
short_description: Retrieve local user information from the system password database.
description:
    - This module retrieves information about all local users from the system password database.
    - It is designed to work on all *nix platforms, including those where the Ansible 'getent' module does not function correctly, such as macOS.
options: {}
author:
    - Jayson Grace (@l50)
'''

def getent():
    all_users = pwd.getpwall()
    users = {user.pw_name: ["x", user.pw_uid, user.pw_gid, user.pw_gecos, user.pw_dir, user.pw_shell] for user in all_users}
    return users

def run_module():
    module = AnsibleModule(
        argument_spec={},
        supports_check_mode=True
    )

    try:
        users = getent()
        module.exit_json(changed=False, ansible_facts={'getent_passwd': users})
    except Exception as e:
        module.fail_json(msg=str(e))

def main():
    run_module()

if __name__ == '__main__':
    main()
