#!/usr/bin/python3
# Author: Jayson Grace <jayson.e.grace@gmail.com>

from ansible.module_utils.basic import AnsibleModule
import os
import secrets
import string
import subprocess

DOCUMENTATION = r'''
---
module: vnc_pw
short_description: Manage VNC passwords for users.
description:
  - Generates or retrieves VNC passwords for a list of users.
options:
  vnc_setup_users:
    description:
      - List of users to manage VNC passwords for.
    type: list
    required: True
author:
  - Jayson Grace (@l50)
'''

def file_exists(file):
    return os.path.isfile(file)

def gen_pw(size):
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for i in range(size))

def run_cmd(cmd):
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    output, err = p.communicate()
    if p.returncode != 0:
        return None, err.decode('utf-8', errors='ignore')
    return output.decode('utf-8', errors='ignore'), None

def get_home_dir(username):
    return '/root' if username == 'root' else f"/home/{username}"

def set_vnc_password(user, password):
    home_dir = get_home_dir(user)
    passwd_file = f"{home_dir}/.vnc/passwd"
    cmd = f"echo {password} | vncpasswd -f > {passwd_file}"
    run_cmd(cmd)

def run_module():
    module_args = dict(
        vnc_setup_users=dict(type='list', required=True),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    vnc_setup_users = module.params['vnc_setup_users']
    changed = False

    for user in vnc_setup_users:
        home_dir = get_home_dir(user['username'])
        passwd_file = f"{home_dir}/.vnc/passwd"

        if not file_exists(passwd_file):
            user['pass'] = gen_pw(8)
            if not module.check_mode:
                set_vnc_password(user['username'], user['pass'])
            changed = True
        else:
            command = f"vncpwd {passwd_file}"
            output, error = run_cmd(command)
            if error:
                module.fail_json(msg=f"Error running vncpwd: {error}")
            user['pass'] = output.strip().split()[1]

    module.exit_json(changed=changed, result=vnc_setup_users)

def main():
    run_module()

if __name__ == '__main__':
    main()
