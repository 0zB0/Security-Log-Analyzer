# Mixed Attack Scenario

Target demo sequence:

1. Web probing from `185.34.22.10`.
2. Sensitive file access attempts.
3. SSH brute force against `admin`.
4. Successful login after repeated failures.
5. Sudo command after login.

This folder will become the one-command demo dataset.

Current focused sample files:

- `packages/sample-data/auth/ssh-bruteforce.log`
- `packages/sample-data/auth/sudo-activity.log`
- `packages/sample-data/nginx/probing.log`
- `packages/sample-data/nginx/reconnaissance.log`
