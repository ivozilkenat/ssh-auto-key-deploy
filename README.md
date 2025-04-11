# SSH Setup Script

This Python script automates SSH key creation and configuration for a remote server. It performs the following:

1. Checks if you are on a Unix-like system (it will not run on Windows unless under WSL).
2. Verifies that the remote server is reachable (e.g., ensure you are on the correct network or connected via a VPN).
3. Creates a new SSH key and passphrase for connecting to the server.
4. Optionally backs up your existing `~/.ssh` directory.
5. Updates your `~/.ssh/known_hosts` file with the server's keys.
6. Copies the newly created key to the remote server via `ssh-copy-id`.
7. Updates your local `~/.ssh/config` file for easy login.

## Usage

```bash
python3 ssh_setup.py <username> [OPTIONS]
```

### Options:

`-q, --quiet`
Suppress most output.

`-w, --wincpy`
Copy the generated SSH key to a Windows partition’s ~\.ssh folder (for WSL users).

`--disablebackup`
Disable creation of a backup for your ~/.ssh directory.

### Example:

```bash
python3 ssh_setup.py alice.smith
```
After running the script successfully, you can connect to the server with either:

```bash
ssh alice.smith@<your-server-domain>
```
or

```bash
ssh <your-config-alias>
```

### Requirements
- Python 3 (the script has been tested on 3.7+).

- OpenSSH client (for ssh, ssh-keygen, ssh-copy-id, ssh-keyscan, etc.).

- WSL (if you plan to use -w/--wincpy on Windows).

### Notes
- Ensure you are on the correct private network or connected via VPN to reach the remote server.

- The script exits if not running on a supported OS (os.name must be posix).

- The default key type created is ed25519 with a 4096-bit key size.
