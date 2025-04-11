#!/usr/bin/python3

# --- USER CONFIG ----------------------------------------------------
# If a user changes their .ssh/config, changes must be made here
HOST_ALIAS = "<HOST_ALIAS>"  # connect with: `ssh $HOST_ALIAS`
SSH_BACKUP_FILE_NAME = ".ssh-keygen-backup"
# --- SCRIPT SETTINGS ------------------------------------------------
HOST = "<HOST>"
KEY_TYPE = "ed25519"  # dsa | ecdsa | ecdsa-sk | ed25519 | ed25519-sk | rsa
# --- SSH PUBLIC KEYS ------------------------------------------------
ED25519_PUB = (
    "XXX"
)
RSA_PUB = (
    "XXX"
)
ECDSA_PUB = (
    "XXX"
)
# --------------------------------------------------------------------

import os
import sys

if os.name == "nt":
    print("[ERROR] Script cannot be run on Windows!")
    sys.exit(1)

from enum import Enum
from getpass import getpass
from queue import Queue
from datetime import datetime
from dataclasses import dataclass

import string
import random
import traceback
import subprocess
import argparse
import shutil
import shlex
import threading
import time
import re
import fcntl
import signal
import io
import pty

from typing import List, Tuple, Set, Sequence, Union, Any


def main(logger, atError):
    """
    Script main function.

    Args:
        logger (Logger): Logger used for script output.
        atError (WrapError._atErrorCallable): atError object that is called during exception.

    Raises:
        Exception: Will be raised if unknown error occurs.
    """

    fingerprints = {Fingerprint.from_string(k) for k in (ED25519_PUB, RSA_PUB, ECDSA_PUB)}
    user_input = InputHandler(logger)

    arg_parser = argparse.ArgumentParser(
        description="Generate a SSH key and copy it onto the target servers. Multiple keys are possible. A backup of .ssh directory will be created by default."
    )

    arg_parser.add_argument(
        "username",
        help="host username: <firstname.lastname>",
        action=ValidateUsername
    )
    arg_parser.add_argument(
        "-q", "--quiet",
        help="suppress output",
        action="store_true"
    )
    arg_parser.add_argument(
        "-w", "--wincpy",
        help="copy ssh key to Windows partition (WSL)",
        action="store_true"
    )
    arg_parser.add_argument(
        "--disablebackup",
        help="disable creation of .ssh directory backup",
        action="store_true"
    )
    args = arg_parser.parse_args()

    if not args.quiet:
        logger.logging_level = Logger.Level.VERBOSE

    ssh_path = os.path.join(os.path.expanduser("~"), ".ssh")
    ssh_path_win_wsl = os.path.join(get_wsl_windows_homedir(), ".ssh") if args.wincpy else None

    # Check VPN
    logger.print("[Checking target network...]")
    if not host_reachable():
        logger.print(
            f"{HOST} cannot be reached. -> You must be inside the target network or connected via a VPN.",
            Logger.Level.ERROR
        )
        sys.exit(1)

    # Create Key
    logger.print("\n[Creating Key]")
    key_file_name = user_input.get_type(
        ">Key file name",
        suggestion=f"id_{KEY_TYPE}_auto_key_deploy",
        check=valid_key_file_name(ssh_path, logger, args.wincpy, ssh_path_win_wsl),
        force=True
    )

    passphrase = user_input.get_password(
        ">Passphrase (enter for empty)",
        confirm=True,
        confirm_prompt=">Enter passphrase again",
        force=True
    )
    passphrase = '""' if passphrase == "" else passphrase

    key_path = os.path.join(ssh_path, key_file_name)
    key_path_win_wsl = os.path.join(ssh_path_win_wsl, key_file_name) if args.wincpy else None
    key_path_win = get_windows_home_dir() + "\\.ssh\\" + key_file_name if args.wincpy else None

    atError.function = clean_key_at_error(key_path, key_path_win_wsl)

    # Creating Backup
    if not args.disablebackup:
        logger.print("\n[Creating ssh directory backup]")
        create_backup(ssh_path, args.wincpy, ssh_path_win_wsl)

    # Generate Key
    res_keygen = subprocess.run(
        f"ssh-keygen -t {KEY_TYPE} -b 4096 -f {key_path} -P {passphrase}",
        capture_output=True,
        text=True,
        shell=True,
        check=True
    )
    if res_keygen.returncode > 0:
        logger.print("Key could not be generated.", Logger.Level.ERROR)
        sys.exit(1)

    # Checking known_hosts
    known_hosts_path = os.path.join(ssh_path, "known_hosts")
    known_hosts_path_win_wsl = os.path.join(ssh_path_win_wsl, "known_hosts") if args.wincpy else None

    res_keyscan = subprocess.run(
        f"ssh-keyscan -t ed25519,rsa,ecdsa {HOST}",
        capture_output=True,
        text=True,
        shell=True,
        check=True
    )
    keyscan_fingerprints = {
        Fingerprint.from_string(key_string.strip())
        for key_string in res_keyscan.stdout.splitlines()
    }

    # Check if keys from script config area are up to date
    for key in fingerprints:
        if key not in keyscan_fingerprints:
            logger.print(
                f"Fetched public keys don't contain/match '{key.type}' from script config. -> check if keys in script are up to date.",
                Logger.Level.ERROR
            )
            sys.exit(1)

    # Add public keys to known_hosts
    update_known_hosts(known_hosts_path, HOST, fingerprints)
    if args.wincpy:
        update_known_hosts(known_hosts_path_win_wsl, HOST, fingerprints, windows=True)

    # Copying to Server
    logger.print("\n[Copying To Server]")
    remote = f"{args.username}@{HOST}"

    process = PtyHandler.spawn_shell(f'ssh-copy-id -f -i {key_path}.pub {remote}')
    process._at_exit = atError

    def m_hostNotReachable(m: PtyHandler.Match):
        logger.print(
            "Connection to Server failed -> Check if you're inside the target network or that your VPN is still active.",
            Logger.Level.ERROR
        )
        sys.exit(1)

    process.match_send("ssh: Could not resolve hostname", callback=m_hostNotReachable, timeout=10)

    def m_password_input(m: PtyHandler.Match) -> None:
        process.send_line(getpass(f">{remote}'s password: "), save=False)

        def m_invalid_password(m: PtyHandler.Match) -> None:
            logger.print("Permission denied. -> Invalid password.", Logger.Level.ERROR)
            sys.exit(1)

        process.match_send(
            "Permission denied, please try again.",
            callback=m_invalid_password,
            timeout=5
        )
        process.match_send("Number of key(s) added:", callback=m_valid_login, timeout=5)

    process.match_send(f"{remote}'s password: ", callback=m_password_input, timeout=5)

    def m_valid_login(m: PtyHandler.Match) -> None:
        process.confirm_matching()

    process.match_send("Number of key(s) added:", callback=m_valid_login, timeout=5)

    # Wait till matching is finished
    process.match_join()

    # Unexpected Error
    if not process.valid_matching() and not process.exited:
        logger.print_file("IO: " + str(process.get_lines()), Logger.Level.FATAL)
        raise Exception("INVALID MATCHING; Unknown Error occurred; see log for i/o", Logger.Level.FATAL)

    # Copy to Windows
    if args.wincpy:
        shutil.copy(key_path, key_path_win_wsl)
        shutil.copy(key_path + ".pub", key_path_win_wsl + ".pub")

    # Write Config
    logger.print("\n[Editing Config]")
    write_config = write_ssh_config(args.username)
    write_config(key_path)
    if args.wincpy:
        write_config(key_path_win_wsl, key_path_win)

    logger.print(
        f"Your key '{key_file_name}' was added to the server. You can now connect with the following commands{' (Linux and Windows)' if args.wincpy else ' (Linux)'}:"
    )
    logger.print(f"1. 'ssh {remote}'")
    logger.print(f"2. 'ssh {HOST_ALIAS}'")


class ValidateUsername(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Union[str, Sequence[Any], None],
        option_string: Union[str, None] = None
    ) -> None:
        if re.fullmatch(r'[a-z]+\.[a-z]+', values) is None:
            parser.error("Invalid username format. Expected <firstname.lastname>")
        setattr(namespace, self.dest, values)


@dataclass(frozen=True)
class Fingerprint:
    """
    Const dataclass to represent fingerprints in the format 'host type key'.
    Prevent mistakes when copying fingerprint strings and supports hashing.
    """
    host: str
    type: str
    key: str

    def __hash__(self) -> int:
        return hash(self.__str__())

    def __eq__(self, __value: object) -> bool:
        return self.__hash__() == hash(__value)

    def __str__(self) -> str:
        """
        Generate known_hosts representation of fingerprint.
        """
        return f"{self.host} {self.type} {self.key}"

    @staticmethod
    def from_string(string: str):
        """
        Create Fingerprint instance using a string in known_hosts format.
        """
        args = string.split()
        assert len(args) == 3, "Public Key expects 3 arguments: 'host type key'."
        return Fingerprint(*args)


def create_backup(ssh_path: str, create_on_windows: bool, ssh_path_win_wsl):
    """
    Copies the .ssh directory.

    Args:
        ssh_path: path of .ssh directory.
        create_on_windows: copy .ssh directory on windows as well.
        ssh_path_win_wsl: path of .ssh directory on windows in WSL format.
    """
    ssh_backup_dir = generate_unused_dir_ext(
        os.path.join(os.path.dirname(ssh_path), SSH_BACKUP_FILE_NAME)
    )
    shutil.copytree(ssh_path, ssh_backup_dir)
    if create_on_windows:
        ssh_backup_dir_win_wsl = generate_unused_dir_ext(
            os.path.join(os.path.dirname(ssh_path_win_wsl), SSH_BACKUP_FILE_NAME)
        )
        shutil.copytree(ssh_path_win_wsl, ssh_backup_dir_win_wsl)


def generate_unused_dir_ext(dir_path: str, ext_len: int = 8):
    """
    Generate a random directory suffix if name is used.
    """
    final_dir_path = dir_path
    while os.path.exists(final_dir_path):
        final_dir_path = f"{dir_path}-{random_string(ext_len)}"
    return final_dir_path


def random_string(length: int):
    return "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(length))


def host_reachable() -> bool:
    """
    Checks if cluster can be reached by pinging the target servers.
    """
    return not subprocess.run(f"ping -c 1 {HOST}", capture_output=True, text=True, shell=True).returncode


def valid_key_file_name(ssh_path: str, logger, check_on_windows: bool, ssh_path_win_wsl: str) -> callable:
    """
    Returns a callable to check whether a given file name is valid.
    """

    def _check(file_name: str) -> bool:
        if len(file_name) < 1:
            logger.print("File name must be at least 1 character long.", Logger.Level.INFO)
            return False

        key_path = os.path.join(ssh_path, file_name)
        if os.path.exists(key_path) or os.path.exists(key_path + ".pub"):
            logger.print(f"Key file '{file_name}(.pub)' already exists.", Logger.Level.INFO)
            return False
        elif check_on_windows:
            key_path_win_wsl = os.path.join(ssh_path_win_wsl, file_name)
            if os.path.exists(key_path_win_wsl) or os.path.exists(key_path_win_wsl + ".pub"):
                logger.print(
                    f"Key file '{file_name}(.pub)' already exists on Windows partition.",
                    Logger.Level.ERROR
                )
                return False
        return True

    return _check


def update_known_hosts(known_hosts_path: str, host_name: str, fingerprints: Set[Fingerprint], windows: bool = False) -> None:
    """
    Update known_hosts by removing all host fingerprints, adding new fingerprints, and hashing (platform dependent).
    """
    remove_host_fingerprints(known_hosts_path, host_name)
    add_fingerprints_to_known_hosts(known_hosts_path, fingerprints)
    use_hashing = ssh_config_uses_hashing_win() if windows else ssh_config_uses_hashing()
    if use_hashing:
        hash_known_hosts(known_hosts_path)


def remove_host_fingerprints(known_hosts_path: str, host_name: str) -> None:
    """
    Remove all fingerprints of given host.
    """
    if not os.path.exists(known_hosts_path):
        return
    subprocess.run(
        f"ssh-keygen -R {host_name} -f {known_hosts_path}",
        capture_output=True,
        text=True,
        shell=True,
        check=True
    )


def add_fingerprints_to_known_hosts(known_hosts_path: str, fingerprints: Set[Fingerprint]) -> None:
    """
    Appends fingerprints to known hosts.
    """
    with open(known_hosts_path, "a", encoding="utf-8") as f:
        for k in fingerprints:
            f.write(str(k) + "\n")


def hash_known_hosts(known_hosts_path: str) -> None:
    """
    Hash known_hosts file.
    """
    subprocess.run(
        f"ssh-keygen -Hf {known_hosts_path}",
        capture_output=True,
        text=True,
        shell=True,
        check=True
    )
    if os.path.exists(known_hosts_path + ".old"):
        os.remove(known_hosts_path + ".old")


def ssh_config_uses_hashing() -> bool:
    """
    Check if HashKnownHosts is used on Unix-like systems.
    """
    res_grep = subprocess.run(
        f"ssh -G Host | grep hashknownhosts",
        capture_output=True,
        text=True,
        shell=True
    )
    return res_grep.stdout.split()[1] == "yes" if res_grep.stdout else False


def ssh_config_uses_hashing_win() -> bool:
    """
    Check if HashKnownHosts is used on Windows partition.
    """
    res_grep = subprocess.run(
        f"cmd.exe /c ssh -G Host | grep hashknownhosts",
        capture_output=True,
        text=True,
        shell=True
    )
    return res_grep.stdout.split()[1] == "yes" if res_grep.stdout else False


def clean_key_at_error(key_path: str, key_path_win_wsl: str) -> callable:
    """
    Returns a function that removes any generated keys by the script if called (e.g. during exceptions).
    """

    def _clean() -> None:
        for key in (key_path, key_path_win_wsl):
            if key is None:
                continue
            ssh_path_ = os.path.dirname(key)
            if not os.path.exists(key):
                continue
            os.remove(key)
            if os.path.exists(key + ".pub"):
                os.remove(key + ".pub")
            for file_name in os.listdir(ssh_path_):
                if "ssh-copy-id" in file_name:
                    os.rmdir(os.path.join(ssh_path_, file_name))

    return _clean


def write_ssh_config(username: str) -> callable:
    """
    Returns a function that handles writing of .ssh/config.
    """

    def _write_config(key_path: str, identity_file_override: str = None) -> None:
        """
        Write config. If not present, add host and new identity file.
        """
        config_path = os.path.join(os.path.dirname(key_path), "config")
        identity_file = key_path if identity_file_override is None else identity_file_override
        target_data = [
            f"\tIdentityFile {identity_file}\n",
            f"\tUser {username}\n"
        ]
        target_alias = f"Host {HOST_ALIAS}"
        target_normal = f"Host *{HOST}"

        def get_config_normal_lines() -> List[str]:
            return [f"{target_normal}\n"] + target_data

        def get_config_alias_lines() -> List[str]:
            return [
                f"{target_alias}\n",
                f"\tHostName {HOST}\n"
            ] + target_data

        def get_identity_file_lines(lines: List[str], start_line: int) -> List[Tuple[int, str]]:
            """
            For a given Host entry get all associated identityFiles.
            """
            identity_lines = []
            for c, line_ in enumerate(lines[start_line + 1:], start=1):
                if "IdentityFile" in line_:
                    identity_lines.append((c + start_line, line_))
                if "Host " in line_:
                    break
            return identity_lines

        def update_lines(lines: List[str], start_line: int, identity_lines: List[Tuple[int, str]]) -> Tuple[List[str], bool]:
            added = False
            for _, l in identity_lines:
                if key_path in l:
                    return lines, added

            file_add = f"\tIdentityFile {identity_file}\n"
            if len(identity_lines) < 1:
                lines.insert(start_line + 1, file_add)
            else:
                lines.insert(identity_lines[0][0], file_add)
            added = True
            return lines, added

        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            found_normal, found_alias = None, None
            normal_updated = False

            for c, l in enumerate(lines):
                if target_normal in l:
                    found_normal = c
                elif target_alias in l:
                    found_alias = c

            if found_normal is not None:
                identity_lines = get_identity_file_lines(lines, found_normal)
                lines, normal_updated = update_lines(lines, found_normal, identity_lines)
            else:
                lines.append("\n")
                lines += get_config_normal_lines()

            if found_alias is not None:
                if normal_updated and found_alias > found_normal:
                    found_alias += 1
                identity_lines = get_identity_file_lines(lines, found_alias)
                lines, _ = update_lines(lines, found_alias, identity_lines)
            else:
                lines.append("\n")
                lines += get_config_alias_lines()

            with open(config_path, "w", encoding="utf-8") as f:
                f.writelines(lines)
        else:
            with open(config_path, "w", encoding="utf-8") as f:
                f.writelines(get_config_normal_lines())
                f.write("\n")
                f.writelines(get_config_alias_lines())

    return _write_config


def get_wsl_windows_homedir() -> str:
    return subprocess.run(
        f'wslpath "{get_windows_home_dir()}"',
        capture_output=True,
        text=True,
        shell=True
    ).stdout.strip()


def get_windows_home_dir() -> str:
    return subprocess.run(
        f'cmd.exe /c echo %USERPROFILE%',
        capture_output=True,
        text=True,
        shell=True
    ).stdout.strip()


class PtyHandle:
    """
    Handles minimalistic interactions with pseudo-terminals.
    """

    def __init__(self, pid, fd) -> None:
        self.pid = pid
        self.fd = fd

        readf = io.open(fd, "rb", buffering=0)
        writef = io.open(fd, "wb", buffering=0, closefd=False)
        self.fileObj = io.BufferedRWPair(readf, writef)

        self.unicode = True
        self.closed = False

    def read(self, size=1024) -> str:
        try:
            b = self.fileObj.read1(size)
            return b.decode() if self.unicode else b
        except OSError:
            raise EOFError("EOF")

    def write(self, b: Union[bytes, str], flush: bool = True) -> int:
        w = self.fileObj.write(b.encode() if self.unicode else b)
        if flush:
            self.fileObj.flush()
        return w

    def close(self) -> None:
        if self.closed:
            return
        self.fileObj.close()
        self.fd = -1
        self.closed = True

    def terminate(self) -> None:
        os.kill(self.pid, signal.SIGSTOP)
        os.waitpid(self.pid, os.WSTOPPED)

    def __del__(self) -> None:
        if not self.closed:
            self.close()

    @classmethod
    def spawn(cls, argv: List[str]):
        argv = argv[:]
        command = argv[0]
        command_with_path = shutil.which(command)
        assert command_with_path is not None, "Command not found"

        argv[0] = command_with_path
        exec_err_pipe_read, exec_err_pipe_write = os.pipe()
        pid, fd = pty.fork()

        if pid == pty.CHILD:
            os.close(exec_err_pipe_read)
            fcntl.fcntl(exec_err_pipe_write, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
            try:
                os.execv(command_with_path, argv)
            except OSError as err:
                os.write(exec_err_pipe_write, str(err).encode())
                os.close(exec_err_pipe_write)
                os._exit(os.EX_OSERR)

        instance = cls(pid, fd)
        os.close(exec_err_pipe_write)
        exec_err_data = os.read(exec_err_pipe_read, 4096)
        os.close(exec_err_pipe_read)

        if len(exec_err_data) != 0:
            raise Exception(f"Subprocess Failed: {exec_err_data.decode()}")

        return instance


class PtyHandler:
    class Match:
        def __init__(
            self,
            target: str,
            send: str = None,
            callback: callable = None,
            timeout: int = None
        ) -> None:
            self.target = target
            self.send = send
            self._callback = callback
            self.timeout = timeout
            self._time_start = time.time()

            self.matched = False
            self.matched_line = None
            self.matched_line_idx = None

        def reached_timeout(self) -> bool:
            if self.timeout is None:
                return False
            return (time.time() - self._time_start) > self.timeout

        def match(self, lines: List[str]) -> bool:
            for c, l in enumerate(lines):
                if self.target in l:
                    self.matched = True
                    self.matched_line = l
                    self.matched_line_idx = c
            return self.matched

        def invoke_callback(self) -> None:
            if self._callback is not None:
                self._callback(self)

    class _PtyWrapper:
        def __init__(self, process: PtyHandle) -> None:
            self.pty = process
            self.lines_send = []
            self._buffer_queue = Queue()
            self._dispatch_read_thread()

            self._activeMatches = set()
            self.failedMatches = set()
            self.successfulMatches = set()
            self._valid_matching = False
            self.exited = False

            self._lock_run = threading.Lock()
            self._lockMatches = threading.Lock()
            self.matcher_thread = None
            self.Match_thread_kill_event = threading.Event()
            self._debug = False
            self._at_exit = None

        def _dispatch_read_thread(self) -> None:
            self.stop_reading_event = threading.Event()
            self.reader_thread = threading.Thread(
                target=self._read_pty_blocking,
                args=(self.stop_reading_event,),
                daemon=True
            )
            self.reader_thread.start()

        def _read_pty_blocking(self, event: threading.Event, buffer_size: int = 1024) -> None:
            try:
                while not event.is_set():
                    self._buffer_queue.put(self.pty.read(buffer_size))
            except EOFError:
                pass

        def get_lines(self, keepLineBreaks: bool = False) -> List[str]:
            lines = []
            for i in list(self._buffer_queue.queue):
                lines += i.splitlines(keepLineBreaks)
            return lines

        def send_line(self, line: str, save: bool = True) -> int:
            w = self.pty.write(line + "\n")
            if save:
                self.lines_send.append(line)
            return w

        def match_send(
            self,
            match: str,
            send: str = None,
            callback: callable = None,
            timeout: int = None
        ) -> None:
            m = PtyHandler.Match(match, send, callback, timeout)
            with self._lockMatches:
                self._activeMatches.add(m)

            if self.matcher_thread is None:
                self.matcher_thread = threading.Thread(
                    target=self._run_matching,
                    args=(self.Match_thread_kill_event,)
                )
                self.matcher_thread.start()

        def match_join(self) -> None:
            self.matcher_thread.join()

        def confirm_matching(self) -> None:
            self.Match_thread_kill_event.set()
            self._valid_matching = True

        def valid_matching(self) -> bool:
            return self._valid_matching

        def _run_matching(self, event: threading.Event) -> None:
            with self._lock_run:
                while len(self._activeMatches) > 0 and not event.is_set():
                    with self._lockMatches:
                        matches = {m for m in self._activeMatches}
                    removeMatches = set()
                    lines = self.get_lines()

                    for m in matches:
                        if m.reached_timeout():
                            removeMatches.add(m)
                        if m.match(lines):
                            if self._debug:
                                print("Matched:", m.target, "--- With:", m.matched_line)
                            if m.send is not None:
                                self.send_line(m.send)
                            try:
                                m.invoke_callback()
                            except SystemExit as e:
                                self.exited = True
                                if self._debug:
                                    print("IO:", self.get_lines(), self.lines_send)
                                if self._at_exit:
                                    self._at_exit()
                                os._exit(e.code)
                            removeMatches.add(m)

                    with self._lockMatches:
                        for m in removeMatches:
                            if m.matched:
                                self.successfulMatches.add(m)
                            else:
                                self.failedMatches.add(m)
                            self._activeMatches.remove(m)

    @staticmethod
    def spawn(argv: List[str], **kwargs) -> _PtyWrapper:
        return PtyHandler._PtyWrapper(PtyHandle.spawn(argv, **kwargs))

    @staticmethod
    def spawn_shell(argv_str: str, **kwargs) -> _PtyWrapper:
        return PtyHandler.spawn(shlex.split(argv_str), **kwargs)


class Logger:
    """
    Generic logging class
    """
    FILE = "".join(__file__.split(".")[:-1]) + "[LOG].txt"

    class Level(Enum):
        class _Lvl:
            def __init__(self, priority: int, prefix: str = "", prefix_padding: bool = True) -> None:
                self.priority = priority
                self.prefix = prefix + " " if (prefix_padding and prefix != "") else prefix

        NONE = _Lvl(0)
        FATAL = _Lvl(1, "[FATAL-ERROR]")
        ERROR = _Lvl(2, "[ERROR]")
        INFO = _Lvl(3, "[INFO]")
        VERBOSE = _Lvl(4)
        ALL = _Lvl(5)

    def __init__(self, log_file: str = None) -> None:
        self.logging_level = Logger.Level.ERROR
        self.log_file = Logger.FILE if log_file is None else log_file
        self.force_to_stdout = False

    def print(self, msg: str, logging_level: Level = Level.VERBOSE, allow_none: bool = False) -> None:
        if self._printable(logging_level, allow_none):
            print(f"{logging_level.value.prefix}{msg}")

    def print_file(
        self,
        msg: str,
        logging_level: Level = Level.VERBOSE,
        allow_none: bool = False,
        use_auto_format: bool = True
    ) -> None:
        if self.force_to_stdout:
            self.print(msg, logging_level, allow_none)
            return

        if self._printable(logging_level, allow_none):
            suffix = f"[{datetime.now()}] " if use_auto_format else ""
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(suffix + logging_level.value.prefix + msg + "\n")

    def _printable(self, logging_level: Level = Level.VERBOSE, allow_none: bool = False) -> bool:
        if not allow_none:
            assert logging_level != Logger.Level.NONE, "Logging Level 'None' is prohibited"
        return logging_level.value.priority <= self.logging_level.value.priority


class InputHandler:
    class PromptType:
        def __init__(
            self,
            logger: Logger,
            prompt: str = "Input",
            input_type: type = str,
            check: callable = None,
            check_err_msg: str = "Invalid Input",
            force: bool = False,
            verbose: bool = False,
            confirm: bool = False,
            confirm_prompt: str = "Enter Input Again: ",
            confirm_err_msg: str = "Inputs Do Not Match",
            suggestion: str = None,
            auto_format: bool = True
        ) -> None:
            self.logger = logger
            self.prompt = prompt
            self.suggestion = suggestion
            self.auto_format = auto_format
            suggestion_string = f" ('{suggestion}')" if suggestion else ""
            self.prompt_formatted = f"{prompt}{suggestion_string}{': ' if self.auto_format else ''}"
            self.inp_type = input_type
            self.check = check
            self.check_err_msg = check_err_msg
            self.force = force
            self.verbose = verbose
            self.confirm = confirm
            self.confirm_prompt = confirm_prompt
            self.confirm_prompt_formatted = (
                f"{confirm_prompt}{': ' if self.auto_format else ''}"
            )
            self.confirm_err_msg = confirm_err_msg
            self._confirm_buffer = None

        def get_input(self, prompt_override: str = None):
            inp = self._capture_input(prompt_override)
            if inp == "" and self.suggestion is not None:
                inp = self.suggestion
            inp = self._cast_input(inp)
            valid = self._check_input(inp)
            if valid:
                if self.confirm:
                    if self._confirm_buffer is None:
                        self._confirm_buffer = inp
                        return self.get_input(prompt_override=self.confirm_prompt_formatted)
                    else:
                        if self._confirm_buffer == inp:
                            return inp
                        else:
                            self.logger.print(self.confirm_err_msg, Logger.Level.INFO)
                            if self.force:
                                self._confirm_buffer = None
                                return self.get_input()
                            return None
                else:
                    return inp
            if self.force:
                if self.verbose:
                    self.logger.print(self.check_err_msg, Logger.Level.INFO)
                if self.confirm:
                    self._confirm_buffer = None
                return self.get_input()
            return None

        def _capture_input(self, prompt_override: str = None) -> str:
            return input(self.prompt_formatted if prompt_override is None else prompt_override)

        def _cast_input(self, inp: str):
            if self.inp_type is str:
                return inp
            try:
                return self.inp_type(inp)
            except ValueError:
                return None

        def _check_input(self, inp: Any) -> bool:
            if inp is None:
                return False
            else:
                return True if self.check is None else self.check(inp)

    class PromptPassword(PromptType):
        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **kwargs)

        def _capture_input(self, prompt_override: str = None) -> str:
            return getpass(self.prompt_formatted if prompt_override is None else prompt_override)

    def __init__(self, logger: Logger) -> None:
        self.logger = logger

    def get_type(self, prompt: str = "Input: ", input_type: type = str, check: callable = None, force: bool = False,  **kwargs):
        p = self.PromptType(
            logger=self.logger,
            prompt=prompt,
            input_type=input_type,
            check=check,
            force=force,
            **kwargs
        )
        return p.get_input()

    def get_password(self, prompt: str = "Password: ", check: callable = None, force: bool = False,  **kwargs):
        p = self.PromptPassword(
            logger=self.logger,
            prompt=prompt,
            check=check,
            force=force,
            **kwargs
        )
        return p.get_input()


class WrapError:
    """
    Utility that wraps any function and invokes a callback if an error occurred.
    """

    class _atErrorCallable:
        def __init__(self, function: callable = None) -> None:
            self.function = function

        def __call__(self, *args: Any, **kwargs: Any) -> Any:
            return self.function(*args, **kwargs) if self.function is not None else None

    def __init__(self, main_function: callable, at_error: callable = None, logger: Logger = None) -> None:
        self.main_function = main_function
        self.at_error = WrapError._atErrorCallable(at_error)
        self.logger = logger
        self.supress_err_output = False

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        try:
            return self.main_function(*args, **kwargs, atError=self.at_error)
        except Exception as e:
            self.at_error()
            if self.logger is not None:
                self.logger.print_file(traceback.format_exc(), Logger.Level.FATAL)
            if self.supress_err_output:
                self.logger.print(
                    "An unexpected error occurred during script execution. See log for further details.",
                    Logger.Level.FATAL
                )
                sys.exit(1)
            raise e
        except KeyboardInterrupt:
            self.at_error()
            sys.exit(1)


if __name__ == "__main__":
    logger = Logger()
    main = WrapError(main, None, logger)  # If any error occurs, generated keys will be removed
    main.supress_err_output = True
    main(logger)
