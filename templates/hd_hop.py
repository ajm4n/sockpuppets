import ctypes, os, sys, struct, base64, time
from ctypes import wintypes

k32 = ctypes.windll.kernel32
wts = ctypes.windll.wtsapi32
adv = ctypes.windll.advapi32
out = r'C:\Users\Public\pyframe.txt'
host_note = r'C:\Users\Public\pyhost.txt'

class SI(ctypes.Structure):
    _fields_ = [
        ('cb', wintypes.DWORD), ('reserved', wintypes.LPWSTR), ('desktop', wintypes.LPWSTR),
        ('title', wintypes.LPWSTR), ('x', wintypes.DWORD), ('y', wintypes.DWORD),
        ('xSize', wintypes.DWORD), ('ySize', wintypes.DWORD), ('xCountChars', wintypes.DWORD),
        ('yCountChars', wintypes.DWORD), ('fillAttribute', wintypes.DWORD), ('flags', wintypes.DWORD),
        ('showWindow', wintypes.WORD), ('cbReserved2', wintypes.WORD), ('lpReserved2', ctypes.c_void_p),
        ('stdInput', wintypes.HANDLE), ('stdOutput', wintypes.HANDLE), ('stdError', wintypes.HANDLE),
    ]

class PI(ctypes.Structure):
    _fields_ = [('hProcess', wintypes.HANDLE), ('hThread', wintypes.HANDLE), ('pid', wintypes.DWORD), ('tid', wintypes.DWORD)]

k32.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
k32.WTSGetActiveConsoleSessionId.restype = wintypes.DWORD
wts.WTSQueryUserToken.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
adv.DuplicateTokenEx.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.POINTER(wintypes.HANDLE)]
adv.CreateProcessAsUserW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR, ctypes.POINTER(SI), ctypes.POINTER(PI)]

def session():
    sid = wintypes.DWORD()
    k32.ProcessIdToSessionId(k32.GetCurrentProcessId(), ctypes.byref(sid))
    return sid.value

def write_frame():
    u32 = ctypes.windll.user32
    g32 = ctypes.windll.gdi32
    u32.CreateDesktopW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    u32.CreateDesktopW.restype = ctypes.c_void_p
    u32.SetThreadDesktop.argtypes = [ctypes.c_void_p]
    u32.SetThreadDesktop.restype = wintypes.BOOL
    u32.IsWindowVisible.argtypes = [ctypes.c_void_p]
    u32.IsWindowVisible.restype = wintypes.BOOL
    u32.GetWindowTextW.argtypes = [ctypes.c_void_p, wintypes.LPWSTR, ctypes.c_int]
    u32.GetClassNameW.argtypes = [ctypes.c_void_p, wintypes.LPWSTR, ctypes.c_int]
    u32.GetWindowRect.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    u32.GetWindowDC.argtypes = [ctypes.c_void_p]
    u32.GetWindowDC.restype = ctypes.c_void_p
    u32.PrintWindow.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.UINT]
    u32.PrintWindow.restype = wintypes.BOOL
    u32.ReleaseDC.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    g32.CreateCompatibleDC.argtypes = [ctypes.c_void_p]
    g32.CreateCompatibleDC.restype = ctypes.c_void_p
    g32.CreateCompatibleBitmap.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
    g32.CreateCompatibleBitmap.restype = ctypes.c_void_p
    g32.SelectObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    g32.SelectObject.restype = ctypes.c_void_p
    g32.DeleteObject.argtypes = [ctypes.c_void_p]
    g32.DeleteDC.argtypes = [ctypes.c_void_p]
    g32.GetDIBits.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.UINT, wintypes.UINT, ctypes.c_void_p, ctypes.c_void_p, wintypes.UINT]
    u32.GetDC.argtypes = [ctypes.c_void_p]
    u32.GetDC.restype = ctypes.c_void_p
    g32.BitBlt.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_int, wintypes.DWORD]
    g32.StretchBlt.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.DWORD]
    name = 'd' + os.urandom(3).hex()
    desk = u32.CreateDesktopW(name, None, None, 0, 0x10000000, None)
    if not desk or not u32.SetThreadDesktop(desk):
        open(host_note, 'w').write('desktop open failed %d' % k32.GetLastError())
        return
    class RECT(ctypes.Structure):
        _fields_ = [('l', wintypes.LONG), ('t', wintypes.LONG), ('r', wintypes.LONG), ('b', wintypes.LONG)]
    class SI2(ctypes.Structure):
        _fields_ = SI._fields_
    wins = []
    cb_type = ctypes.WINFUNCTYPE(wintypes.BOOL, ctypes.c_void_p, ctypes.c_void_p)
    def cb(hwnd, lp):
        if u32.IsWindowVisible(hwnd):
            wins.append(hwnd)
        return True
    enum_cb = cb_type(cb)
    u32.EnumWindows(enum_cb, 0)
    dw, dh = 320, 200
    stride = ((dw * 3 + 3) // 4) * 4
    hdc = u32.GetDC(0)
    mem = g32.CreateCompatibleDC(hdc)
    bmp = g32.CreateCompatibleBitmap(hdc, dw, dh)
    g32.SelectObject(mem, bmp)
    painted = 0
    titles = []
    for hwnd in wins:
        rc = RECT()
        u32.GetWindowRect(hwnd, ctypes.byref(rc))
        ww, wh = rc.r - rc.l, rc.b - rc.t
        if ww < 40 or wh < 40:
            continue
        src = u32.GetWindowDC(hwnd)
        tmp = g32.CreateCompatibleDC(src)
        bits = g32.CreateCompatibleBitmap(src, ww, wh)
        g32.SelectObject(tmp, bits)
        if not u32.PrintWindow(hwnd, tmp, 2):
            g32.BitBlt(tmp, 0, 0, ww, wh, src, 0, 0, 0x00CC0020)
        g32.StretchBlt(mem, 8, 8, dw - 16, dh - 16, tmp, 0, 0, ww, wh, 0x00CC0020)
        g32.DeleteObject(bits)
        g32.DeleteDC(tmp)
        u32.ReleaseDC(hwnd, src)
        buf = ctypes.create_unicode_buffer(64)
        u32.GetWindowTextW(hwnd, buf, 64)
        titles.append(buf.value or '?')
        painted += 1
        if painted >= 3:
            break
    class BI(ctypes.Structure):
        _fields_ = [('size', wintypes.DWORD), ('width', wintypes.LONG), ('height', wintypes.LONG),
                    ('planes', wintypes.WORD), ('bitCount', wintypes.WORD), ('compression', wintypes.DWORD),
                    ('sizeImage', wintypes.DWORD), ('xppm', wintypes.LONG), ('yppm', wintypes.LONG),
                    ('clrUsed', wintypes.DWORD), ('clrImportant', wintypes.DWORD)]
    bi = BI(40, dw, dh, 1, 24, 0, 0, 0, 0, 0, 0)
    pixels = ctypes.create_string_buffer(stride * dh)
    g32.GetDIBits(mem, bmp, 0, dh, pixels, ctypes.byref(bi), 0)
    blob = pixels.raw
    data = b'BM' + struct.pack('<IHHI', 54 + len(blob), 0, 0, 54) + struct.pack('<IiiHHIIiiII', 40, dw, dh, 1, 24, 0, len(blob), 0, 0, 0, 0) + blob
    open(out, 'w').write('HDIMG:320,200:' + base64.b64encode(data).decode())
    open(host_note, 'w').write('host session=%d wins=%d %s' % (session(), painted, ' '.join(titles)))

if os.environ.get('SP_HD_HOST') == '1' or session() != 0:
    try:
        write_frame()
    except Exception as ex:
        open(host_note, 'w').write('capture failed %s' % ex)
    sys.exit(0)

sid = k32.WTSGetActiveConsoleSessionId()
tok = wintypes.HANDLE()
dup = wintypes.HANDLE()
if not wts.WTSQueryUserToken(sid, ctypes.byref(tok)):
    sys.exit(2)
if not adv.DuplicateTokenEx(tok, 0x02000000, None, 2, 1, ctypes.byref(dup)):
    sys.exit(3)
si = SI()
si.cb = ctypes.sizeof(si)
si.desktop = 'winsta0\\default'
pi = PI()
script = os.path.abspath(__file__)
cmd = ctypes.create_unicode_buffer('"%s" "%s"' % (sys.executable, script))
os.environ['SP_HD_HOST'] = '1'
ok = adv.CreateProcessAsUserW(dup, None, cmd, None, None, False, 0, None, None, ctypes.byref(si), ctypes.byref(pi))
os.environ.pop('SP_HD_HOST', None)
if not ok:
    print('launch failed', k32.GetLastError())
    sys.exit(4)
k32.CloseHandle(pi.hProcess)
k32.CloseHandle(pi.hThread)
deadline = time.time() + 20
while time.time() < deadline and not os.path.exists(out):
    time.sleep(0.4)
print(open(host_note).read().strip() if os.path.exists(host_note) else 'no host')
print('frame %d' % os.path.getsize(out) if os.path.exists(out) else 'no frame')
