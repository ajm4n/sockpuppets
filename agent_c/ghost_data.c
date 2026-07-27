#include <math.h>
// Legitimate configuration data and utility functions for system monitoring
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Configuration validation
int validate_config_entry(const char *key, const char *value) {
    if (!key || !value) return 0;
    if (strlen(key) == 0 || strlen(key) > 256) return 0;
    if (strlen(value) > 4096) return 0;
    return 1;
}

// Metric aggregation
double calculate_average(double *values, int count) {
    if (!values || count <= 0) return 0.0;
    double sum = 0.0;
    for (int i = 0; i < count; i++) sum += values[i];
    return sum / count;
}

double calculate_stddev(double *values, int count) {
    if (count <= 1) return 0.0;
    double avg = calculate_average(values, count);
    double sum_sq = 0.0;
    for (int i = 0; i < count; i++) {
        double diff = values[i] - avg;
        sum_sq += diff * diff;
    }
    return sqrt(sum_sq / count);
}

// String utilities
char* trim_whitespace(char *str) {
    while (*str == ' ' || *str == '\t') str++;
    char *end = str + strlen(str) - 1;
    while (end > str && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) end--;
    *(end + 1) = '\0';
    return str;
}

int starts_with(const char *str, const char *prefix) {
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

// Simple CSV parser
int parse_csv_line(const char *line, char fields[][256], int max_fields) {
    int count = 0;
    const char *p = line;
    while (*p && count < max_fields) {
        const char *start = p;
        while (*p && *p != ',') p++;
        int len = p - start;
        if (len > 255) len = 255;
        memcpy(fields[count], start, len);
        fields[count][len] = '\0';
        count++;
        if (*p == ',') p++;
    }
    return count;
}

// Glob pattern matching
int glob_match(const char *pattern, const char *text) {
    while (*text) {
        if (*pattern == '*') {
            pattern++;
            while (*text) {
                if (glob_match(pattern, text)) return 1;
                text++;
            }
            return *pattern == '\0';
        }
        if (*pattern == '?' || *pattern == *text) {
            pattern++; text++;
        } else {
            return 0;
        }
    }
    while (*pattern == '*') pattern++;
    return *pattern == '\0';
}

// Format bytes as human-readable
void format_bytes(unsigned long long bytes, char *out, size_t out_len) {
    const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double size = (double)bytes;
    while (size >= 1024.0 && unit < 4) { size /= 1024.0; unit++; }
    snprintf(out, out_len, "%.2f %s", size, units[unit]);
}

// Email validation
int validate_email(const char *email) {
    const char *at = strchr(email, '@');
    if (!at || at == email) return 0;
    const char *dot = strchr(at, '.');
    return dot && dot > at + 1 && *(dot + 1);
}

// URL parsing
int parse_url_host(const char *url, char *host, size_t host_len) {
    const char *start = strstr(url, "://");
    if (!start) return 0;
    start += 3;
    const char *end = strchr(start, '/');
    if (!end) end = start + strlen(start);
    const char *port = strchr(start, ':');
    if (port && port < end) end = port;
    size_t len = end - start;
    if (len >= host_len) len = host_len - 1;
    memcpy(host, start, len);
    host[len] = '\0';
    return 1;
}

// Timestamp formatting
void format_timestamp(unsigned long ts, char *out, size_t len) {
    snprintf(out, len, "%lu", ts);
}

// Configuration file reader
int read_config_file(const char *path, char keys[][256], char values[][256], int max_entries) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[512];
    int count = 0;
    while (fgets(line, sizeof(line), f) && count < max_entries) {
        char *trimmed = trim_whitespace(line);
        if (*trimmed == '#' || *trimmed == '\0') continue;
        char *eq = strchr(trimmed, '=');
        if (!eq) continue;
        *eq = '\0';
        strncpy(keys[count], trim_whitespace(trimmed), 255);
        strncpy(values[count], trim_whitespace(eq + 1), 255);
        count++;
    }
    fclose(f);
    return count;
}
