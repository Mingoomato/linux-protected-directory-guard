#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/fanotify.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdalign.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include "fanotify_records.h"

#define MAX_POLICY_BYTES (1024U * 1024U)
#define MAX_ROOTS 64
#define MAX_RULES 512
#define MAX_LINE 4096

struct rule {
    char id[128], scope[PATH_MAX], operation[64], action[16];
};
struct policy {
    char revision[128], default_action[16];
    char roots[MAX_ROOTS][PATH_MAX];
    size_t root_count;
    struct rule rules[MAX_RULES];
    size_t rule_count;
};

static volatile sig_atomic_t stopping;
static void stop_signal(int sig) { (void)sig; stopping = 1; }

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') ++s;
    size_t n = strlen(s);
    while (n && (s[n-1] == ' ' || s[n-1] == '\t' || s[n-1] == '\r' || s[n-1] == '\n'))
        s[--n] = '\0';
    return s;
}

static int read_policy_line(FILE *in, char *line, size_t cap,
                            size_t *line_length, size_t *input_bytes) {
    *line_length = 0;
    *input_bytes = 0;
    int ch;
    while ((ch = fgetc(in)) != EOF) {
        ++*input_bytes;
        if (ch == '\n') { line[*line_length] = '\0'; return 1; }
        if (*line_length + 1U >= cap) { errno = EFBIG; return -1; }
        line[(*line_length)++] = (char)ch;
    }
    if (ferror(in)) { errno = EIO; return -1; }
    if (*line_length == 0U) return 0;
    line[*line_length] = '\0';
    return 1;
}

static int copy_value(char *dst, size_t cap, const char *src) {
    size_t n = strlen(src);
    if (!n || n >= cap) { errno = EINVAL; return -1; }
    memcpy(dst, src, n + 1U);
    return 0;
}

static int valid_identifier(const char *s) {
    if (!s || !*s) return 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {
        const unsigned char c = *p;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.')) return 0;
    }
    return 1;
}

static int mark_once(unsigned *fields, unsigned bit) {
    if (*fields & bit) { errno = EEXIST; return -1; }
    *fields |= bit;
    return 0;
}

static int is_broad_root(const char *path) {
    return !strcmp(path, "/") || !strcmp(path, "/etc") || !strcmp(path, "/usr") ||
           !strcmp(path, "/home") || !strcmp(path, "/var") || !strcmp(path, "/root");
}

static int safe_scope(const char *path, char out[PATH_MAX]) {
    if (!path || path[0] != '/') { errno = EINVAL; return -1; }
    if (strlen(path) >= PATH_MAX) { errno = ENAMETOOLONG; return -1; }
    if (!realpath(path, out)) return -1;
    if (is_broad_root(out)) { errno = EPERM; return -1; }
    return 0;
}

static int path_within(const char *root, const char *path) {
    size_t n = strlen(root);
    return !strncmp(root, path, n) && (path[n] == '\0' || path[n] == '/');
}

static int scopes_overlap(const char *a, const char *b) {
    return path_within(a, b) || path_within(b, a);
}

static int valid_op(const char *op) {
    return !strcmp(op, "open_for_read") || !strcmp(op, "open_for_write") ||
           !strcmp(op, "unlink") || !strcmp(op, "rename");
}

static int parse_policy(const char *file, struct policy *p) {
    memset(p, 0, sizeof(*p));
    strcpy(p->default_action, "allow");
    int fd = open(file, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    FILE *in = fdopen(fd, "r");
    if (!in) { close(fd); return -1; }
    enum { SECTION_NONE, SECTION_ROOTS, SECTION_RULES } section = SECTION_NONE;
    struct rule current = {0};
    bool have_rule = false;
    unsigned top_fields = 0, current_fields = 0;
    char line[MAX_LINE + 1U];
    size_t bytes = 0;
    int rc = 0;
    for (;;) {
        size_t line_length = 0, input_bytes = 0;
        int line_status = read_policy_line(in, line, sizeof(line), &line_length, &input_bytes);
        if (line_status == 0) break;
        if (line_status < 0) { rc = -1; break; }
        bytes += input_bytes;
        if (bytes > MAX_POLICY_BYTES || line_length > MAX_LINE) { errno = EFBIG; rc = -1; break; }
        if (strchr(line, '\t')) { errno = EINVAL; rc = -1; break; }
        char *s = trim(line);
        if (!*s || *s == '#') continue;
        unsigned indent = (unsigned)(s - line);
        if (s[0] == '-' && s[1] == ' ') {
            if (indent != 2U) { errno = EINVAL; rc = -1; break; }
            char *value = trim(s + 2);
            if (section == SECTION_ROOTS) {
                if (p->root_count >= MAX_ROOTS) { errno = E2BIG; rc = -1; break; }
                char root[PATH_MAX];
                if (safe_scope(value, root) != 0) { rc = -1; break; }
                for (size_t i = 0; i < p->root_count; ++i) {
                    if (scopes_overlap(p->roots[i], root)) { errno = EEXIST; rc = -1; break; }
                }
                if (rc != 0) break;
                strcpy(p->roots[p->root_count++], root);
                continue;
            }
            if (section == SECTION_RULES) {
                if (have_rule) {
                    if (!current.id[0] || !current.scope[0] || !current.operation[0] || !current.action[0]) {
                        errno = EINVAL; rc = -1; break;
                    }
                    if (p->rule_count >= MAX_RULES) { errno = E2BIG; rc = -1; break; }
                    for (size_t i = 0; i < p->rule_count; ++i)
                        if (!strcmp(p->rules[i].id, current.id)) { errno = EEXIST; rc = -1; break; }
                    if (rc != 0) break;
                    p->rules[p->rule_count++] = current;
                }
                memset(&current, 0, sizeof(current)); have_rule = true;
                current_fields = 0;
                char *colon = strchr(value, ':');
                if (!colon) { errno = EINVAL; rc = -1; break; }
                *colon = '\0';
                if (strcmp(trim(value), "id") != 0 || mark_once(&current_fields, 1U) != 0 ||
                    copy_value(current.id, sizeof(current.id), trim(colon+1)) != 0 ||
                    !valid_identifier(current.id)) {
                    errno = EINVAL; rc = -1; break;
                }
                continue;
            }
            errno = EINVAL; rc = -1; break;
        }
        char *colon = strchr(s, ':');
        if (!colon) { errno = EINVAL; rc = -1; break; }
        *colon = '\0';
        char *key = trim(s), *value = trim(colon + 1);
        if (indent == 0) {
            unsigned bit = !strcmp(key, "schema_version") ? 1U :
                (!strcmp(key, "policy_revision") ? 2U :
                (!strcmp(key, "mode") ? 4U :
                (!strcmp(key, "default_action") ? 8U :
                (!strcmp(key, "protected_roots") ? 16U :
                (!strcmp(key, "rules") ? 32U : 0U)))));
            if (!bit) { errno = EINVAL; rc = -1; break; }
            if (mark_once(&top_fields, bit) != 0) { rc = -1; break; }
            if (!strcmp(key, "schema_version")) {
                if (strcmp(value, "policy.v1")) { errno = EINVAL; rc = -1; break; }
            } else if (!strcmp(key, "policy_revision")) {
                if (copy_value(p->revision, sizeof(p->revision), value) != 0 ||
                    !valid_identifier(p->revision)) { errno = EINVAL; rc = -1; break; }
            } else if (!strcmp(key, "mode")) {
                if (strcmp(value, "audit")) { errno = ENOTSUP; rc = -1; break; }
            } else if (!strcmp(key, "default_action")) {
                if (strcmp(value, "allow") && strcmp(value, "deny")) { errno = EINVAL; rc = -1; break; }
                strcpy(p->default_action, value);
            } else if (!strcmp(key, "protected_roots")) {
                section = SECTION_ROOTS;
            } else if (!strcmp(key, "rules")) {
                section = SECTION_RULES;
            } else {
                errno = EINVAL; rc = -1; break;
            }
        } else if (section == SECTION_RULES && have_rule) {
            if (indent != 4U) { errno = EINVAL; rc = -1; break; }
            if (!strcmp(key, "scope")) {
                if (mark_once(&current_fields, 2U) != 0) { rc = -1; break; }
                char scope[PATH_MAX];
                if (safe_scope(value, scope) != 0 || copy_value(current.scope, sizeof(current.scope), scope) != 0) {
                    rc = -1; break;
                }
            } else if (!strcmp(key, "operation")) {
                if (mark_once(&current_fields, 4U) != 0) { rc = -1; break; }
                if (!valid_op(value) || copy_value(current.operation, sizeof(current.operation), value) != 0) {
                    errno = EINVAL; rc = -1; break;
                }
            } else if (!strcmp(key, "action")) {
                if (mark_once(&current_fields, 16U) != 0) { rc = -1; break; }
                if ((strcmp(value, "allow") && strcmp(value, "deny")) ||
                    copy_value(current.action, sizeof(current.action), value) != 0) {
                    errno = EINVAL; rc = -1; break;
                }
            } else if (!strcmp(key, "subject")) {
                if (mark_once(&current_fields, 8U) != 0) { rc = -1; break; }
                if (strcmp(value, "any")) { errno = ENOTSUP; rc = -1; break; }
            } else {
                errno = EINVAL; rc = -1; break;
            }
        } else {
            errno = EINVAL; rc = -1; break;
        }
    }
    if (rc == 0 && have_rule) {
        if (!current.id[0] || !current.scope[0] || !current.operation[0] || !current.action[0]) {
            errno = EINVAL; rc = -1;
        } else {
            for (size_t i = 0; i < p->rule_count; ++i)
                if (!strcmp(p->rules[i].id, current.id)) { errno = EEXIST; rc = -1; break; }
            if (rc == 0 && p->rule_count < MAX_RULES) p->rules[p->rule_count++] = current;
            else if (p->rule_count >= MAX_RULES) { errno = E2BIG; rc = -1; }
        }
    }
    fclose(in);
    const unsigned required_top_fields = 1U | 2U | 4U | 16U | 32U;
    if (rc == 0 && ((top_fields & required_top_fields) != required_top_fields ||
                    !p->revision[0] || !p->root_count || !p->rule_count)) {
        errno = EINVAL; return -1;
    }
    for (size_t i = 0; rc == 0 && i < p->rule_count; ++i) {
        bool inside = false;
        for (size_t j = 0; j < p->root_count; ++j)
            if (path_within(p->roots[j], p->rules[i].scope)) inside = true;
        if (!inside) { errno = EPERM; rc = -1; }
    }
    for (size_t i = 0; rc == 0 && i < p->rule_count; ++i) {
        for (size_t j = i + 1U; j < p->rule_count; ++j) {
            const struct rule *a = &p->rules[i], *b = &p->rules[j];
            if (strcmp(a->operation, b->operation) || !scopes_overlap(a->scope, b->scope)) continue;
            if (!strcmp(a->scope, b->scope) || strcmp(a->action, b->action)) {
                errno = EINVAL; rc = -1; break;
            }
        }
    }
    return rc;
}

static int evaluate(const struct policy *p, const char *path, const char *op,
                    char action[16], char rule_id[128]) {
    const struct rule *best = NULL;
    rule_id[0] = '\0';
    for (size_t i = 0; i < p->rule_count; ++i) {
        const struct rule *r = &p->rules[i];
        if (strcmp(r->operation, op) || !path_within(r->scope, path)) continue;
        if (!best || strlen(r->scope) > strlen(best->scope)) best = r;
    }
    if (best) {
        strcpy(action, best->action);
        strcpy(rule_id, best->id);
    } else strcpy(action, p->default_action);
    return 0;
}

static int json_escape(const char *s, char *out, size_t cap);

static const char *opt(int argc, char **argv, const char *key, const char *fallback) {
    for (int i = 1; i + 1 < argc; ++i) if (!strcmp(argv[i], key)) return argv[i+1];
    return fallback;
}

static int cmd_explain(const struct policy *p, const char *path_arg, const char *op) {
    char path[PATH_MAX], escaped_path[PATH_MAX * 6U];
    if (safe_scope(path_arg, path) != 0) { perror("dirguardctl: path"); return 2; }
    if (json_escape(path, escaped_path, sizeof(escaped_path)) != 0) {
        fprintf(stderr, "PDG_INVALID_PATH: cannot encode path for JSON\n"); return 2;
    }
    if (!valid_op(op)) { fprintf(stderr, "invalid operation\n"); return 2; }
    bool in_root = false;
    for (size_t i = 0; i < p->root_count; ++i) if (path_within(p->roots[i], path)) in_root = true;
    if (!in_root) { fprintf(stderr, "PDG_INVALID_POLICY: path outside protected roots\n"); return 2; }
    char action[16], id[128];
    evaluate(p, path, op, action, id);
    const char *reason = id[0] ? id : "DEFAULT_ACTION";
    printf("{\"schema_version\":\"guard_decision.v1\",\"id\":\"explain-%s-%s\","
           "\"policy_id\":\"%s\",\"policy_revision\":\"%s\","
           "\"operation\":\"%s\",\"source_api\":\"policy_explain\",\"decision\":\"%s\","
           "\"enforced\":false,\"hook_verified\":false,\"coverage\":\"audit_only\","
           "\"reason_code\":\"%s\",\"scope_identity\":{\"path\":\"%s\"},"
           "\"actor_attribution\":\"unknown\",\"pid_source\":\"unknown\",\"errno\":null}\n",
           p->revision, reason, p->revision, p->revision, op, action, reason, escaped_path);
    return 0;
}

/* POSIX paths may contain arbitrary bytes. Preserve valid UTF-8 and encode
 * each invalid byte as U+00XX so every emitted record remains valid JSON. */
static int json_escape(const char *s, char *out, size_t cap) {
    size_t n = 0;
    static const char hex[] = "0123456789abcdef";
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {
        if (*p == '"' || *p == '\\') {
            if (n + 2U >= cap) { errno = ENOSPC; return -1; }
            out[n++] = '\\'; out[n++] = (char)*p;
        } else if (*p < 0x20U) {
            if (n + 6U >= cap) { errno = ENOSPC; return -1; }
            out[n++] = '\\'; out[n++] = 'u'; out[n++] = '0'; out[n++] = '0';
            out[n++] = hex[*p >> 4]; out[n++] = hex[*p & 0x0fU];
        } else if (*p >= 0x7fU) {
            size_t utf8_len = 0;
            unsigned char c = *p;
            if (c >= 0xc2U && c <= 0xdfU && (p[1] & 0xc0U) == 0x80U) utf8_len = 2U;
            else if (c == 0xe0U && p[1] >= 0xa0U && p[1] <= 0xbfU &&
                     (p[2] & 0xc0U) == 0x80U) utf8_len = 3U;
            else if (((c >= 0xe1U && c <= 0xecU) || (c >= 0xeeU && c <= 0xefU)) &&
                     (p[1] & 0xc0U) == 0x80U && (p[2] & 0xc0U) == 0x80U) utf8_len = 3U;
            else if (c == 0xedU && p[1] >= 0x80U && p[1] <= 0x9fU &&
                     (p[2] & 0xc0U) == 0x80U) utf8_len = 3U;
            else if (c == 0xf0U && p[1] >= 0x90U && p[1] <= 0xbfU &&
                     (p[2] & 0xc0U) == 0x80U && (p[3] & 0xc0U) == 0x80U) utf8_len = 4U;
            else if (c >= 0xf1U && c <= 0xf3U && (p[1] & 0xc0U) == 0x80U &&
                     (p[2] & 0xc0U) == 0x80U && (p[3] & 0xc0U) == 0x80U) utf8_len = 4U;
            else if (c == 0xf4U && p[1] >= 0x80U && p[1] <= 0x8fU &&
                     (p[2] & 0xc0U) == 0x80U && (p[3] & 0xc0U) == 0x80U) utf8_len = 4U;
            if (utf8_len != 0U) {
                if (n + utf8_len >= cap) { errno = ENOSPC; return -1; }
                memcpy(out + n, p, utf8_len);
                n += utf8_len;
                p += utf8_len - 1U;
            } else {
                if (n + 6U >= cap) { errno = ENOSPC; return -1; }
                out[n++] = '\\'; out[n++] = 'u'; out[n++] = '0'; out[n++] = '0';
                out[n++] = hex[*p >> 4]; out[n++] = hex[*p & 0x0fU];
            }
        } else {
            if (n + 1U >= cap) { errno = ENOSPC; return -1; }
            out[n++] = (char)*p;
        }
    }
    if (n >= cap) { errno = ENOSPC; return -1; }
    out[n] = '\0';
    return 0;
}

static int write_all(int fd, const char *buffer, size_t length) {
    size_t written = 0;
    while (written < length) {
        ssize_t n = write(fd, buffer + written, length - written);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { if (n == 0) errno = EIO; return -1; }
        written += (size_t)n;
    }
    return 0;
}

static int parse_duration(const char *text, int *seconds) {
    if (!text || !*text) { errno = EINVAL; return -1; }
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p)
        if (*p < '0' || *p > '9') { errno = EINVAL; return -1; }
    errno = 0;
    char *end = NULL;
    long value = strtol(text, &end, 10);
    if (errno || !end || *end || value < 0 || value > INT_MAX) {
        errno = ERANGE;
        return -1;
    }
    *seconds = (int)value;
    return 0;
}

static int cmd_audit(const struct policy *p, const char *root_arg, const char *events_path,
                    int duration_sec) {
    char root[PATH_MAX];
    if (safe_scope(root_arg, root) != 0) { perror("dirguardctl: root"); return 2; }
    bool listed = false;
    for (size_t i = 0; i < p->root_count; ++i) if (!strcmp(p->roots[i], root)) listed = true;
    if (!listed) { fprintf(stderr, "PDG_INVALID_POLICY: root is not an exact protected root\n"); return 2; }
    int fan = fanotify_init(FAN_CLOEXEC | FAN_NONBLOCK | FAN_CLASS_NOTIF,
                            O_RDONLY | O_LARGEFILE | O_CLOEXEC);
    if (fan < 0) {
        int saved = errno;
        const char *code = (saved == EPERM || saved == EACCES) ?
            "PDG_INSUFFICIENT_PRIVILEGE" : "PDG_UNSUPPORTED_HOOK";
        fprintf(stderr, "{\"error\":\"%s\",\"coverage\":\"unsupported\","
                        "\"hook_verified\":false,\"errno\":%d}\n", code, saved);
        return 3;
    }
    uint64_t mask = FAN_OPEN | FAN_CLOSE_WRITE | FAN_EVENT_ON_CHILD;
    if (fanotify_mark(fan, FAN_MARK_ADD | FAN_MARK_MOUNT, mask, AT_FDCWD, root) != 0) {
        int saved = errno; close(fan);
        const char *code = (saved == EPERM || saved == EACCES) ?
            "PDG_INSUFFICIENT_PRIVILEGE" : "PDG_UNSUPPORTED_HOOK";
        fprintf(stderr, "{\"error\":\"%s\",\"coverage\":\"unsupported\","
                        "\"hook_verified\":false,\"errno\":%d}\n", code, saved);
        return 3;
    }
    int logfd = open(events_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC |
                     O_NOFOLLOW | O_NONBLOCK, 0600);
    if (logfd < 0) {
        int saved = errno; close(fan);
        fprintf(stderr, "{\"error\":\"PDG_INVALID_EVENT_LOG\",\"coverage\":\"unsupported\",\"errno\":%d}\n", saved);
        return 1;
    }
    struct stat log_stat;
    int log_error = 0;
    if (fstat(logfd, &log_stat) != 0) log_error = errno;
    else if (!S_ISREG(log_stat.st_mode) || log_stat.st_uid != geteuid()) log_error = EPERM;
    else if (fchmod(logfd, 0600) != 0) log_error = errno;
    if (log_error != 0) {
        close(logfd); close(fan);
        fprintf(stderr, "{\"error\":\"PDG_INVALID_EVENT_LOG\",\"coverage\":\"unsupported\",\"errno\":%d}\n", log_error);
        return 1;
    }
    signal(SIGINT, stop_signal); signal(SIGTERM, stop_signal);
    time_t started = time(NULL);
    alignas(struct fanotify_event_metadata) unsigned char buf[65536];
    char escaped_root[PATH_MAX * 6U];
    if (json_escape(root, escaped_root, sizeof(escaped_root)) != 0) {
        close(logfd); close(fan); return 1;
    }
    printf("{\"mode\":\"audit_only\",\"enforcement\":false,\"coverage\":\"audit_only\",\"root\":\"%s\"}\n", escaped_root);
    int audit_rc = 0;
    int failure_errno = 0;
    uint64_t event_sequence = 0;
    const char *failure_reason = "MONITOR_STOPPED";
    while (!stopping) {
        if (duration_sec > 0 && time(NULL) - started >= duration_sec) break;
        struct pollfd pfd = { .fd = fan, .events = POLLIN };
        int ready = poll(&pfd, 1, 500);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) { audit_rc = 1; failure_reason = "POLL_FAILED"; failure_errno = errno; break; }
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            audit_rc = 1; failure_reason = "FANOTIFY_GROUP_FAILED"; failure_errno = EIO; break;
        }
        if (!ready) continue;
        ssize_t n = read(fan, buf, sizeof(buf));
        if (n < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        if (n <= 0) {
            audit_rc = 1; failure_reason = "FANOTIFY_READ_FAILED";
            failure_errno = n < 0 ? errno : EPIPE;
            break;
        }
        for (size_t off = 0; off < (size_t)n;) {
            size_t remaining = (size_t)n - off;
            struct fanotify_event_metadata *meta = (struct fanotify_event_metadata *)(void *)(buf + off);
            if (!metadata_record_valid(meta, remaining)) {
                audit_rc = 1; failure_reason = "INVALID_FANOTIFY_METADATA";
                failure_errno = errno; stopping = 1; break;
            }
            if (meta->mask & FAN_Q_OVERFLOW) {
                char line[512];
                int len = snprintf(line, sizeof(line),
                    "{\"schema_version\":\"guard_decision.v1\",\"id\":\"pdg-%s-%" PRIu64 "\","
                    "\"policy_id\":\"%s\",\"policy_revision\":\"%s\","
                    "\"operation\":\"queue_overflow\",\"source_api\":\"fanotify\","
                    "\"decision\":\"unknown\",\"reason_code\":\"FANOTIFY_QUEUE_OVERFLOW\","
                    "\"enforced\":false,\"hook_verified\":true,\"coverage\":\"gap\","
                    "\"actor_attribution\":\"unknown\",\"pid_source\":\"unknown\",\"errno\":null}\n",
                    p->revision, ++event_sequence, p->revision, p->revision);
                int record_error = (len < 0 || (size_t)len >= sizeof(line)) ? EOVERFLOW :
                    (write_all(logfd, line, (size_t)len) != 0 ? errno : 0);
                if (record_error != 0) {
                    audit_rc = 1; failure_reason = "EVENT_LOG_WRITE_FAILED";
                    failure_errno = record_error;
                } else {
                    audit_rc = 1; failure_reason = "FANOTIFY_QUEUE_OVERFLOW"; failure_errno = ENOBUFS;
                }
                stopping = 1;
                break;
            }
            if (meta->fd >= 0) {
                char fdpath[64], resolved[PATH_MAX], escaped[PATH_MAX * 6U];
                snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", meta->fd);
                ssize_t size = readlink(fdpath, resolved, sizeof(resolved));
                if (size >= 0 && (size_t)size < sizeof(resolved)) {
                    resolved[size] = '\0';
                    if (!path_within(root, resolved)) {
                        close(meta->fd);
                        off += meta->event_len;
                        continue;
                    }
                    struct stat event_stat;
                    int metadata_error = 0;
                    errno = 0;
                    if (fstat(meta->fd, &event_stat) != 0) {
                        metadata_error = errno;
                        if (metadata_error == 0) metadata_error = EIO;
                    }
                    else {
                        errno = 0;
                        if (json_escape(resolved, escaped, sizeof(escaped)) != 0) {
                            metadata_error = errno;
                            if (metadata_error == 0) metadata_error = EIO;
                        }
                    }
                    if (metadata_error != 0) {
                        close(meta->fd);
                        audit_rc = 1; failure_reason = "EVENT_METADATA_UNAVAILABLE";
                        failure_errno = metadata_error;
                        stopping = 1; break;
                    }
                    char line[PATH_MAX * 6U + 1024U];
                    int len = snprintf(line, sizeof(line),
                        "{\"schema_version\":\"guard_decision.v1\",\"id\":\"pdg-%s-%" PRIu64 "\","
                        "\"policy_id\":\"%s\",\"policy_revision\":\"%s\","
                        "\"operation\":\"%s\",\"source_api\":\"fanotify\","
                        "\"decision\":\"unknown\",\"reason_code\":\"AUDIT_ONLY\",\"enforced\":false,\"hook_verified\":true,"
                        "\"scope_identity\":{\"path\":\"%s\",\"device_major\":%u,\"device_minor\":%u,\"inode\":%ju,\"file_identity_source\":\"fstat_event_fd\"},"
                        "\"actor_attribution\":\"%s\",\"pid_source\":\"%s\","
                        "\"pid\":%d,\"errno\":null,\"event_mask\":%llu,\"coverage\":\"audit_only\"}\n",
                        p->revision, ++event_sequence, p->revision, p->revision,
                        event_operation(meta->mask), escaped,
                        major(event_stat.st_dev), minor(event_stat.st_dev), (uintmax_t)event_stat.st_ino,
                        meta->pid > 0 ? "process_pid_observed" : "unknown",
                        meta->pid > 0 ? "fanotify_event_metadata.pid" : "unknown",
                        meta->pid, (unsigned long long)meta->mask);
                    int record_error = (len <= 0 || (size_t)len >= sizeof(line)) ? EOVERFLOW :
                        (write_all(logfd, line, (size_t)len) != 0 ? errno : 0);
                    if (record_error != 0) {
                        audit_rc = 1; failure_reason = "EVENT_LOG_WRITE_FAILED";
                        failure_errno = record_error;
                        stopping = 1;
                    }
                } else {
                    audit_rc = 1; failure_reason = "EVENT_PATH_UNAVAILABLE";
                    failure_errno = size < 0 ? errno : ENAMETOOLONG;
                    stopping = 1;
                }
                close(meta->fd);
            } else {
                audit_rc = 1; failure_reason = "EVENT_WITHOUT_FILE_DESCRIPTOR";
                failure_errno = EPROTO;
                stopping = 1;
            }
            off += meta->event_len;
            if (audit_rc != 0) break;
        }
    }
    if (audit_rc == 0) {
        char line[512];
        const char *reason = stopping ? "STOPPED_BY_SIGNAL" : "DURATION_COMPLETE";
        int len = snprintf(line, sizeof(line),
            "{\"schema_version\":\"guard_decision.v1\",\"id\":\"pdg-%s-%" PRIu64 "\","
            "\"policy_id\":\"%s\",\"policy_revision\":\"%s\","
            "\"operation\":\"monitor_stopped\",\"source_api\":\"fanotify\","
            "\"decision\":\"unknown\",\"reason_code\":\"%s\",\"enforced\":false,"
            "\"hook_verified\":true,\"coverage\":\"audit_only\","
            "\"actor_attribution\":\"unknown\",\"pid_source\":\"unknown\",\"errno\":null}\n",
            p->revision, ++event_sequence, p->revision, p->revision, reason);
        int record_error = (len <= 0 || (size_t)len >= sizeof(line)) ? EOVERFLOW :
            (write_all(logfd, line, (size_t)len) != 0 ? errno : 0);
        if (record_error != 0) {
            audit_rc = 1; failure_reason = "EVENT_LOG_WRITE_FAILED";
            failure_errno = record_error;
        }
    }
    close(logfd); close(fan);
    if (audit_rc != 0)
        fprintf(stderr, "{\"error\":\"PDG_MONITOR_DEGRADED\",\"coverage\":\"degraded\",\"reason_code\":\"%s\",\"errno\":%d,\"enforced\":false}\n", failure_reason, failure_errno);
    return audit_rc;
}

static int bpf_lsm_config_enabled(void) {
    struct utsname kernel;
    if (uname(&kernel) != 0) return -1;
    char config_path[PATH_MAX];
    int written = snprintf(config_path, sizeof(config_path), "/boot/config-%s", kernel.release);
    if (written < 0 || (size_t)written >= sizeof(config_path)) return -1;
    FILE *config = fopen(config_path, "r");
    if (!config) return -1;
    char line[256];
    int enabled = -1;
    while (fgets(line, sizeof(line), config)) {
        size_t length = strlen(line);
        while (length && (line[length - 1U] == '\n' || line[length - 1U] == '\r'))
            line[--length] = '\0';
        if (!strcmp(line, "CONFIG_BPF_LSM=y")) { enabled = 1; break; }
        if (!strcmp(line, "# CONFIG_BPF_LSM is not set")) { enabled = 0; break; }
    }
    fclose(config);
    return enabled;
}

static int executable_on_path(const char *name) {
    const char *path = getenv("PATH");
    if (!path || !*path || !name || !*name) return 0;
    const char *segment = path;
    while (true) {
        const char *separator = strchr(segment, ':');
        size_t directory_length = separator ? (size_t)(separator - segment) : strlen(segment);
        char candidate[PATH_MAX];
        int written;
        if (directory_length > sizeof(candidate) - strlen(name) - 2U) {
            if (!separator) break;
            segment = separator + 1;
            continue;
        }
        if (!directory_length)
            written = snprintf(candidate, sizeof(candidate), "%s", name);
        else
            written = snprintf(candidate, sizeof(candidate), "%.*s/%s",
                               (int)directory_length, segment, name);
        if (written >= 0 && (size_t)written < sizeof(candidate) && access(candidate, X_OK) == 0)
            return 1;
        if (!separator) break;
        segment = separator + 1;
    }
    return 0;
}

static int active_bpf_lsm(char *lsm, size_t capacity) {
    FILE *f = fopen("/sys/kernel/security/lsm", "r");
    if (!f) return 0;
    size_t count = fread(lsm, 1U, capacity - 1U, f);
    fclose(f);
    lsm[count] = '\0';
    char *save = NULL;
    for (char *name = strtok_r(lsm, ",\r\n", &save); name;
         name = strtok_r(NULL, ",\r\n", &save)) {
        if (!strcmp(name, "bpf")) return 1;
    }
    return 0;
}

static int cmd_doctor(void) {
    int fan = fanotify_init(FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_NONBLOCK,
                            O_RDONLY | O_CLOEXEC);
    bool available = fan >= 0;
    int fan_errno = available ? 0 : errno;
    if (fan >= 0) close(fan);
    char lsm[2048] = "";
    bool bpf_lsm = active_bpf_lsm(lsm, sizeof(lsm)) != 0;
    int bpf_config = bpf_lsm_config_enabled();
    bool btf_available = access("/sys/kernel/btf/vmlinux", R_OK) == 0;
    bool bpftool_available = executable_on_path("bpftool") != 0;
    bool preflight_ready = bpf_config == 1 && bpf_lsm && btf_available && bpftool_available;
    const char *config_status = bpf_config == 1 ? "enabled" :
                                bpf_config == 0 ? "disabled" : "unknown";
    printf("{\"fanotify_api_available\":%s,\"fanotify_api_errno\":%d,"
           "\"fanotify_mount_mark\":\"not_run_requires_disposable_privileged_vm\","
           "\"active_lsm_bpf\":%s,\"config_bpf_lsm\":\"%s\","
           "\"kernel_btf_available\":%s,\"bpftool_available\":%s,"
           "\"bpf_lsm_preflight\":\"%s\",\"bpf_hook_probe\":\"not_run_no_hook_selected\","
           "\"enforcement\":\"unsupported in this build\"}\n",
           available ? "true" : "false", fan_errno, bpf_lsm ? "true" : "false",
           config_status, btf_available ? "true" : "false",
           bpftool_available ? "true" : "false", preflight_ready ? "ready" : "incomplete");
    return available ? 0 : 3;
}

static void usage(void) {
    puts("dirguardctl doctor [--json]\n"
         "dirguardctl policy validate --file POLICY.yaml\n"
         "dirguardctl policy explain --file POLICY.yaml --path FILE --op OP\n"
         "dirguardctl status --policy POLICY.yaml\n"
         "dirguardctl audit --root DIR --policy POLICY.yaml --events FILE [--duration SEC]\n"
         "dirguardctl enforce --root DIR --policy POLICY.yaml --confirm-lab-scope\n"
         "dirguardctl disable --root DIR");
}

int main(int argc, char **argv) {
    if (argc < 2 || !strcmp(argv[1], "--help")) { usage(); return argc < 2 ? 2 : 0; }
    if (!strcmp(argv[1], "doctor")) return cmd_doctor();
    if (!strcmp(argv[1], "disable")) { puts("audit-only build has no persistent hooks to disable"); return 0; }
    if (!strcmp(argv[1], "enforce")) {
        fprintf(stderr, "{\"error\":\"PDG_UNSUPPORTED_ENFORCEMENT\",\"coverage\":\"unsupported\",\"enforced\":false}\n");
        return 3;
    }
    const char *policy_file = opt(argc, argv, "--policy", opt(argc, argv, "--file", NULL));
    if (!policy_file) { usage(); return 2; }
    struct policy policy;
    if (parse_policy(policy_file, &policy) != 0) {
        fprintf(stderr, "PDG_INVALID_POLICY: %s\n", strerror(errno)); return 2;
    }
    if (!strcmp(argv[1], "policy")) {
        if (argc < 3) { usage(); return 2; }
        if (!strcmp(argv[2], "validate")) { puts("{\"valid\":true,\"mode\":\"audit\"}"); return 0; }
        if (!strcmp(argv[2], "explain")) {
            const char *path = opt(argc, argv, "--path", NULL);
            const char *op = opt(argc, argv, "--op", NULL);
            if (!path || !op) { usage(); return 2; }
            return cmd_explain(&policy, path, op);
        }
    } else if (!strcmp(argv[1], "status")) {
        printf("{\"policy_revision\":\"%s\",\"mode\":\"audit\",\"enforced\":false,\"coverage\":\"audit_only\"}\n", policy.revision);
        return 0;
    } else if (!strcmp(argv[1], "audit")) {
        const char *root = opt(argc, argv, "--root", NULL);
        const char *events = opt(argc, argv, "--events", "./dirguard-events.ndjson");
        int duration = 0;
        if (!root || parse_duration(opt(argc, argv, "--duration", "0"), &duration) != 0) {
            fprintf(stderr, "PDG_INVALID_ARGUMENT: duration must be a non-negative integer\n");
            return 2;
        }
        return cmd_audit(&policy, root, events, duration);
    }
    usage(); return 2;
}
