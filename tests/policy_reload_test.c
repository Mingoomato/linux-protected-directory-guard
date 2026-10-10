#define main dirguardctl_program_main
#include "../src/dirguardctl.c"
#undef main

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "check failed at line %d: %s (errno=%d)\n", \
                __LINE__, #condition, errno); \
        return 1; \
    } \
} while (0)

static int write_policy_fixture(const char *path, const char *root,
                                const char *revision, const char *default_action,
                                int include_rule) {
    char text[MAX_LINE * 4U];
    int length = snprintf(text, sizeof(text),
        "schema_version: policy.v1\n"
        "policy_revision: %s\n"
        "mode: audit\n"
        "default_action: %s\n"
        "protected_roots:\n"
        "  - %s\n"
        "%s",
        revision, default_action, root,
        include_rule ?
            "rules:\n"
            "  - id: deny-writes\n"
            "    scope: ROOT_PLACEHOLDER\n"
            "    operation: open_for_write\n"
            "    action: deny\n"
            "    subject: any\n" : "");
    if (length < 0 || (size_t)length >= sizeof(text)) { errno = EOVERFLOW; return -1; }
    if (include_rule) {
        const char placeholder[] = "ROOT_PLACEHOLDER";
        char *at = strstr(text, placeholder);
        if (!at || strlen(root) >= sizeof(text) - (size_t)(at - text)) { errno = EOVERFLOW; return -1; }
        size_t remaining = strlen(at + sizeof(placeholder) - 1U);
        memmove(at + strlen(root), at + sizeof(placeholder) - 1U, remaining + 1U);
        memcpy(at, root, strlen(root));
        length = (int)strlen(text);
    }
    int fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    int rc = write_all(fd, text, (size_t)length);
    int saved = errno;
    if (close(fd) != 0 && rc == 0) { rc = -1; saved = errno; }
    if (rc != 0) errno = saved;
    return rc;
}

int main(void) {
    char directory_template[] = "/tmp/pdg-reload-test-XXXXXX";
    char *directory = mkdtemp(directory_template);
    CHECK(directory != NULL);
    char root_one[PATH_MAX], root_two[PATH_MAX], policy_path[PATH_MAX];
    CHECK(snprintf(root_one, sizeof(root_one), "%s/root-one", directory) > 0);
    CHECK(snprintf(root_two, sizeof(root_two), "%s/root-two", directory) > 0);
    CHECK(snprintf(policy_path, sizeof(policy_path), "%s/policy.yaml", directory) > 0);
    CHECK(mkdir(root_one, 0700) == 0);
    CHECK(mkdir(root_two, 0700) == 0);
    int fd = open(policy_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    CHECK(fd >= 0);
    CHECK(close(fd) == 0);

    struct policy active;
    CHECK(write_policy_fixture(policy_path, root_one, "revision-one", "allow", 1) == 0);
    CHECK(parse_policy(policy_path, &active) == 0);
    CHECK(!strcmp(active.revision, "revision-one"));

    CHECK(write_policy_fixture(policy_path, root_one, "revision-two", "deny", 1) == 0);
    CHECK(reload_policy(&active, policy_path) == 0);
    CHECK(!strcmp(active.revision, "revision-two"));
    char action[16], rule_id[128];
    CHECK(evaluate(&active, root_one, "open_for_read", action, rule_id) == 0);
    CHECK(!strcmp(action, "deny"));

    CHECK(write_policy_fixture(policy_path, root_one, "broken-revision", "allow", 0) == 0);
    CHECK(reload_policy(&active, policy_path) != 0);
    CHECK(!strcmp(active.revision, "revision-two"));
    CHECK(evaluate(&active, root_one, "open_for_read", action, rule_id) == 0);
    CHECK(!strcmp(action, "deny"));

    CHECK(write_policy_fixture(policy_path, root_two, "moved-root", "allow", 1) == 0);
    CHECK(reload_policy(&active, policy_path) != 0);
    CHECK(errno == EPERM);
    CHECK(!strcmp(active.revision, "revision-two"));
    CHECK(evaluate(&active, root_one, "open_for_read", action, rule_id) == 0);
    CHECK(!strcmp(action, "deny"));

    CHECK(write_policy_fixture(policy_path, root_one, "revision-two", "allow", 1) == 0);
    CHECK(reload_policy(&active, policy_path) != 0);
    CHECK(errno == EALREADY);
    CHECK(!strcmp(active.revision, "revision-two"));
    CHECK(evaluate(&active, root_one, "open_for_read", action, rule_id) == 0);
    CHECK(!strcmp(action, "deny"));

    CHECK(unlink(policy_path) == 0);
    CHECK(rmdir(root_one) == 0);
    CHECK(rmdir(root_two) == 0);
    CHECK(rmdir(directory) == 0);
    puts("PDG policy reload transaction: PASS");
    return 0;
}
