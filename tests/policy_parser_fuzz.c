#define main dirguardctl_program_main
#include "../src/dirguardctl.c"
#undef main

static char fuzz_root[PATH_MAX];
static char fuzz_policy_path[PATH_MAX];
static unsigned char expanded_policy[MAX_POLICY_BYTES + 1U];

static void fuzz_cleanup(void) {
    if (fuzz_policy_path[0]) (void)unlink(fuzz_policy_path);
    if (fuzz_root[0]) (void)rmdir(fuzz_root);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    char root_template[] = "/tmp/pdg-fuzz-root-XXXXXX";
    char policy_template[] = "/tmp/pdg-fuzz-policy-XXXXXX";
    char *root = mkdtemp(root_template);
    if (!root || copy_value(fuzz_root, sizeof(fuzz_root), root) != 0) return -1;
    int fd = mkstemp(policy_template);
    if (fd < 0 || close(fd) != 0 ||
        copy_value(fuzz_policy_path, sizeof(fuzz_policy_path), policy_template) != 0) {
        if (fd >= 0) (void)unlink(policy_template);
        (void)rmdir(fuzz_root);
        return -1;
    }
    if (atexit(fuzz_cleanup) != 0) {
        fuzz_cleanup();
        return -1;
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static const unsigned char token[] = "@ROOT@";
    const size_t token_length = sizeof(token) - 1U;
    const size_t root_length = strlen(fuzz_root);
    if (size > MAX_POLICY_BYTES + 1U) return 0;

    size_t in = 0;
    size_t out = 0;
    while (in < size && out < sizeof(expanded_policy)) {
        if (size - in >= token_length &&
            memcmp(data + in, token, token_length) == 0) {
            if (root_length > sizeof(expanded_policy) - out) break;
            memcpy(expanded_policy + out, fuzz_root, root_length);
            out += root_length;
            in += token_length;
        } else {
            expanded_policy[out++] = data[in++];
        }
    }

    int fd = open(fuzz_policy_path, O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return 0;
    int write_error = write_all(fd, (const char *)expanded_policy, out);
    int close_error = close(fd);
    if (write_error != 0 || close_error != 0) return 0;

    struct policy candidate;
    (void)parse_policy(fuzz_policy_path, &candidate);
    return 0;
}
