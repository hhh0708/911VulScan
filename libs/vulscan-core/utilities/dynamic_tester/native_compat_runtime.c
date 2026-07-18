#include "vulscan_native_compat.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>

/* AFL buffers are defined once in vulscan_native_compat.c (linked separately). */

static size_t vulscan_read_all(int fd, char *buf, size_t cap) {
    size_t total = 0;
    while (total + 1 < cap) {
        ssize_t n = read(fd, buf + total, cap - 1 - total);
        if (n <= 0) {
            break;
        }
        total += (size_t)n;
    }
    buf[total] = '\0';
    return total;
}

static vulscan_child_capture vulscan_run_asan_child_impl(
    void (*fn_void)(void),
    void (*fn_ptr)(void *),
    void *arg
) {
    vulscan_child_capture out;
    int pipefd[2];
    int status = 0;

    memset(&out, 0, sizeof(out));
    if (pipe(pipefd) != 0) {
        return out;
    }

    pid_t pid = fork();
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        if (fn_ptr) {
            fn_ptr(arg);
        } else if (fn_void) {
            fn_void();
        }
        _exit(0);
    }

    close(pipefd[1]);
    waitpid(pid, &status, 0);
    out.len = vulscan_read_all(pipefd[0], out.buf, sizeof(out.buf));
    close(pipefd[0]);

    if (WIFEXITED(status)) {
        out.exit_code = WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        out.signaled = 1;
        out.signal_num = WTERMSIG(status);
    }
    return out;
}

vulscan_child_capture vulscan_run_asan_child_void(void (*fn)(void)) {
    return vulscan_run_asan_child_impl(fn, NULL, NULL);
}

vulscan_child_capture vulscan_run_asan_child_ptr(void (*fn)(void *), void *arg) {
    return vulscan_run_asan_child_impl(NULL, fn, arg);
}

int vulscan_has_sanitizer_evidence(const char *buf) {
    if (!buf || !*buf) {
        return 0;
    }
    if (strstr(buf, "AddressSanitizer")) {
        return 1;
    }
    if (strstr(buf, "runtime error:")) {
        return 1;
    }
    if (strstr(buf, "heap-buffer-overflow")) {
        return 1;
    }
    if (strstr(buf, "stack-buffer-overflow")) {
        return 1;
    }
    if (strstr(buf, "heap-use-after-free")) {
        return 1;
    }
    if (strstr(buf, "SUMMARY: AddressSanitizer")) {
        return 1;
    }
    return 0;
}

int vulscan_has_differential_leak(
    const char *baseline,
    const char *malicious,
    size_t field_limit
) {
    size_t base_len = baseline ? strlen(baseline) : 0;
    size_t evil_len = malicious ? strlen(malicious) : 0;

    if (evil_len > base_len + field_limit) {
        return 1;
    }
    if (baseline && malicious) {
        for (size_t i = 0; malicious[i] != '\0'; i++) {
            if (strchr(baseline, malicious[i]) == NULL && malicious[i] >= 0x20) {
                return 1;
            }
        }
    }
    return 0;
}

static void vulscan_put_json_string(const char *s) {
    fputc('"', stdout);
    if (!s) {
        fputc('"', stdout);
        return;
    }
    for (; *s; s++) {
        switch (*s) {
            case '"':  fputs("\\\"", stdout); break;
            case '\\': fputs("\\\\", stdout); break;
            case '\n': fputs("\\n", stdout); break;
            case '\r': fputs("\\r", stdout); break;
            case '\t': fputs("\\t", stdout); break;
            default:
                if ((unsigned char)*s >= 0x20) {
                    fputc(*s, stdout);
                }
                break;
        }
    }
    fputc('"', stdout);
}

void vulscan_emit_result_json(
    const char *status,
    const char *details,
    const char *evidence_content
) {
    const char *st = status ? status : "ERROR";
    fputs("{\"status\":", stdout);
    vulscan_put_json_string(st);
    fputs(",\"details\":", stdout);
    vulscan_put_json_string(details ? details : "");
    fputs(",\"evidence\":[{\"type\":\"command_output\",\"content\":", stdout);
    vulscan_put_json_string(evidence_content ? evidence_content : "");
    fputs("}]}\n", stdout);
}
