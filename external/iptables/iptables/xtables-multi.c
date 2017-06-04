#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "xshared.h"

#include "xtables-multi.h"

#ifdef ENABLE_IPV4
#include "iptables-multi.h"
#endif

#ifdef ENABLE_IPV6
#include "ip6tables-multi.h"
#endif

#include <pthread.h>
#include <fcntl.h>
#include <errno.h>

#define LOG_TAG "iptables"
#include <cutils/log.h>

#define WATCHDOG_TIMEOUT 30

static size_t read_fully(int fd, char* data, size_t size) {
    size_t remaining = size;
    while (remaining > 0) {
        ssize_t n = TEMP_FAILURE_RETRY(read(fd, data, remaining));
        if (n <= 0) {
            return size - remaining;
        }
        data += n;
        remaining -= n;
    }
    return size;
}

static void log_stack() {
    char *stack_path = NULL;
    int fd = -1;
    size_t read_len = 0;
    char read_buf[1024] = {0};
    pid_t pid = getpid();

    ALOGD("backtrace: pid=%d", pid);
    if (asprintf(&stack_path, "/proc/self/task/%d/stack", pid) < 0) {
        return;
    }
    fd = TEMP_FAILURE_RETRY(open(stack_path, O_RDONLY));
    if (stack_path) {
        free(stack_path);
    }
    if (fd < 0) {
        return;
    }
    read_len = read_fully(fd, read_buf, sizeof(read_buf) - 1);
    if (read_len > 0 && read_len < sizeof(read_buf)) {
        read_buf[read_len] = '\0';
        ALOGD("%s", read_buf);
    }
    close(fd);
}

static void *ipt_watchdog_thread(void *arg) {
    sleep(WATCHDOG_TIMEOUT);
    log_stack();
    exit(EXIT_FAILURE);
}

static const struct subcommand multi_subcommands[] = {
#ifdef ENABLE_IPV4
	{"iptables",            iptables_main},
	{"main4",               iptables_main},
	{"iptables-save",       iptables_save_main},
	{"save4",               iptables_save_main},
	{"iptables-restore",    iptables_restore_main},
	{"restore4",            iptables_restore_main},
#endif
	{"iptables-xml",        iptables_xml_main},
	{"xml",                 iptables_xml_main},
#ifdef ENABLE_IPV6
	{"ip6tables",           ip6tables_main},
	{"main6",               ip6tables_main},
	{"ip6tables-save",      ip6tables_save_main},
	{"save6",               ip6tables_save_main},
	{"ip6tables-restore",   ip6tables_restore_main},
	{"restore6",            ip6tables_restore_main},
#endif
	{NULL},
};

int main(int argc, char **argv)
{
	pthread_t thread;
	pthread_create(&thread, NULL, ipt_watchdog_thread, NULL);
	pthread_detach(thread);
	return subcmd_main(argc, argv, multi_subcommands);
}
