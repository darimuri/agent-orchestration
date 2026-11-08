/* Source-only terminal consumer. No daemon, store, grant or executor authority. */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/capability.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <systemd/sd-bus.h>

#define CLI_NAME "org.buzz.HostApproval1"
#define CLI_PATH "/org/buzz/HostApproval1"
#define CLI_INTERFACE "org.buzz.HostApproval1"
#define CLI_BROKER "org.freedesktop.DBus"
#define CLI_BROKER_PATH "/org/freedesktop/DBus"
#define CLI_ADDRESS "unix:path=/run/dbus/system_bus_socket"
#define CLI_AGENT "/usr/bin/pkttyagent"
#define CLI_SUMMARY 16384u
#define CLI_TOTAL_MS UINT64_C(60000)
#define CLI_CLEANUP_MS UINT64_C(2000)
#define CLI_READY_MS UINT64_C(10000)

/* Only the C fixture, which includes this translation unit, can replace these.
 * No exported test entry point, argv selector or getenv exists in production. */
#ifdef HOST_APPROVAL_CLI_TEST
struct cli_fixture {
    const char *address, *agent;
    uid_t broker_uid, service_uid;
    bool permit_agent_uid, reject_identity, reject_broker, reject_tty;
    bool pidfd_failure, cleanup_failure, parent_race;
    uint64_t work_ms, ready_ms;
};
static struct cli_fixture fixture;
#endif

struct cli {
    sd_bus *bus;
    sd_bus_slot *filter, *call;
    sd_bus_message *reply;
    bool invalid, pinned, delivered, child_created, child_dead, confirmed;
    int tty, signals, pidfd, notify, exec_status;
    pid_t child;
    uint64_t last, deadline, work_deadline;
    char service[256], unique[256], broker[33], receipt[33];
    struct stat terminal;
    struct termios saved_terminal;
};

static bool bounded(const char *s, size_t n) { return s && strnlen(s, n + 1u) <= n; }
static bool hex(const char *s, size_t n) {
    if (!bounded(s, n) || strlen(s) != n) return false;
    for (size_t i = 0; i < n; i++) if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return false;
    return true;
}
static bool phase(const char *s) {
    static const char *const phases[] = {"absent", "pending", "approved", "rejected", "expired", "reserved", "conflict", "capacity", "denied", "outcome_unknown"};
    if (!bounded(s, 32u)) return false;
    for (size_t i = 0; i < sizeof(phases) / sizeof(phases[0]); i++) if (!strcmp(s, phases[i])) return true;
    return false;
}
static bool unique_name(const char *s) { return bounded(s, 255u) && s[0] == ':' && sd_bus_service_name_is_valid(s) > 0; }
static int clock_ms(uint64_t *out) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) < 0 || t.tv_sec < 0 || (uint64_t)t.tv_sec > (UINT64_MAX - 1000u) / 1000u) return -1;
    *out = (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
    return 0;
}
static int remaining(struct cli *c, uint64_t deadline, uint64_t *out) {
    uint64_t now;
    if (clock_ms(&now) < 0 || now < c->last || now >= deadline) return -1;
    c->last = now; *out = deadline - now; return 0;
}
static bool identity_ok(void) {
    uid_t real, effective, saved; gid_t gr, ge, gs;
    struct __user_cap_header_struct header = { .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0 };
    struct __user_cap_data_struct caps[2] = {{0}, {0}};
    if (getresuid(&real, &effective, &saved) < 0 || getresgid(&gr, &ge, &gs) < 0 ||
        real == 0 || real != effective || real != saved || gr != ge || gr != gs || getauxval(AT_SECURE) ||
        syscall(SYS_capget, &header, caps) < 0) return false;
    for (unsigned i = 0; i < 2u; i++) if (caps[i].effective || caps[i].permitted || caps[i].inheritable) return false;
#ifdef HOST_APPROVAL_CLI_TEST
    if (fixture.reject_identity) return false;
    if (fixture.permit_agent_uid) return true;
#endif
    return real != 10001u;
}
static bool terminal_ok(struct cli *c) {
    struct stat input, output, error;
    unsigned int device;
#ifdef HOST_APPROVAL_CLI_TEST
    if (fixture.reject_tty) return false;
#endif
    return c->tty >= 0 && isatty(STDIN_FILENO) && isatty(STDOUT_FILENO) && isatty(STDERR_FILENO) &&
        ioctl(c->tty, TIOCGDEV, &device) == 0 && fstat(0, &input) == 0 && fstat(1, &output) == 0 && fstat(2, &error) == 0 &&
        S_ISCHR(input.st_mode) && S_ISCHR(output.st_mode) && S_ISCHR(error.st_mode) && input.st_uid == getuid() &&
        input.st_rdev == (dev_t)device && input.st_rdev == c->terminal.st_rdev && input.st_ino == c->terminal.st_ino && input.st_dev == c->terminal.st_dev &&
        output.st_rdev == input.st_rdev && error.st_rdev == input.st_rdev &&
        tcgetpgrp(c->tty) == getpgrp() && tcgetsid(c->tty) == getsid(0);
}
static bool child_alive(struct cli *c) {
    if (!c->child_created) return true;
    if (c->child_dead || c->pidfd < 0) return false;
    struct pollfd p = { .fd = c->pidfd, .events = POLLIN };
    if (poll(&p, 1u, 0) != 0) { c->child_dead = true; return false; }
    return true;
}
static int filter(sd_bus_message *m, void *userdata, sd_bus_error *error) {
    struct cli *c = userdata; (void)error;
    if (sd_bus_message_is_signal(m, "org.freedesktop.DBus.Local", "Disconnected") > 0) c->invalid = true;
    if (sd_bus_message_is_signal(m, CLI_BROKER, "NameOwnerChanged") > 0 && c->pinned) {
        const char *sender = sd_bus_message_get_sender(m), *name, *old, *current;
        if (sender && !strcmp(sender, CLI_BROKER) && sd_bus_message_has_signature(m, "sss") > 0 &&
            sd_bus_message_read(m, "sss", &name, &old, &current) > 0 &&
            (!strcmp(name, CLI_NAME) || !strcmp(name, c->service))) c->invalid = true;
    }
    return 0;
}
static int replied(sd_bus_message *m, void *userdata, sd_bus_error *error) {
    struct cli *c = userdata; (void)error;
    if (c->reply) c->invalid = true;
    else c->reply = sd_bus_message_ref(m);
    return 1;
}
/* Every asynchronous stage services broker continuity, foreground TTY, signals,
 * child lifetime and the ORIGINAL monotonic budget. Never reads terminal input. */
static int step(struct cli *c, uint64_t deadline, int extra, short events) {
    uint64_t left, bus_timeout = UINT64_MAX;
    if (remaining(c, deadline, &left) < 0 || c->invalid || !terminal_ok(c) || !child_alive(c)) return -1;
    struct signalfd_siginfo signal_info;
    if (read(c->signals, &signal_info, sizeof(signal_info)) != -1 || errno != EAGAIN) return -1;
    for (unsigned i = 0; i < 32u; i++) {
        int r = sd_bus_process(c->bus, NULL);
        if (r < 0 || c->invalid) return -1;
        if (!r) break;
    }
    if (sd_bus_is_open(c->bus) <= 0 || c->invalid || !child_alive(c) || remaining(c, deadline, &left) < 0) return -1;
    if (c->reply) return 0;
    int bus_events = sd_bus_get_events(c->bus), fd = sd_bus_get_fd(c->bus);
    if (bus_events < 0 || fd < 0 || sd_bus_get_timeout(c->bus, &bus_timeout) < 0) return -1;
    uint64_t wait = left < 50u ? left : 50u;
    if (bus_timeout != UINT64_MAX) {
        uint64_t now_us = c->last * 1000u;
        uint64_t bus_wait = bus_timeout <= now_us ? 0u : (bus_timeout - now_us + 999u) / 1000u;
        if (bus_wait < wait) wait = bus_wait;
    }
    struct pollfd p[] = {{ .fd = fd, .events = (short)bus_events }, { .fd = c->signals, .events = POLLIN },
        { .fd = c->pidfd, .events = POLLIN }, { .fd = extra, .events = events }};
    int r = poll(p, sizeof(p) / sizeof(p[0]), (int)wait);
    if (r < 0 || p[1].revents || p[2].revents) return -1;
    return 0;
}
static void drop_reply(struct cli *c) {
    c->call = sd_bus_slot_unref(c->call); c->reply = sd_bus_message_unref(c->reply);
}
static int invoke(struct cli *c, const char *destination, const char *path, const char *interface,
                  const char *member, const char *first, const char *second, bool decide) {
    sd_bus_message *m = NULL; uint64_t left;
    drop_reply(c);
    if (step(c, c->work_deadline, -1, 0) < 0 || remaining(c, c->work_deadline, &left) < 0) return -1;
    int r = sd_bus_message_new_method_call(c->bus, &m, destination, path, interface, member);
    if (r >= 0) r = sd_bus_message_set_auto_start(m, 0);
    if (r >= 0) r = sd_bus_message_set_allow_interactive_authorization(m, 0);
    if (r >= 0 && first) r = second ? sd_bus_message_append(m, "ss", first, second) : sd_bus_message_append(m, "s", first);
    if (r >= 0) {
        /* Conservatively crosses the possible-delivery boundary BEFORE send. */
        if (decide) c->delivered = true;
        r = sd_bus_call_async(c->bus, &c->call, m, replied, c, left * 1000u);
    }
    sd_bus_message_unref(m);
    if (r < 0) return -1;
    while (!c->reply) if (step(c, c->work_deadline, -1, 0) < 0) return -1;
    return step(c, c->work_deadline, -1, 0);
}
static bool response(struct cli *c, const char *sender, const char *signature) {
    const char *actual = c->reply ? sd_bus_message_get_sender(c->reply) : NULL;
    return !c->invalid && actual && !strcmp(actual, sender) && sd_bus_message_is_method_error(c->reply, NULL) == 0 &&
        sd_bus_message_has_signature(c->reply, signature) > 0;
}
static int broker_call(struct cli *c, const char *method, const char *arg) {
    return invoke(c, CLI_BROKER, CLI_BROKER_PATH, CLI_BROKER, method, arg, NULL, false);
}
static int connect_broker(struct cli *c) {
    const char *address = CLI_ADDRESS;
    uid_t broker_uid = 0, service_uid = 0;
#ifdef HOST_APPROVAL_CLI_TEST
    address = fixture.address; broker_uid = fixture.broker_uid; service_uid = fixture.service_uid;
#endif
    int r = sd_bus_new(&c->bus);
    if (r >= 0) r = sd_bus_set_address(c->bus, address);
    if (r >= 0) r = sd_bus_set_bus_client(c->bus, 1);
    if (r >= 0) r = sd_bus_negotiate_fds(c->bus, 0);
    if (r >= 0) r = sd_bus_start(c->bus);
    if (r < 0) return -1;
    while (sd_bus_is_ready(c->bus) <= 0) if (step(c, c->work_deadline, -1, 0) < 0) return -1;
    /* Kernel peer credentials authenticate the fixed local broker; no proc UID
     * augmentation, session-bus environment or caller-supplied trust flag. */
    struct ucred peer; socklen_t length = sizeof(peer);
    if (getsockopt(sd_bus_get_fd(c->bus), SOL_SOCKET, SO_PEERCRED, &peer, &length) < 0 || length != sizeof(peer) || peer.uid != broker_uid) return -1;
#ifdef HOST_APPROVAL_CLI_TEST
    if (fixture.reject_broker) return -1;
#endif
    const char *unique;
    if (sd_bus_get_unique_name(c->bus, &unique) < 0 || !unique_name(unique)) return -1;
    memcpy(c->unique, unique, strlen(unique) + 1u);
    if (sd_bus_add_filter(c->bus, &c->filter, filter, c) < 0 ||
        broker_call(c, "AddMatch", "type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',member='NameOwnerChanged',path='/org/freedesktop/DBus'") < 0 || !response(c, CLI_BROKER, "")) return -1;
    if (broker_call(c, "GetId", NULL) < 0 || !response(c, CLI_BROKER, "s")) return -1;
    const char *id;
    if (sd_bus_message_read(c->reply, "s", &id) <= 0 || !hex(id, 32u) || sd_bus_message_at_end(c->reply, 1) <= 0) return -1;
    memcpy(c->broker, id, sizeof(c->broker));
    if (broker_call(c, "GetNameOwner", CLI_NAME) < 0 || !response(c, CLI_BROKER, "s")) return -1;
    const char *owner;
    if (sd_bus_message_read(c->reply, "s", &owner) <= 0 || !unique_name(owner) || sd_bus_message_at_end(c->reply, 1) <= 0) return -1;
    memcpy(c->service, owner, strlen(owner) + 1u); c->pinned = true;
    if (broker_call(c, "GetConnectionUnixUser", c->service) < 0 || !response(c, CLI_BROKER, "u")) return -1;
    uint32_t uid;
    if (sd_bus_message_read(c->reply, "u", &uid) <= 0 || uid != service_uid || sd_bus_message_at_end(c->reply, 1) <= 0) return -1;
    drop_reply(c);
    return 0;
}
static int continuity(struct cli *c) {
    /* A retained socket cannot migrate brokers. Verify ID and current well-known
     * owner again at the send boundary as well as watching all ownership changes. */
    if (broker_call(c, "GetId", NULL) < 0 || !response(c, CLI_BROKER, "s")) return -1;
    const char *id, *owner;
    if (sd_bus_message_read(c->reply, "s", &id) <= 0 || strcmp(id, c->broker) || sd_bus_message_at_end(c->reply, 1) <= 0) return -1;
    if (broker_call(c, "GetNameOwner", CLI_NAME) < 0 || !response(c, CLI_BROKER, "s")) return -1;
    if (sd_bus_message_read(c->reply, "s", &owner) <= 0 || strcmp(owner, c->service) || sd_bus_message_at_end(c->reply, 1) <= 0) return -1;
    drop_reply(c); return step(c, c->work_deadline, -1, 0);
}
static int output(struct cli *c, const char *bytes, size_t length, bool monitored) {
    size_t offset = 0;
    while (offset < length) {
        uint64_t left;
        if (remaining(c, c->deadline, &left) < 0 || !terminal_ok(c)) return -1;
        if (monitored && step(c, c->work_deadline, c->tty, POLLOUT) < 0) return -1;
        ssize_t n = write(c->tty, bytes + offset, length - offset);
        if (n > 0) offset += (size_t)n;
        else if (n < 0 && errno == EAGAIN) {
            struct pollfd p = { .fd = c->tty, .events = POLLOUT };
            if (poll(&p, 1u, (int)(left < 10u ? left : 10u)) < 0) return -1;
        } else return -1;
    }
    return 0;
}
static int display(struct cli *c, const char *id, const char *decision, const char *state, const char *digest, const char *summary) {
    char text[CLI_SUMMARY * 4u + 1024u];
    int n = snprintf(text, sizeof(text), "Request: %s\nDecision requested: %s\nObserved phase: %s\nIntent digest: %s\nRoot-provided summary (entire, escaped bytes):\n", id, decision, state, digest);
    if (n < 0 || (size_t)n >= sizeof(text)) return -1;
    size_t used = (size_t)n;
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; summary[i]; i++) {
        unsigned char b = (unsigned char)summary[i];
        if (used + 4u >= sizeof(text)) return -1;
        if (b >= 0x20u && b <= 0x7eu && b != '\\') text[used++] = (char)b;
        else { text[used++] = '\\'; text[used++] = 'x'; text[used++] = digits[b >> 4]; text[used++] = digits[b & 15u]; }
    }
    static const char note[] = "\nObservation only. This client does not create jobs, execute work or authorize Ready.\n";
    if (used + sizeof(note) > sizeof(text)) return -1;
    memcpy(text + used, note, sizeof(note) - 1u); used += sizeof(note) - 1u;
    /* Unbuffered bounded writes complete before any authentication child exists. */
    return output(c, text, used, true);
}
static void close_fd(int *fd) { if (*fd >= 0) { (void)close(*fd); *fd = -1; } }
_Noreturn static void child_exec(struct cli *c, int notify_write, int error_write, int gate_read, pid_t parent, const char *agent) {
    /* No parent-owned fd (including bus, journal or credential handles) survives.
     * Duplicate above the fixed layout before rearranging overlapping numbers. */
    /* A separate blocking TTY description lets the OS agent read normally
     * without changing the parent's nonblocking output description. */
    int tty = open("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC), notify = fcntl(notify_write, F_DUPFD_CLOEXEC, 10);
    int status = fcntl(error_write, F_DUPFD_CLOEXEC, 10), gate = fcntl(gate_read, F_DUPFD_CLOEXEC, 10);
    if (tty < 0 || notify < 0 || status < 0 || gate < 0 || prctl(PR_SET_PDEATHSIG, SIGKILL) < 0 || getppid() != parent) _exit(125);
    if (dup2(tty, 0) < 0 || dup2(tty, 1) < 0 || dup2(tty, 2) < 0 || dup2(notify, 3) < 0 || dup3(status, 4, O_CLOEXEC) < 0 || dup3(gate, 5, O_CLOEXEC) < 0 ||
        syscall(SYS_close_range, 6u, UINT_MAX, 0u) < 0) _exit(125);
    char release;
    if (read(5, &release, 1u) != 1 || release != 'G' || getppid() != parent) _exit(125);
    (void)close(5);
    struct sigaction action = { .sa_handler = SIG_DFL };
    if (sigemptyset(&action.sa_mask) < 0) _exit(125);
    const int reset[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGTSTP, SIGTTIN, SIGTTOU, SIGPIPE};
    for (size_t i = 0; i < sizeof(reset) / sizeof(reset[0]); i++) if (sigaction(reset[i], &action, NULL) < 0) _exit(125);
    sigset_t empty;
    if (sigemptyset(&empty) < 0 || sigprocmask(SIG_SETMASK, &empty, NULL) < 0) _exit(125);
    char *const args[] = {(char *)agent, "--system-bus-name", c->unique, "--notify-fd", "3", NULL};
    char *const environment[] = {"LANG=C", "LC_ALL=C", "TZ=UTC", "TERM=dumb", "GIO_USE_VFS=local", NULL};
    execve(agent, args, environment);
    /* EOF alone is NEVER exec success: also require a live pidfd-owned child. */
    const char failed = 'E'; (void)write(4, &failed, 1u); _exit(126);
}
static int spawn_agent(struct cli *c) {
    int notify[2] = {-1, -1}, status[2] = {-1, -1}, gate[2] = {-1, -1};
    const char *agent = CLI_AGENT;
#ifdef HOST_APPROVAL_CLI_TEST
    agent = fixture.agent;
#endif
    struct stat st;
    if (stat(agent, &st) < 0 || !S_ISREG(st.st_mode) || (st.st_mode & 06022) || !(st.st_mode & 0111)) return -1;
#ifndef HOST_APPROVAL_CLI_TEST
    if (st.st_uid != 0) return -1;
#endif
    if (pipe2(notify, O_CLOEXEC | O_NONBLOCK) < 0 || pipe2(status, O_CLOEXEC | O_NONBLOCK) < 0 || pipe2(gate, O_CLOEXEC) < 0) goto failed;
    pid_t parent = getpid();
    c->child = fork();
    if (c->child < 0) goto failed;
    if (!c->child) child_exec(c, notify[1], status[1], gate[0], parent, agent);
    c->child_created = true;
    close_fd(&notify[1]); close_fd(&status[1]); close_fd(&gate[0]);
    long fd = syscall(SYS_pidfd_open, c->child, 0u);
    if (fd >= 0 && fd <= INT_MAX) c->pidfd = (int)fd;
#ifdef HOST_APPROVAL_CLI_TEST
    if (fixture.parent_race) _exit(99);
    if (fixture.pidfd_failure) close_fd(&c->pidfd);
#endif
    if (c->pidfd < 0 || write(gate[1], "G", 1u) != 1) goto failed;
    close_fd(&gate[1]); c->notify = notify[0]; c->exec_status = status[0]; return 0;
failed:
    for (unsigned i = 0; i < 2u; i++) { close_fd(&notify[i]); close_fd(&status[i]); close_fd(&gate[i]); }
    return -1;
}
static int ready(struct cli *c) {
    uint64_t left, limit;
    if (remaining(c, c->work_deadline, &left) < 0) return -1;
    uint64_t budget = CLI_READY_MS;
#ifdef HOST_APPROVAL_CLI_TEST
    if (fixture.ready_ms) budget = fixture.ready_ms;
#endif
    limit = c->last + (left < budget ? left : budget);
    bool exec_ok = false, notify_eof = false;
    drop_reply(c);
    while (!exec_ok || !notify_eof) {
        if (step(c, limit, exec_ok ? c->notify : c->exec_status, POLLIN) < 0) return -1;
        char byte;
        if (!exec_ok) {
            ssize_t n = read(c->exec_status, &byte, 1u);
            if (n == 0) exec_ok = true;
            else if (n > 0 || errno != EAGAIN) return -1;
        }
        if (!notify_eof) {
            ssize_t n = read(c->notify, &byte, 1u);
            if (n == 0) notify_eof = true;
            else if (n > 0 || errno != EAGAIN) return -1;
        }
    }
    close_fd(&c->notify); close_fd(&c->exec_status);
    return child_alive(c) ? step(c, limit, -1, 0) : -1;
}
static bool reap(struct cli *c) {
    int status;
    pid_t result = waitpid(c->child, &status, WNOHANG);
    if (result == c->child) { c->child_created = false; return true; }
    return false;
}
static int owned_signal(struct cli *c, int signal) {
    if (c->pidfd >= 0) return (int)syscall(SYS_pidfd_send_signal, c->pidfd, signal, NULL, 0u);
    /* Only the never-reaped fork child, still behind our closed exec gate. Its
     * PID cannot be recycled until waitpid succeeds. No numeric PID adoption. */
    return kill(c->child, signal);
}
static bool cleanup(struct cli *c) {
    drop_reply(c); c->filter = sd_bus_slot_unref(c->filter); c->bus = sd_bus_close_unref(c->bus);
    close_fd(&c->notify); close_fd(&c->exec_status);
    bool ok = true;
    if (c->child_created) {
        if (!reap(c)) {
            (void)owned_signal(c, SIGTERM);
            uint64_t now = 0;
            if (clock_ms(&now) < 0) now = c->deadline;
            uint64_t term_end = now + 1000u;
            for (unsigned i = 0; i < 100u && c->child_created; i++) {
                if (reap(c)) break;
                if (clock_ms(&now) < 0 || now >= term_end || now >= c->deadline) break;
                struct pollfd p = { .fd = c->pidfd, .events = POLLIN }; (void)poll(&p, 1u, 10);
            }
            if (c->child_created) (void)owned_signal(c, SIGKILL);
            for (unsigned i = 0; i < 100u && c->child_created; i++) {
                if (reap(c)) break;
                if (clock_ms(&now) < 0 || now >= c->deadline) break;
                struct pollfd p = { .fd = c->pidfd, .events = POLLIN }; (void)poll(&p, 1u, 10);
            }
        }
        ok = !c->child_created;
        /* Never enable echo while an agent can still be reading a password. */
        if (ok && terminal_ok(c) && (tcflush(c->tty, TCIFLUSH) < 0 || tcsetattr(c->tty, TCSANOW, &c->saved_terminal) < 0)) ok = false;
    }
    close_fd(&c->pidfd);
#ifdef HOST_APPROVAL_CLI_TEST
    if (fixture.cleanup_failure) ok = false;
#endif
    return ok;
}
static int run_client(int argc, char **argv) {
    struct cli c = { .tty = -1, .signals = -1, .pidfd = -1, .notify = -1, .exec_status = -1 };
    int result = 1; bool cleaned;
    if (argc != 3 || (strcmp(argv[1], "approve") && strcmp(argv[1], "reject")) || !hex(argv[2], 32u) || !identity_ok()) return 1;
    if (clock_ms(&c.last) < 0 || c.last > UINT64_MAX - CLI_TOTAL_MS) return 1;
    c.deadline = c.last + CLI_TOTAL_MS; c.work_deadline = c.deadline - CLI_CLEANUP_MS;
#ifdef HOST_APPROVAL_CLI_TEST
    if (fixture.work_ms) c.work_deadline = c.last + fixture.work_ms;
#endif
    sigset_t signals, previous;
    if (sigemptyset(&signals) < 0) return 1;
    const int blocked[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGTSTP, SIGTTIN, SIGTTOU, SIGPIPE};
    for (size_t i = 0; i < sizeof(blocked) / sizeof(blocked[0]); i++) if (sigaddset(&signals, blocked[i]) < 0) return 1;
    if (sigprocmask(SIG_BLOCK, &signals, &previous) < 0) return 1;
    /* SIG_IGN/SA_NOCLDWAIT inherited from a launcher must not auto-reap our
     * child and permit PID reuse before the gated pidfd-failure cleanup. */
    struct sigaction child_action = { .sa_handler = SIG_DFL };
    if (sigemptyset(&child_action.sa_mask) < 0 || sigaction(SIGCHLD, &child_action, NULL) < 0) return 1;
    c.signals = signalfd(-1, &signals, SFD_CLOEXEC | SFD_NONBLOCK);
    c.tty = open("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC | O_NONBLOCK);
    if (c.signals < 0 || c.tty < 0 || fstat(0, &c.terminal) < 0 || !terminal_ok(&c) || tcgetattr(c.tty, &c.saved_terminal) < 0 || connect_broker(&c) < 0) goto done;
    if (invoke(&c, c.service, CLI_PATH, CLI_INTERFACE, "Inspect", argv[2], NULL, false) < 0 || !response(&c, c.service, "sss")) goto done;
    const char *state, *digest, *summary;
    if (sd_bus_message_read(c.reply, "sss", &digest, &summary, &state) <= 0 || sd_bus_message_at_end(c.reply, 1) <= 0 ||
        !phase(state) || (!hex(digest, 64u) && strcmp(digest, "")) || !bounded(summary, CLI_SUMMARY) ||
        (!strcmp(state, "pending") && (!digest[0] || !summary[0]))) goto done;
    bool pending = !strcmp(state, "pending");
    if (display(&c, argv[2], argv[1], state, digest, summary) < 0) goto done;
    drop_reply(&c);
    if (!pending) {
        static const char observation[] = "Historical/non-pending observation: no authentication or Decide. Inspect/reconcile explicitly.\n";
        (void)output(&c, observation, sizeof(observation) - 1u, true); goto done;
    }
    if (continuity(&c) < 0 || spawn_agent(&c) < 0 || ready(&c) < 0 || continuity(&c) < 0) goto done;
    if (invoke(&c, c.service, CLI_PATH, CLI_INTERFACE, "Decide", argv[2], argv[1], true) < 0 || !response(&c, c.service, "ss")) goto done;
    const char *receipt;
    if (sd_bus_message_read(c.reply, "ss", &state, &receipt) <= 0 || sd_bus_message_at_end(c.reply, 1) <= 0 || !phase(state) ||
        (!hex(receipt, 32u) && strcmp(receipt, ""))) goto done;
    if ((!strcmp(state, "approved") || !strcmp(state, "rejected")) && !hex(receipt, 32u)) goto done;
    if (!strcmp(state, "outcome_unknown")) goto done;
    /* A well-formed, authenticated nonmatching server result is definite denial. */
    result = 1; c.delivered = false;
    if ((!strcmp(argv[1], "approve") && !strcmp(state, "approved")) || (!strcmp(argv[1], "reject") && !strcmp(state, "rejected"))) {
        memcpy(c.receipt, receipt, sizeof(c.receipt)); c.confirmed = true; result = 0;
        char text[128]; int n = snprintf(text, sizeof(text), "server_confirmed %s receipt %s\n", state, c.receipt);
        if (n < 0 || (size_t)n >= sizeof(text) || output(&c, text, (size_t)n, false) < 0) result = 2;
    }
done:
    cleaned = cleanup(&c);
    if (!cleaned || c.delivered) result = 2;
    if (result == 2 && c.tty >= 0) {
        static const char unknown[] = "outcome_unknown: possible decision delivery or unresolved cleanup; do not retry automatically. Inspect/reconcile the same request ID.\n";
        (void)output(&c, unknown, sizeof(unknown) - 1u, false);
    } else if (result == 1 && c.tty >= 0) {
        static const char denied[] = "No new matching confirmed decision. Inspect/reconcile explicitly.\n";
        (void)output(&c, denied, sizeof(denied) - 1u, false);
    }
    close_fd(&c.tty); close_fd(&c.signals);
    /* This is a one-shot executable; leave cancellation signals blocked until
     * process exit rather than deliver a pending signal after reporting a code. */
    (void)previous;
    return result;
}
#ifndef HOST_APPROVAL_CLI_TEST
int main(int argc, char **argv) {
    /* libsystemd/glib helpers cannot consume inherited transport/loader knobs.
     * The already-running dynamic loader is part of the separate host inventory. */
    if (clearenv() < 0 || setenv("LANG", "C", 1) < 0 || setenv("LC_ALL", "C", 1) < 0) return 1;
    return run_client(argc, argv);
}
#endif
