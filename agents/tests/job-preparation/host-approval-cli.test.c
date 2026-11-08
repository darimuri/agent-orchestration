/* Synthetic disposable-broker/PTY tests of the ACTUAL client translation unit.
 * No root service, Polkit, durable receipt, real password or host acceptance. */
#define HOST_APPROVAL_CLI_TEST
#include "../../job-preparation/native/host-approval.c"
#include <assert.h>
#include <sys/mman.h>

extern char **environ;
struct observations {
    unsigned inspect, decide;
    char sender[256], decision[8];
};
static struct observations *observed;
static const char *scenario;
static pid_t client_pid;
static sd_bus_message *held;
static sd_bus *other;
static bool is_case(const char *name) { return !strcmp(scenario, name); }
static const char digest_value[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char receipt_value[] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static const char summary_value[] = "{\"capabilities\":[\"source\",\"Draft PR\",\"Ready\"],\"role\":\"Developer\"}";
static const char malicious[] = "Ready\033[2J\r\n\t\177\302\233\342\200\256END\\capabilities";

static int inspect(sd_bus_message *m, void *context, sd_bus_error *error) {
    (void)context; (void)error; const char *id;
    assert(sd_bus_message_read(m, "s", &id) > 0 && hex(id, 32u));
    assert(sd_bus_message_get_auto_start(m) == 0);
    assert(observed->inspect++ == 0u);
    const char *sender = sd_bus_message_get_sender(m);
    assert(unique_name(sender)); memcpy(observed->sender, sender, strlen(sender) + 1u);
    if (is_case("inspect_wrong_sender")) {
        sd_bus_message *reply = NULL;
        assert(sd_bus_message_new_method_return(m, &reply) >= 0 && sd_bus_message_append(reply, "sss", digest_value, summary_value, "pending") >= 0);
        assert(sd_bus_send(other, reply, NULL) >= 0 && sd_bus_flush(other) >= 0); sd_bus_message_unref(reply); return 1;
    }
    if (is_case("signal_before")) assert(kill(client_pid, SIGINT) == 0);
    if (is_case("inspect_timeout")) return 1;
    if (is_case("inspect_signature")) return sd_bus_reply_method_return(m, "s", "pending");
    if (is_case("inspect_trailing")) return sd_bus_reply_method_return(m, "ssss", digest_value, summary_value, "pending", "extra");
    if (is_case("inspect_phase")) return sd_bus_reply_method_return(m, "sss", digest_value, summary_value, "unknown_phase");
    if (is_case("inspect_digest")) return sd_bus_reply_method_return(m, "sss", "", summary_value, "pending");
    if (is_case("inspect_summary")) return sd_bus_reply_method_return(m, "sss", digest_value, "", "pending");
    if (is_case("inspect_upper_digest")) return sd_bus_reply_method_return(m, "sss", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", summary_value, "pending");
    if (is_case("inspect_oversized")) {
        char summary[CLI_SUMMARY + 2u]; memset(summary, 'x', sizeof(summary)); summary[sizeof(summary) - 1u] = 0;
        return sd_bus_reply_method_return(m, "sss", digest_value, summary, "pending");
    }
    if (is_case("service_replaced") || is_case("service_disconnect")) {
        int r = sd_bus_reply_method_return(m, "sss", digest_value, summary_value, "pending");
        assert(sd_bus_flush(sd_bus_message_get_bus(m)) >= 0);
        assert(sd_bus_release_name(sd_bus_message_get_bus(m), CLI_NAME) >= 0);
        if (is_case("service_replaced")) assert(sd_bus_request_name(other, CLI_NAME, 0) > 0);
        return r;
    }
    if (is_case("broker_disconnect")) {
        /* Close the real client socket through a synthetic cancellation signal.
         * Actual daemon-death testing is also driven by the JS parent. */
        assert(kill(client_pid, SIGHUP) == 0); return 1;
    }
    const char *state = "pending";
    if (!strncmp(scenario, "historical_", 11u)) state = scenario + 11u;
    return sd_bus_reply_method_return(m, "sss", digest_value, is_case("terminal_bytes") ? malicious : summary_value, state);
}
static int decide(sd_bus_message *m, void *context, sd_bus_error *error) {
    (void)context; (void)error; const char *id, *decision;
    assert(sd_bus_message_read(m, "ss", &id, &decision) > 0 && hex(id, 32u));
    assert(sd_bus_message_get_auto_start(m) == 0);
    assert(observed->inspect == 1u && observed->decide++ == 0u);
    assert(!strcmp(observed->sender, sd_bus_message_get_sender(m)));
    assert(!strcmp(decision, "approve") || !strcmp(decision, "reject"));
    memcpy(observed->decision, decision, strlen(decision) + 1u);
    if (is_case("decide_wrong_sender")) {
        sd_bus_message *reply = NULL;
        assert(sd_bus_message_new_method_return(m, &reply) >= 0 && sd_bus_message_append(reply, "ss", "approved", receipt_value) >= 0);
        assert(sd_bus_send(other, reply, NULL) >= 0 && sd_bus_flush(other) >= 0); sd_bus_message_unref(reply); return 1;
    }
    if (is_case("signal_decide_int") || is_case("signal_decide_term") || is_case("signal_decide_hup")) {
        int signal = is_case("signal_decide_int") ? SIGINT : is_case("signal_decide_term") ? SIGTERM : SIGHUP;
        assert(kill(client_pid, signal) == 0); return 1;
    }
    if (is_case("daemon_death") || is_case("lost_reply") || is_case("child_after_ready") || is_case("child_during_decide") || is_case("password")) { held = sd_bus_message_ref(m); return 1; }
    if (is_case("decide_signature")) return sd_bus_reply_method_return(m, "s", "approved");
    if (is_case("decide_trailing")) return sd_bus_reply_method_return(m, "sss", "approved", receipt_value, "extra");
    if (is_case("decide_phase")) return sd_bus_reply_method_return(m, "ss", "provisioned", receipt_value);
    if (is_case("decide_missing_receipt")) return sd_bus_reply_method_return(m, "ss", "approved", "");
    if (is_case("decide_invalid_receipt")) return sd_bus_reply_method_return(m, "ss", "approved", "NOT-A-RECEIPT");
    if (is_case("decide_unknown")) return sd_bus_reply_method_return(m, "ss", "outcome_unknown", "");
    if (is_case("decide_denied")) return sd_bus_reply_method_return(m, "ss", "denied", "");
    if (is_case("decide_conflict")) return sd_bus_reply_method_return(m, "ss", "conflict", "");
    if (is_case("decide_reserved")) return sd_bus_reply_method_return(m, "ss", "reserved", receipt_value);
    if (is_case("decide_opposite")) return sd_bus_reply_method_return(m, "ss", "rejected", receipt_value);
    return sd_bus_reply_method_return(m, "ss", !strcmp(decision, "approve") ? "approved" : "rejected", receipt_value);
}
/* Raw object dispatch deliberately permits malformed reply signatures. A typed
 * vtable would reject those fixture replies before the client could see them. */
static int dispatch(sd_bus_message *m, void *context, sd_bus_error *error) {
    const char *interface = is_case("wrong_interface") ? "org.buzz.Wrong" : CLI_INTERFACE;
    if (sd_bus_message_is_method_call(m, interface, "Inspect") > 0) return inspect(m, context, error);
    if (sd_bus_message_is_method_call(m, interface, "Decide") > 0) return decide(m, context, error);
    return 0;
}
static sd_bus *bus_new(const char *address) {
    sd_bus *bus = NULL;
    assert(sd_bus_new(&bus) >= 0 && sd_bus_set_address(bus, address) >= 0 && sd_bus_set_bus_client(bus, 1) >= 0 && sd_bus_start(bus) >= 0);
    const char *unique; assert(sd_bus_get_unique_name(bus, &unique) >= 0);
    return bus;
}
static void delay_ms(unsigned ms) {
    struct timespec t = { .tv_sec = (time_t)(ms / 1000u), .tv_nsec = (long)(ms % 1000u) * 1000000L };
    while (nanosleep(&t, &t) < 0 && errno == EINTR) { }
}
static int agent_main(int argc, char **argv) {
    assert(argc == 5 && !strcmp(argv[1], "--system-bus-name") && unique_name(argv[2]) && !strcmp(argv[3], "--notify-fd") && !strcmp(argv[4], "3"));
    /* Sanitized environment and no unrelated FDs, in the actual exec child. */
    size_t env_count = 0; for (char **p = environ; *p; p++) env_count++;
    assert((fcntl(0, F_GETFL) & O_NONBLOCK) == 0);
    assert(env_count == 5u && !getenv("DBUS_SYSTEM_BUS_ADDRESS") && !getenv("CLI_SENTINEL") && !getenv("LD_PRELOAD"));
    for (int fd = 4; fd < 256; fd++) assert(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
    const char *mode = strrchr(argv[0], '/'); assert(mode); mode++;
    assert(dprintf(1, "FAKE_AGENT pid=%ld subject=%s sanitized_fds=ok\n", (long)getpid(), argv[2]) > 0);
    if (strstr(mode, "notify_exit") || strstr(mode, "registration_conflict") || strstr(mode, "child_before_ready")) return 126;
    if (strstr(mode, "notify_data")) { assert(write(3, "X", 1u) == 1); for (;;) pause(); }
    if (strstr(mode, "notify_never")) { for (;;) pause(); }
    if (strstr(mode, "ignore_term")) assert(signal(SIGTERM, SIG_IGN) != SIG_ERR);
    assert(close(3) == 0);
    if (strstr(mode, "password")) {
        struct termios before, hidden; assert(tcgetattr(0, &before) == 0); hidden = before; hidden.c_lflag &= (tcflag_t)~ECHO;
        assert(tcsetattr(0, TCSANOW, &hidden) == 0 && dprintf(1, "FAKE_PROMPT\n") > 0);
        char byte; unsigned count = 0;
        while (count++ < 128u && read(0, &byte, 1u) == 1 && byte != '\n') { }
        assert(tcsetattr(0, TCSANOW, &before) == 0 && dprintf(1, "FAKE_DONE\n") > 0);
    }
    for (;;) pause();
}
static int expected_code(void) {
    if (is_case("approve") || is_case("reject") || is_case("terminal_bytes") || is_case("ignore_term") || is_case("password")) return 0;
    if (!strncmp(scenario, "decide_", 7u) && !is_case("decide_denied") && !is_case("decide_conflict") && !is_case("decide_reserved") && !is_case("decide_opposite")) return 2;
    if (!strncmp(scenario, "signal_decide_", 14u) || is_case("lost_reply") || is_case("child_after_ready") || is_case("child_during_decide") || is_case("cleanup_failure")) return 2;
    return 1;
}
int main(int argc, char **argv) {
    if (argc == 5 && !strcmp(argv[1], "--system-bus-name")) return agent_main(argc, argv);
    assert(argc == 5 && getuid() != 0); scenario = argv[2];
    assert(prctl(PR_SET_CHILD_SUBREAPER, 1) == 0);
    observed = mmap(NULL, sizeof(*observed), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    assert(observed != MAP_FAILED); memset(observed, 0, sizeof(*observed));
    sd_bus *service = bus_new(argv[1]); other = bus_new(argv[1]); sd_bus_slot *methods = NULL;
    const char *path = is_case("wrong_path") ? "/org/buzz/Wrong" : CLI_PATH;
    assert(sd_bus_add_object(service, &methods, path, dispatch, NULL) >= 0);
    assert(sd_bus_request_name(service, CLI_NAME, SD_BUS_NAME_ALLOW_REPLACEMENT) >= 0);
    fixture = (struct cli_fixture){ .address = argv[1], .agent = argv[3], .broker_uid = getuid(), .service_uid = getuid(), .permit_agent_uid = true, .ready_ms = 300u, .work_ms = 1800u };
    if (is_case("wrong_service_uid")) fixture.service_uid = 0;
    if (is_case("wrong_broker_uid")) fixture.broker_uid = 0;
    fixture.reject_identity = is_case("privileged_identity") || is_case("root_identity") || is_case("shared_agent_uid"); fixture.reject_broker = is_case("wrong_broker");
    fixture.reject_tty = is_case("synthetic_tty_loss"); fixture.pidfd_failure = is_case("pidfd_failure");
    fixture.cleanup_failure = is_case("cleanup_failure"); fixture.parent_race = is_case("parent_death_gate");
    if (is_case("shared_agent_uid")) fixture.permit_agent_uid = false;
    if (is_case("deadline_start")) fixture.work_ms = 1u;
    int master = posix_openpt(O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC); assert(master >= 0);
    assert(grantpt(master) == 0 && unlockpt(master) == 0);
    char slave_name[128]; assert(ptsname_r(master, slave_name, sizeof(slave_name)) == 0);
    /* Deliberately inherited unrelated FD must not cross the agent exec. */
    int unrelated[2]; assert(pipe(unrelated) == 0);
    int service_fd = sd_bus_get_fd(service), other_fd = sd_bus_get_fd(other);
    assert(service_fd >= 0 && other_fd >= 0 && service_fd != other_fd);
    pid_t sentinel = fork(); assert(sentinel >= 0);
    if (!sentinel) { assert(close(service_fd) == 0 && close(other_fd) == 0); for (;;) pause(); }
    client_pid = fork(); assert(client_pid >= 0);
    if (!client_pid) {
        assert(close(service_fd) == 0 && close(other_fd) == 0);
        assert(setsid() >= 0);
        int slave = open(slave_name, O_RDWR); assert(slave >= 0 && ioctl(slave, TIOCSCTTY, 0) == 0);
        assert(dup2(slave, 0) == 0 && dup2(slave, 1) == 1 && dup2(slave, 2) == 2);
        if (slave > 2) assert(close(slave) == 0);
        assert(close(master) == 0);
        if (is_case("no_tty")) { int null = open("/dev/null", O_RDWR); assert(null >= 0 && dup2(null, 0) == 0); }
        if (is_case("redirected_stdout")) { int null = open("/dev/null", O_RDWR); assert(null >= 0 && dup2(null, 1) == 1); }
        if (is_case("background_tty")) {
            /* A separate foreground process group makes this invocation background. */
            pid_t foreground = fork(); assert(foreground >= 0);
            if (!foreground) { assert(setpgid(0, 0) == 0); delay_ms(2000u); _exit(0); }
            assert(setpgid(foreground, foreground) == 0 && tcsetpgrp(0, foreground) == 0);
        }
        assert(setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/definitely/not/the/broker", 1) == 0 && setenv("CLI_SENTINEL", "synthetic-only", 1) == 0);
        char *args[] = {"host-approval", is_case("reject") ? "reject" : "approve", "0123456789abcdef0123456789abcdef", NULL};
        if (is_case("invalid_id")) args[2] = "0123456789abcdef0123456789abcdeF";
        if (is_case("invalid_decision")) args[1] = "--approve";
        int count = is_case("extra_arg") ? 4 : 3;
        _exit(run_client(count, args));
    }
    char transcript[CLI_SUMMARY * 4u + 8192u] = {0}; size_t length = 0;
    int status = 0; bool exited = false, password_sent = false, killed_parent = false, broker_requested = false, killed_agent = false;
    uint64_t start, now; assert(clock_ms(&start) == 0);
    while (!exited) {
        assert(clock_ms(&now) == 0 && now - start < 6000u);
        for (unsigned i = 0; i < 16u; i++) { int r = sd_bus_process(service, NULL); assert(r >= 0 || broker_requested); if (r <= 0) break; }
        ssize_t n = read(master, transcript + length, sizeof(transcript) - length - 1u);
        if (n > 0) { length += (size_t)n; transcript[length] = 0; }
        assert(length + 1u < sizeof(transcript));
        if (is_case("password") && strstr(transcript, "FAKE_PROMPT") && !password_sent) {
            static const char marker[] = "SYNTHETIC_PASSWORD_DO_NOT_LOG\n";
            assert(write(master, marker, sizeof(marker) - 1u) == (ssize_t)(sizeof(marker) - 1u)); password_sent = true;
        }
        if (is_case("password") && held && strstr(transcript, "FAKE_DONE")) {
            assert(sd_bus_reply_method_return(held, "ss", "approved", receipt_value) >= 0); held = sd_bus_message_unref(held);
        }
        if (is_case("parent_death") && strstr(transcript, "FAKE_AGENT") && !killed_parent) { assert(kill(client_pid, SIGKILL) == 0); killed_parent = true; }
        if ((is_case("child_after_ready") || is_case("child_during_decide")) && observed->decide && !killed_agent) {
            char *agent = strstr(transcript, "FAKE_AGENT pid=");
            if (agent) {
                long pid = 0; assert(sscanf(agent, "FAKE_AGENT pid=%ld", &pid) == 1 && pid > 1 && pid <= INT_MAX);
                assert(getpgid((pid_t)pid) == client_pid && kill((pid_t)pid, SIGKILL) == 0); killed_agent = true;
            }
        }
        if (is_case("daemon_death") && observed->decide && !broker_requested) {
            /* JS owns the broker process; ask it to kill that exact retained child. */
            assert(dprintf(1, "KILL_DISPOSABLE_BROKER\n") > 0); broker_requested = true;
        }
        pid_t result = waitpid(client_pid, &status, WNOHANG); assert(result >= 0); exited = result == client_pid;
        struct pollfd p = { .fd = master, .events = POLLIN }; (void)poll(&p, 1u, 2);
    }
    for (;;) {
        ssize_t n = read(master, transcript + length, sizeof(transcript) - length - 1u); if (n <= 0) break;
        length += (size_t)n; transcript[length] = 0; assert(length + 1u < sizeof(transcript));
    }
    if (is_case("parent_death")) assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    else if (is_case("parent_death_gate")) assert(WIFEXITED(status) && WEXITSTATUS(status) == 99);
    else {
        int expected = is_case("daemon_death") ? 2 : expected_code();
        if (!WIFEXITED(status) || WEXITSTATUS(status) != expected) {
            (void)dprintf(2, "synthetic scenario %s expected=%d status=%d transcript=%s\n", scenario, expected, status, transcript); abort();
        }
    }
    if (expected_code() == 0 || is_case("cleanup_failure")) {
        assert(observed->inspect == 1u && observed->decide == 1u);
        char *summary_end = strstr(transcript, "authorize Ready."), *agent_start = strstr(transcript, "FAKE_AGENT");
        assert(summary_end && agent_start && summary_end < agent_start);
        char expected_subject[300]; assert(snprintf(expected_subject, sizeof(expected_subject), "subject=%s sanitized_fds=ok", observed->sender) > 0);
        assert(strstr(transcript, expected_subject) && strstr(transcript, "server_confirmed") && strstr(transcript, receipt_value));
    }
    if (!strncmp(scenario, "historical_", 11u)) assert(!observed->decide && !strstr(transcript, "FAKE_AGENT") && strstr(transcript, "no authentication or Decide"));
    if (is_case("terminal_bytes")) assert(strstr(transcript, "\\x1b[2J\\x0d\\x0a\\x09\\x7f\\xc2\\x9b\\xe2\\x80\\xaeEND\\x5ccapabilities") && !strchr(transcript, '\033'));
    if (is_case("lost_reply") || !strncmp(scenario, "signal_decide_", 14u)) assert(observed->decide == 1u && strstr(transcript, "outcome_unknown"));
    if (expected_code() == 1 && strncmp(scenario, "decide_", 7u) && !is_case("daemon_death") && !is_case("parent_death") && !is_case("parent_death_gate")) assert(observed->decide == 0u);
    assert(observed->decide <= 1u && !strstr(transcript, "SYNTHETIC_PASSWORD_DO_NOT_LOG"));
    /* Parent-death/background grandchildren are reaped by this fixture's
     * subreaper. No claim that SIGKILL executes client userspace cleanup. */
    assert(waitpid(sentinel, &status, WNOHANG) == 0 && kill(sentinel, SIGTERM) == 0 && waitpid(sentinel, &status, 0) == sentinel);
    assert(clock_ms(&start) == 0);
    for (;;) {
        pid_t reaped = waitpid(-1, &status, WNOHANG);
        if (reaped > 0) { assert(reaped != sentinel); continue; }
        if (reaped == -1) { assert(errno == ECHILD); break; }
        assert(reaped == 0);
        assert(clock_ms(&now) == 0);
        if (now - start > 2200u) break;
        delay_ms(5u);
    }
    /* Any remaining descendant (agent or background fixture) is a real failure. */
    assert(waitpid(-1, &status, WNOHANG) == -1 && errno == ECHILD);
    held = sd_bus_message_unref(held); methods = sd_bus_slot_unref(methods); service = sd_bus_close_unref(service); other = sd_bus_close_unref(other);
    assert(close(master) == 0 && close(unrelated[0]) == 0 && close(unrelated[1]) == 0);
    assert(munmap(observed, sizeof(*observed)) == 0);
    assert(dprintf(1, "PASS %s: synthetic broker/agent/PTY; NOT live Polkit/TTY/root/store acceptance\n", scenario) > 0);
    return 0;
}
