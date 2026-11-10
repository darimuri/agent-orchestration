/* SYNTHETIC support only: real terminal client, disposable bus, fake Polkit.
 * No root/installed Polkit/host session claim. Not linked into production. */
#define HOST_APPROVAL_CLI_TEST
#include "../../job-preparation/native/host-approval.c"
#include <assert.h>

static sd_bus *pk_bus;
static const char *pk_mode;
static int pk_result(sd_bus_message *call, int allowed, int challenge) {
    sd_bus_message *reply = NULL;
    assert(sd_bus_message_new_method_return(call, &reply) >= 0);
    assert(sd_bus_message_open_container(reply, 'r', "bba{ss}") >= 0);
    assert(sd_bus_message_append(reply, "bb", allowed, challenge) >= 0);
    assert(sd_bus_message_open_container(reply, 'a', "{ss}") >= 0);
    assert(sd_bus_message_close_container(reply) >= 0 && sd_bus_message_close_container(reply) >= 0);
    int r = sd_bus_send(pk_bus, reply, NULL); sd_bus_message_unref(reply); return r;
}
static int pk_check(sd_bus_message *m, void *context, sd_bus_error *error) {
    (void)context; (void)error;
    const char *kind = NULL, *key = NULL, *subject = NULL, *action = NULL, *cancel_id = NULL;
    uint32_t flags = 0;
    assert(sd_bus_message_enter_container(m, 'r', "sa{sv}") > 0);
    assert(sd_bus_message_read(m, "s", &kind) > 0 && !strcmp(kind, "system-bus-name"));
    assert(sd_bus_message_enter_container(m, 'a', "{sv}") > 0 && sd_bus_message_enter_container(m, 'e', "sv") > 0);
    assert(sd_bus_message_read(m, "s", &key) > 0 && !strcmp(key, "name"));
    assert(sd_bus_message_enter_container(m, 'v', "s") > 0 && sd_bus_message_read(m, "s", &subject) > 0 && subject[0] == ':');
    assert(sd_bus_message_exit_container(m) >= 0 && sd_bus_message_exit_container(m) >= 0 && sd_bus_message_exit_container(m) >= 0 && sd_bus_message_exit_container(m) >= 0);
    assert(sd_bus_message_read(m, "s", &action) > 0);
    assert(!strcmp(action, "org.buzz.host-approval.approve") || !strcmp(action, "org.buzz.host-approval.reject"));
    assert(sd_bus_message_skip(m, "a{ss}") >= 0 && sd_bus_message_read(m, "us", &flags, &cancel_id) > 0 && cancel_id[0]);
    assert(dprintf(1, "CHECK subject=%s action=%s flags=%u\n", subject, action, flags) > 0);
    if (!strcmp(pk_mode, "hold")) return 1;
    if (!strcmp(pk_mode, "malformed")) return sd_bus_reply_method_return(m, "s", "bad");
    if (!strcmp(pk_mode, "denied")) return pk_result(m, 0, 0);
    return flags ? pk_result(m, 1, 0) : pk_result(m, 0, 1);
}
static int pk_cancel(sd_bus_message *m, void *context, sd_bus_error *error) {
    (void)context; (void)error; return sd_bus_reply_method_return(m, "");
}
static const sd_bus_vtable pk_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("CheckAuthorization", "(sa{sv})sa{ss}us", "(bba{ss})", pk_check, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("CancelCheckAuthorization", "s", "", pk_cancel, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_VTABLE_END
};
static sd_bus *fixture_bus(const char *address) {
    sd_bus *bus = NULL;
    assert(sd_bus_new(&bus) >= 0 && sd_bus_set_address(bus, address) >= 0 && sd_bus_set_bus_client(bus, 1) >= 0 && sd_bus_start(bus) >= 0);
    return bus;
}
static int fake_agent(int argc, char **argv) {
    assert(argc == 5 && !strcmp(argv[1], "--system-bus-name") && argv[2][0] == ':' && !strcmp(argv[3], "--notify-fd") && !strcmp(argv[4], "3"));
    for (int fd = 4; fd < 256; fd++) assert(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
    assert(!getenv("DBUS_SYSTEM_BUS_ADDRESS") && !getenv("NODE_OPTIONS"));
    assert(dprintf(1, "FAKE_AGENT subject=%s\n", argv[2]) > 0 && close(3) == 0);
    for (;;) pause();
}
static int terminal(int argc, char **argv) {
    assert(argc == 7); int master = posix_openpt(O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC); assert(master >= 0);
    assert(grantpt(master) == 0 && unlockpt(master) == 0); char name[128]; assert(ptsname_r(master, name, sizeof(name)) == 0);
    pid_t child = fork(); assert(child >= 0);
    if (!child) {
        assert(setsid() >= 0); int slave = open(name, O_RDWR); assert(slave >= 0 && ioctl(slave, TIOCSCTTY, 0) == 0);
        assert(dup2(slave, 0) == 0 && dup2(slave, 1) == 1 && dup2(slave, 2) == 2); if (slave > 2) assert(close(slave) == 0); assert(close(master) == 0);
        fixture = (struct cli_fixture){ .address = argv[2], .agent = argv[5], .broker_uid = getuid(), .service_uid = getuid(), .permit_agent_uid = true, .work_ms = 2500u, .ready_ms = 1000u };
        if (!strcmp(argv[6], "no_tty")) fixture.reject_tty = true;
        char *args[] = {"host-approval", argv[3], argv[4], NULL}; _exit(run_client(3, args));
    }
    int status = 0; uint64_t start = 0, now = 0; assert(clock_ms(&start) == 0);
    for (;;) {
        char bytes[8192]; ssize_t n = read(master, bytes, sizeof(bytes)); if (n > 0) assert(write(1, bytes, (size_t)n) == n);
        pid_t result = waitpid(child, &status, WNOHANG); assert(result >= 0);
        if (result == child) break;
        assert(clock_ms(&now) == 0 && now - start < 6000u); struct pollfd p = { .fd = master, .events = POLLIN }; (void)poll(&p, 1u, 2);
    }
    for (;;) { char bytes[8192]; ssize_t n = read(master, bytes, sizeof(bytes)); if (n <= 0) break; assert(write(1, bytes, (size_t)n) == n); }
    assert(close(master) == 0); return WIFEXITED(status) ? WEXITSTATUS(status) : 3;
}
static int raw_call(int argc, char **argv) {
    assert(argc == 6); sd_bus *bus = fixture_bus(argv[2]); sd_bus_message *m = NULL, *reply_message = NULL;
    assert(sd_bus_message_new_method_call(bus, &m, CLI_NAME, CLI_PATH, CLI_INTERFACE, argv[3]) >= 0 && sd_bus_message_set_auto_start(m, 0) >= 0);
    assert(sd_bus_message_append(m, "s", argv[4]) >= 0); if (!strcmp(argv[3], "Decide")) assert(sd_bus_message_append(m, "s", argv[5]) >= 0);
    int r = sd_bus_call(bus, m, UINT64_C(3000000), NULL, &reply_message);
    if (r >= 0) { const char *a = NULL, *b = NULL, *c = NULL; if (!strcmp(argv[3], "Inspect")) { assert(sd_bus_message_read(reply_message, "sss", &a, &b, &c) > 0); assert(dprintf(1, "OBSERVE %s digest=%s summary=%s\n", c, a, b) > 0); } else { assert(sd_bus_message_read(reply_message, "ss", &a, &b) > 0); assert(dprintf(1, "DECISION %s receipt=%s\n", a, b) > 0); } }
    sd_bus_message_unref(reply_message); sd_bus_message_unref(m); sd_bus_close_unref(bus); return r >= 0 ? 0 : 1;
}
int main(int argc, char **argv) {
    if (argc == 5 && !strcmp(argv[1], "--system-bus-name")) return fake_agent(argc, argv);
    assert(argc >= 2);
    if (!strcmp(argv[1], "terminal")) return terminal(argc, argv);
    if (!strcmp(argv[1], "raw")) return raw_call(argc, argv);
    assert(argc == 4 && !strcmp(argv[1], "authority")); pk_mode = argv[3]; pk_bus = fixture_bus(argv[2]); sd_bus_slot *slot = NULL;
    assert(sd_bus_add_object_vtable(pk_bus, &slot, "/org/freedesktop/PolicyKit1/Authority", "org.freedesktop.PolicyKit1.Authority", pk_vtable, NULL) >= 0);
    assert(sd_bus_request_name(pk_bus, "org.freedesktop.PolicyKit1", SD_BUS_NAME_ALLOW_REPLACEMENT) > 0 && dprintf(1, "READY synthetic Polkit\n") > 0);
    for (;;) { int r = sd_bus_process(pk_bus, NULL); assert(r >= 0); if (!r) assert(sd_bus_wait(pk_bus, 10000u) >= 0); }
}
