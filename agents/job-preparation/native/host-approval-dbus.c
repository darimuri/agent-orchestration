/* Native sender/Polkit primitive, not a daemon, store bridge or effect executor. */
#include "host-approval-dbus.h"
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-login.h>

_Static_assert(sizeof(((struct ha_binding *)0)->decision) >= sizeof("approve"), "decision capacity");

#define PK_NAME "org.freedesktop.PolicyKit1"
#define PK_PATH "/org/freedesktop/PolicyKit1/Authority"
#define PK_INTERFACE "org.freedesktop.PolicyKit1.Authority"
#define HA_ERROR "org.buzz.HostApproval1.Error.Denied"
#define HA_SYSTEM_ADDRESS "unix:path=/run/dbus/system_bus_socket"
#ifndef HA_TEST
enum ha_test_fault { HA_FAULT_NONE, HA_FAULT_ALLOC, HA_FAULT_SEND, HA_FAULT_WATCH, HA_FAULT_CREDS };
#endif
struct ha_server {
    bool live, processing, poisoned, synthetic_session;
    unsigned index, inflight;
    uint64_t last_epoch;
    struct ha_config config;
    struct ha_core_ops core;
    sd_bus *bus;
    sd_id128_t broker_id;
    char authority[256], unique[256];
    sd_bus_slot *methods, *names, *disconnect;
};
struct ha_call {
    bool live, decide, auth_started, auth_done, pending;
    unsigned stage;
    ha_server *server;
    sd_bus_message *message;
    sd_bus_slot *authorization;
    struct ha_binding binding;
    char sender[256], request_id[33], decision[8], cancellation[96];
    pid_t pid;
    int pidfd;
    uint64_t deadline, monotonic_deadline;
    ha_completion completion;
    void *completion_context;
    ha_lease *lease;
};
struct ha_lease { bool live; ha_server *server; ha_call *call; };
/* Never recycle handle addresses. Tombstones make stale pointers fail without
 * dereferencing freed memory, including after server teardown. Bounded lifetime
 * exhaustion denies; no reset/adoption mechanism. No allocation in these arenas. */
static ha_server servers[HA_MAX_SERVERS];
static ha_call calls[HA_MAX_HANDLES];
static ha_lease leases[HA_MAX_HANDLES];
static unsigned servers_used, calls_used, leases_used;
#ifdef HA_TEST
static enum ha_test_fault fail_next;
void ha_test_fail_next(enum ha_test_fault fault) { fail_next = fault; }
#endif
static bool fault(enum ha_test_fault which) {
#ifdef HA_TEST
    if (fail_next == which) { fail_next = HA_FAULT_NONE; return true; }
#else
    (void)which;
#endif
    return false;
}
static ha_server *server_known(ha_server *s) {
    for (unsigned i = 0; i < servers_used; i++) if (s == &servers[i]) return s;
    return NULL;
}
static ha_call *call_known(ha_call *c) {
    for (unsigned i = 0; i < calls_used; i++) if (c == &calls[i]) return c;
    return NULL;
}
static ha_lease *lease_known(ha_lease *l) {
    for (unsigned i = 0; i < leases_used; i++) if (l == &leases[i]) return l;
    return NULL;
}
static bool bounded(const char *p, size_t max) { return p && strnlen(p, max + 1u) <= max; }
static bool hex(const char *p, size_t n) {
    if (!bounded(p, n) || strlen(p) != n) return false;
    for (size_t i = 0; i < n; i++) if (!((p[i] >= '0' && p[i] <= '9') || (p[i] >= 'a' && p[i] <= 'f'))) return false;
    return true;
}
static bool identifier(const char *p) {
    if (!bounded(p, 128u) || !p[0]) return false;
    for (size_t i = 0; p[i]; i++) if (!((p[i] >= 'a' && p[i] <= 'z') || (p[i] >= 'A' && p[i] <= 'Z') || (p[i] >= '0' && p[i] <= '9') || (i && (p[i] == '-' || p[i] == '_')))) return false;
    return true;
}
static bool decision(const char *p) { return bounded(p, 7u) && (!strcmp(p, "approve") || !strcmp(p, "reject")); }
static bool phase(const char *p) {
    static const char *const allowed[] = {"absent","pending","approved","rejected","expired","reserved","conflict","capacity","denied","outcome_unknown"};
    if (!bounded(p, 32u)) return false;
    for (size_t i = 0; i < sizeof(allowed)/sizeof(allowed[0]); i++) if (!strcmp(p, allowed[i])) return true;
    return false;
}
static int monotonic_ms(uint64_t *out) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) < 0 || t.tv_sec < 0 || (uint64_t)t.tv_sec > UINT64_MAX / 1000u) return -EIO;
    *out = (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
    return 0;
}
static int now_ms(ha_server *s, uint64_t *out) {
    uint64_t n = 0;
    if (s->config.now_ms(s->config.clock_context, &n) < 0 || n < s->last_epoch || n > UINT64_C(9007199254740991)) { s->poisoned = true; return -EACCES; }
    s->last_epoch = n; *out = n; return 0;
}
static int name_owner(sd_bus *bus, const char *name, char out[256]) {
    sd_bus_creds *creds = NULL; const char *unique = NULL;
    int r = fault(HA_FAULT_CREDS) ? -EIO : sd_bus_get_name_creds(bus, name, SD_BUS_CREDS_UNIQUE_NAME, &creds);
    if (r >= 0) r = sd_bus_creds_get_unique_name(creds, &unique);
    if (r >= 0 && (!bounded(unique, 255u) || unique[0] != ':')) r = -EACCES;
    if (r >= 0) memcpy(out, unique, strlen(unique) + 1u);
    sd_bus_creds_unref(creds); return r;
}
static bool connection_current(ha_server *s) {
    sd_id128_t id; char authority[256], owner[256];
    return s->live && !s->poisoned && s->bus && sd_bus_is_open(s->bus) > 0 && sd_bus_is_ready(s->bus) > 0 &&
        sd_bus_get_bus_id(s->bus, &id) >= 0 && sd_id128_equal(id, s->broker_id) &&
        name_owner(s->bus, PK_NAME, authority) >= 0 && !strcmp(authority, s->authority) &&
        name_owner(s->bus, HA_NAME, owner) >= 0 && !strcmp(owner, s->unique);
}
static bool sender_current(ha_call *c) {
    ha_server *s = c->server; sd_bus_creds *creds = NULL;
    uid_t uid = (uid_t)-1; pid_t pid = 0; bool ok = false;
    if (!connection_current(s) || fault(HA_FAULT_CREDS)) return false;
    if (sd_bus_get_name_creds(s->bus, c->sender, SD_BUS_CREDS_UID | SD_BUS_CREDS_PID, &creds) < 0 ||
        sd_bus_creds_get_uid(creds, &uid) < 0 || sd_bus_creds_get_pid(creds, &pid) < 0 || uid != s->config.owner_uid || pid <= 0 || (c->pid && c->pid != pid)) goto done;
    if (!c->decide) { c->pid = pid; ok = true; goto done; }
#ifdef HA_TEST
    if (s->synthetic_session) { c->pid = pid; ok = true; goto done; }
#endif
    if (c->pidfd >= 0) {
        struct pollfd p = { .fd = c->pidfd, .events = POLLIN };
        if (poll(&p, 1u, 0) != 0) goto done;
    } else {
#ifdef SYS_pidfd_open
        long fd = syscall(SYS_pidfd_open, pid, 0u);
        if (fd < 0 || fd > INT_MAX) goto done;
        c->pidfd = (int)fd;
#else
        goto done;
#endif
    }
    {
        char *session = NULL, *tty = NULL; const char *process_tty = NULL; sd_bus_creds *augmented = NULL; uid_t session_uid = (uid_t)-1;
        /* OS augmentation is additional deny-only evidence, NEVER the Polkit
         * subject. The subject always remains the broker unique sender. */
        int r = sd_pidfd_get_session(c->pidfd, &session);
        if (r >= 0) r = sd_session_get_uid(session, &session_uid);
        if (r >= 0 && session_uid == uid && sd_session_is_active(session) > 0) r = sd_session_get_tty(session, &tty); else r = -EACCES;
        if (r >= 0) r = sd_bus_get_name_creds(s->bus, c->sender, SD_BUS_CREDS_UID | SD_BUS_CREDS_PID | SD_BUS_CREDS_TTY | SD_BUS_CREDS_AUGMENT, &augmented);
        if (r >= 0) r = sd_bus_creds_get_tty(augmented, &process_tty);
        ok = r >= 0 && tty && tty[0] && process_tty && !strcmp(tty, process_tty);
        sd_bus_creds_unref(augmented); free(session); free(tty);
    }
    c->pid = pid;
done:
    sd_bus_creds_unref(creds); return ok;
}
static bool call_current(ha_call *c) {
    uint64_t n = 0, mono = 0;
    bool ok = c && c->live && c->server->live && !c->server->poisoned && now_ms(c->server, &n) >= 0 && monotonic_ms(&mono) >= 0 &&
        n < c->deadline && mono < c->monotonic_deadline && sender_current(c);
    return ok && now_ms(c->server, &n) >= 0 && monotonic_ms(&mono) >= 0 && c->live && c->server->live &&
        n < c->deadline && mono < c->monotonic_deadline;
}
static void cancel_check(ha_call *c) {
    sd_bus_message *m = NULL;
    if (!c->pending || !c->server->bus) return;
    if (!fault(HA_FAULT_SEND) && sd_bus_message_new_method_call(c->server->bus, &m, c->server->authority, PK_PATH, PK_INTERFACE, "CancelCheckAuthorization") >= 0 &&
        sd_bus_message_append(m, "s", c->cancellation) >= 0 && sd_bus_message_set_expect_reply(m, 0) >= 0) (void)sd_bus_send(c->server->bus, m, NULL);
    sd_bus_message_unref(m);
}
static void complete(ha_call *c, ha_lease *lease) {
    ha_completion fn = c->completion; void *context = c->completion_context;
    c->completion = NULL; c->completion_context = NULL; c->pending = false; c->auth_done = true;
    c->authorization = sd_bus_slot_unref(c->authorization);
    if (fn) fn(c, lease, context);
}
static void invalidate(ha_call *c) {
    if (!c || !c->live) return;
    c->live = false;
    if (c->lease) c->lease->live = false;
    cancel_check(c);
    sd_bus_message *message = c->message; c->message = NULL;
    if (c->server->inflight) c->server->inflight--;
    if (c->pidfd >= 0) { (void)close(c->pidfd); c->pidfd = -1; }
    complete(c, NULL);
    if (message) { (void)sd_bus_reply_method_errorf(message, HA_ERROR, "%s", "approval_denied"); sd_bus_message_unref(message); }
}
static int name_changed(sd_bus_message *m, void *userdata, sd_bus_error *error) {
    ha_server *s = userdata; const char *name = NULL, *old = NULL, *next = NULL; (void)error;
    if (!s->live || !sd_bus_message_get_sender(m) || strcmp(sd_bus_message_get_sender(m), "org.freedesktop.DBus") || sd_bus_message_read(m, "sss", &name, &old, &next) <= 0) return 0;
    if ((!strcmp(name, PK_NAME) && strcmp(old, next)) || (!strcmp(name, HA_NAME) && strcmp(next, s->unique))) s->poisoned = true;
    for (unsigned i = 0; i < calls_used; i++) if (calls[i].server == s && calls[i].live && (s->poisoned || !strcmp(calls[i].sender, name))) invalidate(&calls[i]);
    return 0;
}
static int disconnected(sd_bus_message *m, void *userdata, sd_bus_error *error) {
    ha_server *s = userdata; (void)m; (void)error; s->poisoned = true;
    for (unsigned i = 0; i < calls_used; i++) if (calls[i].server == s) invalidate(&calls[i]);
    return 0;
}
static int send_check(ha_call *c);
static bool result_schema(sd_bus_message *m, int *authorized, int *challenge) {
    if (!sd_bus_message_has_signature(m, "(bba{ss})") || sd_bus_message_enter_container(m, 'r', "bba{ss}") <= 0 ||
        sd_bus_message_read(m, "bb", authorized, challenge) < 0 || sd_bus_message_enter_container(m, 'a', "{ss}") <= 0) return false;
    size_t bytes = 0; unsigned count = 0; int r;
    while ((r = sd_bus_message_enter_container(m, 'e', "ss")) > 0) {
        const char *key = NULL, *value = NULL;
        if (++count > 16u || sd_bus_message_read(m, "ss", &key, &value) < 0 || !bounded(key, 128u) || !bounded(value, 512u)) return false;
        bytes += strlen(key) + strlen(value);
        if (bytes > HA_METADATA_BYTES || !strcmp(key, "polkit.temporary_authorization_id") ||
            ((!strcmp(key, "polkit.retains_authorization_after_challenge") || !strcmp(key, "polkit.dismissed")) && value[0]) || sd_bus_message_exit_container(m) < 0) return false;
    }
    return r == 0 && sd_bus_message_exit_container(m) >= 0 && sd_bus_message_exit_container(m) >= 0 && sd_bus_message_at_end(m, 1) > 0;
}
static int authorized_reply(sd_bus_message *m, void *userdata, sd_bus_error *error) {
    ha_call *c = userdata; int authorized = 0, challenge = 0; (void)error;
    if (!c->live || !c->pending || !c->completion) return 0;
    c->authorization = sd_bus_slot_unref(c->authorization);
    const char *sender = sd_bus_message_get_sender(m);
    if (!call_current(c) || sd_bus_message_is_method_error(m, NULL) > 0 || !sender || strcmp(sender, c->server->authority) || !result_schema(m, &authorized, &challenge)) { invalidate(c); return 0; }
    c->pending = false;
    if (!c->stage) {
        /* Deny cached/implicit YES and retained authorization. Require a
         * challenge first; real non-keep policy/fresh prompts remain host gates. */
        if (authorized || !challenge) { invalidate(c); return 0; }
        c->stage = 1u;
        if (send_check(c) < 0) invalidate(c);
        return 0;
    }
    if (!authorized || challenge || leases_used >= HA_MAX_HANDLES || fault(HA_FAULT_ALLOC)) { invalidate(c); return 0; }
    ha_lease *lease = &leases[leases_used++];
    *lease = (ha_lease){ .live = true, .server = c->server, .call = c };
    c->lease = lease; complete(c, lease); return 0;
}
static int send_check(ha_call *c) {
    sd_bus_message *m = NULL; int r = -EACCES; uint64_t n = 0;
    if (!call_current(c) || now_ms(c->server, &n) < 0 || n >= c->deadline || fault(HA_FAULT_ALLOC)) return -EACCES;
    int printed = snprintf(c->cancellation, sizeof(c->cancellation), "ha-%u-%zu-%u", c->server->index, (size_t)(c - calls), c->stage);
    if (printed < 0 || (size_t)printed >= sizeof(c->cancellation)) return -EACCES;
    r = sd_bus_message_new_method_call(c->server->bus, &m, c->server->authority, PK_PATH, PK_INTERFACE, "CheckAuthorization");
    if (r < 0) goto out;
    if ((r = sd_bus_message_open_container(m, 'r', "sa{sv}")) < 0 || (r = sd_bus_message_append(m, "s", "system-bus-name")) < 0 ||
        (r = sd_bus_message_open_container(m, 'a', "{sv}")) < 0 || (r = sd_bus_message_open_container(m, 'e', "sv")) < 0 ||
        (r = sd_bus_message_append(m, "s", "name")) < 0 || (r = sd_bus_message_open_container(m, 'v', "s")) < 0 ||
        (r = sd_bus_message_append(m, "s", c->sender)) < 0 || (r = sd_bus_message_close_container(m)) < 0 ||
        (r = sd_bus_message_close_container(m)) < 0 || (r = sd_bus_message_close_container(m)) < 0 || (r = sd_bus_message_close_container(m)) < 0 ||
        (r = sd_bus_message_append(m, "s", !strcmp(c->decision, "approve") ? HA_APPROVE_ACTION : HA_REJECT_ACTION)) < 0 ||
        (r = sd_bus_message_open_container(m, 'a', "{ss}")) < 0) goto out;
    const char *keys[] = {"requestId","intentDigest","decision","ownerId","policyDigest"};
    const char *values[] = {c->binding.request_id,c->binding.intent_digest,c->binding.decision,c->binding.owner_id,c->binding.policy_digest};
    for (size_t i = 0; i < 5u; i++) {
        if ((r = sd_bus_message_open_container(m, 'e', "ss")) < 0 || (r = sd_bus_message_append(m, "ss", keys[i], values[i])) < 0 || (r = sd_bus_message_close_container(m)) < 0) goto out;
    }
    if ((r = sd_bus_message_close_container(m)) < 0 || (r = sd_bus_message_append(m, "us", c->stage ? UINT32_C(1) : UINT32_C(0), c->cancellation)) < 0) goto out;
    r = fault(HA_FAULT_SEND) ? -EIO : sd_bus_call_async(c->server->bus, &c->authorization, m, authorized_reply, c, (c->deadline - n) * 1000u);
    if (r >= 0) c->pending = true;
out:
    sd_bus_message_unref(m); return r;
}
int ha_authorize(ha_call *input, const struct ha_binding *binding, uint64_t deadline, ha_completion fn, void *context) {
    ha_call *c = call_known(input); uint64_t n = 0, mono = 0;
    if (!c || !binding || !fn || !call_current(c) || !c->decide || c->auth_started ||
        !hex(binding->request_id, 32u) || !hex(binding->intent_digest, 64u) || !decision(binding->decision) || !identifier(binding->owner_id) || !hex(binding->policy_digest, 64u) ||
        strcmp(binding->request_id, c->request_id) || strcmp(binding->decision, c->decision) || strcmp(binding->owner_id, c->server->config.owner_id) || strcmp(binding->policy_digest, c->server->config.policy_digest) ||
        now_ms(c->server, &n) < 0 || monotonic_ms(&mono) < 0 || deadline <= n) return -EACCES;
    c->auth_started = true; c->binding = *binding;
    if (deadline < c->deadline) { c->deadline = deadline; uint64_t limit = mono + deadline - n; if (limit < c->monotonic_deadline) c->monotonic_deadline = limit; }
    c->completion = fn; c->completion_context = context;
    int r = send_check(c); if (r < 0) invalidate(c); return r;
}
static int method(sd_bus_message *m, void *userdata, sd_bus_error *error) {
    ha_server *s = userdata; const char *id = NULL, *decide = NULL, *sender = sd_bus_message_get_sender(m); uint64_t n = 0, mono = 0;
    (void)error;
    bool is_decide = sd_bus_message_is_method_call(m, HA_INTERFACE, "Decide") > 0;
    if (!s->live || !connection_current(s) || sd_bus_message_get_bus(m) != s->bus || !bounded(sender, 255u) || sender[0] != ':' ||
        !sd_bus_message_has_signature(m, is_decide ? "ss" : "s") || sd_bus_message_read(m, is_decide ? "ss" : "s", &id, &decide) < 0 ||
        !hex(id, 32u) || (is_decide && !decision(decide)) || calls_used >= HA_MAX_HANDLES || s->inflight >= HA_MAX_INFLIGHT || fault(HA_FAULT_ALLOC) ||
        now_ms(s, &n) < 0 || monotonic_ms(&mono) < 0) goto denied;
    for (unsigned i = 0; i < calls_used; i++) if (calls[i].live && calls[i].server == s && !strcmp(calls[i].sender, sender) && !strcmp(calls[i].request_id, id)) goto denied;
    ha_call provisional = { .live = true, .decide = is_decide, .server = s, .pidfd = -1,
        .deadline = n + s->config.authority_timeout_ms, .monotonic_deadline = mono + s->config.authority_timeout_ms };
    memcpy(provisional.sender, sender, strlen(sender) + 1u); memcpy(provisional.request_id, id, 33u);
    if (is_decide) memcpy(provisional.decision, decide, strlen(decide) + 1u);
    /* Untrusted/wrong-owner traffic cannot consume nonrecycled handles. */
    if (!sender_current(&provisional)) { if (provisional.pidfd >= 0) (void)close(provisional.pidfd); goto denied; }
    ha_call *c = &calls[calls_used++]; *c = provisional;
    c->message = sd_bus_message_ref(m); s->inflight++;
    if (!c->message) { invalidate(c); return 1; }
    if (is_decide) s->core.on_decide(c, id, decide, s->core.context); else s->core.on_inspect(c, id, s->core.context);
    return 1;
denied:
    return sd_bus_reply_method_errorf(m, HA_ERROR, "%s", "approval_denied");
}
static const sd_bus_vtable vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("Inspect", "s", "sss", method, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("Decide", "ss", "ss", method, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_VTABLE_END
};
int ha_call_reply(ha_call *input, const struct ha_reply *reply) {
    ha_call *c = call_known(input); sd_bus_message *m = NULL;
    if (!c || !reply || !call_current(c) || !phase(reply->phase) ||
        (c->decide ? !bounded(reply->receipt_id, 32u) || (reply->receipt_id[0] && !hex(reply->receipt_id, 32u)) :
         !bounded(reply->intent_digest, 64u) || (reply->intent_digest[0] && !hex(reply->intent_digest, 64u)) || !bounded(reply->summary_json, HA_SUMMARY_BYTES))) return -EACCES;
    if (c->decide && (c->pending || (c->auth_started && (!c->auth_done || !c->lease || !ha_lease_valid(c->lease))))) return -EACCES;
    int r = fault(HA_FAULT_ALLOC) ? -ENOMEM : sd_bus_message_new_method_return(c->message, &m);
    if (r >= 0) r = c->decide ? sd_bus_message_append(m, "ss", reply->phase, reply->receipt_id) : sd_bus_message_append(m, "sss", reply->intent_digest, reply->summary_json, reply->phase);
    if (r >= 0) r = fault(HA_FAULT_SEND) ? -EIO : sd_bus_send(c->server->bus, m, NULL);
    sd_bus_message_unref(m);
    /* Consume the call even when response publication is uncertain. No claim
     * that a trusted core did or did not commit follows from this transport. */
    if (r >= 0) { c->message = sd_bus_message_unref(c->message); }
    invalidate(c); return r < 0 ? -EIO : 0;
}
void ha_call_cancel(ha_call *input) { invalidate(call_known(input)); }
int ha_lease_valid(ha_lease *input) {
    ha_lease *l = lease_known(input);
    if (!l || !l->live || !l->server->live || !l->call->auth_done || !call_current(l->call)) { if (l) l->live = false; return 0; }
    return 1;
}
void ha_lease_free(ha_lease *input) { ha_lease *l = lease_known(input); if (l && l->live) { l->live = false; invalidate(l->call); } }
static int construct(const struct ha_config *config, const struct ha_core_ops *core, sd_bus *bus, bool synthetic, ha_server **out) {
    if (out) *out = NULL;
    if (!config || !core || !out || !core->on_inspect || !core->on_decide || !config->now_ms || !identifier(config->owner_id) || !hex(config->policy_digest, 64u) ||
        config->owner_uid == 0 || (!synthetic && config->owner_uid == 10001u) || config->authority_timeout_ms == 0 || config->authority_timeout_ms > 60000u || servers_used >= HA_MAX_SERVERS || !bus || sd_bus_is_bus_client(bus) <= 0 || sd_bus_is_ready(bus) <= 0 || fault(HA_FAULT_ALLOC)) return -EACCES;
    ha_server *s = &servers[servers_used++];
    *s = (ha_server){ .live = true, .synthetic_session = synthetic, .index = servers_used, .config = *config, .core = *core, .bus = sd_bus_ref(bus) };
    const char *unique = NULL;
    if (sd_bus_get_unique_name(bus, &unique) < 0 || !bounded(unique, 255u)) { ha_server_free(s); return -EACCES; }
    memcpy(s->unique, unique, strlen(unique) + 1u);
    if (sd_bus_get_bus_id(bus, &s->broker_id) < 0 || name_owner(bus, PK_NAME, s->authority) < 0 || now_ms(s, &s->last_epoch) < 0 || fault(HA_FAULT_WATCH) ||
        sd_bus_add_match(bus, &s->names, "type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',member='NameOwnerChanged',path='/org/freedesktop/DBus'", name_changed, s) < 0 ||
        sd_bus_add_match(bus, &s->disconnect, "type='signal',interface='org.freedesktop.DBus.Local',member='Disconnected',path='/org/freedesktop/DBus/Local'", disconnected, s) < 0 ||
        sd_bus_add_object_vtable(bus, &s->methods, HA_PATH, HA_INTERFACE, vtable, s) < 0 || sd_bus_request_name(bus, HA_NAME, 0) <= 0) { ha_server_free(s); return -EACCES; }
    *out = s; return 0;
}
int ha_server_new(const struct ha_config *config, const struct ha_core_ops *core, ha_server **out) {
    sd_bus *bus = NULL; if (out) *out = NULL;
    if (!config || !core || !out || !core->on_inspect || !core->on_decide || !config->now_ms || !identifier(config->owner_id) || !hex(config->policy_digest, 64u) || config->owner_uid == 0 || config->owner_uid == 10001u || config->authority_timeout_ms == 0 || config->authority_timeout_ms > 60000u) return -EACCES;
    int r = sd_bus_new(&bus);
    if (r >= 0) r = sd_bus_set_address(bus, HA_SYSTEM_ADDRESS);
    if (r >= 0) r = sd_bus_set_bus_client(bus, 1);
    if (r >= 0) r = sd_bus_set_method_call_timeout(bus, UINT64_C(1000000));
    if (r >= 0) r = sd_bus_start(bus);
    const char *unique = NULL;
    if (r >= 0) r = sd_bus_get_unique_name(bus, &unique);
    if (r >= 0) r = construct(config, core, bus, false, out);
    sd_bus_unref(bus); return r < 0 ? -EACCES : 0;
}
#ifdef HA_TEST
int ha_test_server_new(const struct ha_config *config, const struct ha_core_ops *core, sd_bus *bus, ha_server **out) { return construct(config, core, bus, true, out); }
#endif
int ha_server_process(ha_server *input, uint32_t timeout_ms) {
    ha_server *s = server_known(input); uint64_t n = 0, mono = 0, wait = timeout_ms;
    if (!s || !s->live || s->processing || timeout_ms > 60000u) return -EACCES;
    s->processing = true;
    if (now_ms(s, &n) < 0 || monotonic_ms(&mono) < 0 || !connection_current(s)) s->poisoned = true;
    for (unsigned i = 0; i < calls_used; i++) if (calls[i].server == s && calls[i].live) {
        ha_call *c = &calls[i];
        if (s->poisoned || n >= c->deadline || mono >= c->monotonic_deadline) invalidate(c);
        else { uint64_t remaining = c->deadline - n; if (remaining < wait) wait = remaining; remaining = c->monotonic_deadline - mono; if (remaining < wait) wait = remaining; }
    }
    if (s->poisoned) { ha_server_free(s); s->processing = false; return -EACCES; }
    int r = sd_bus_process(s->bus, NULL);
    if (r < 0 || s->poisoned) { ha_server_free(s); s->processing = false; return -EACCES; }
    if (r == 0 && wait && s->live) r = sd_bus_wait(s->bus, wait * 1000u);
    s->processing = false; return r < 0 ? -EACCES : r;
}
void ha_server_free(ha_server *input) {
    ha_server *s = server_known(input); if (!s || !s->live) return;
    s->live = false; s->poisoned = true;
    for (unsigned i = 0; i < calls_used; i++) if (calls[i].server == s) invalidate(&calls[i]);
    s->methods = sd_bus_slot_unref(s->methods); s->names = sd_bus_slot_unref(s->names); s->disconnect = sd_bus_slot_unref(s->disconnect);
    s->bus = sd_bus_close_unref(s->bus);
}
