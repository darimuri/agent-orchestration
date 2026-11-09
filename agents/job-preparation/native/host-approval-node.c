/* Private, main-thread Node-API composition. No authority crosses JSON. */
#define NAPI_VERSION 8
#include <node_api.h>
#include "host-approval-dbus.h"
#include <errno.h>
#include <math.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

struct node_server;
struct node_state;
struct node_call {
    struct node_server *owner;
    struct node_call *next;
    ha_call *call;
    ha_lease *lease;
    napi_ref self, parent, signal, listener;
    napi_deferred deferred;
    bool live, started, settled;
    char id[33], decision[8];
};
struct node_server {
    napi_env env;
    struct node_state *state;
    struct node_server *next;
    struct node_call *calls;
    ha_server *server;
    napi_ref clock, inspect, decide, self;
    bool live, processing, operation, clock_busy, shutting_down;
};
struct node_state { napi_env env; struct node_server *servers; unsigned servers_used, calls_used, wrappers; bool finalized, constructing; napi_ref anchors; };
static const napi_type_tag server_tag = {UINT64_C(0x5491ad8c21d75981), UINT64_C(0xaf0351812a6abc11)};
static const napi_type_tag call_tag = {UINT64_C(0x6692bd8d31d86982), UINT64_C(0xbf1362923b7bcd22)};
static const napi_type_tag lease_tag = {UINT64_C(0x7793ce9e41e97983), UINT64_C(0xcf2473a34c8cde33)};
#ifdef HA_TEST
static unsigned node_fault;
#endif
static napi_status reference(napi_env env, napi_value value, uint32_t count, napi_ref *out) {
#ifdef HA_TEST
    if (node_fault == 5u) { node_fault = 0; return napi_generic_failure; }
#endif
    return napi_create_reference(env, value, count, out);
}
static bool main_thread(void) { return syscall(SYS_gettid) == (long)getpid(); }
static napi_value fail(napi_env env) {
    bool pending = false;
    if (napi_is_exception_pending(env, &pending) == napi_ok && pending) return NULL;
    (void)napi_throw_error(env, "approval_unavailable", "approval_unavailable"); return NULL;
}
static napi_value undefined(napi_env env) { napi_value v = NULL; (void)napi_get_undefined(env, &v); return v; }
static void drop(napi_env env, napi_ref *ref) { if (*ref) { (void)napi_delete_reference(env, *ref); *ref = NULL; } }
static bool string(napi_env env, napi_value value, char *out, size_t capacity) {
    napi_valuetype type; size_t size = 0, copied = 0;
    return napi_typeof(env, value, &type) == napi_ok && type == napi_string &&
        napi_get_value_string_utf8(env, value, NULL, 0, &size) == napi_ok && size < capacity &&
        napi_get_value_string_utf8(env, value, out, capacity, &copied) == napi_ok && size == copied && strlen(out) == size;
}
static bool field(napi_env env, napi_value object, const char *key, napi_value *value) {
    return napi_get_named_property(env, object, key, value) == napi_ok;
}
static bool text(napi_env env, napi_value object, const char *key, char *out, size_t size) {
    napi_value value; return field(env, object, key, &value) && string(env, value, out, size);
}
static bool integer(napi_env env, napi_value value, uint64_t *out) {
    napi_valuetype type; double n = 0;
    if (napi_typeof(env, value, &type) != napi_ok || type != napi_number || napi_get_value_double(env, value, &n) != napi_ok ||
        !isfinite(n) || n < 0 || n > 9007199254740991.0 || floor(n) != n) return false;
    *out = (uint64_t)n; return true;
}
static bool exact(napi_env env, napi_value value, uint32_t count) {
    napi_value names; uint32_t n = 0;
    return napi_get_all_property_names(env, value, napi_key_own_only, napi_key_all_properties, napi_key_numbers_to_strings, &names) == napi_ok &&
        napi_get_array_length(env, names, &n) == napi_ok && n == count;
}
static bool instance(napi_env env, napi_value self, const napi_type_tag *tag, void *expected) {
    bool tagged = false; void *pointer = NULL;
    return main_thread() && napi_check_object_type_tag(env, self, tag, &tagged) == napi_ok && tagged &&
        napi_unwrap(env, self, &pointer) == napi_ok && pointer == expected;
}
static void finish(struct node_call *c);
static void release_state(struct node_state *state);
static void close_server(struct node_server *s) {
    if (!s->live) { if (s->server) ha_server_free(s->server); return; }
    s->live = false;
    ha_server_free(s->server);
    for (struct node_call *c = s->calls; c; c = c->next) finish(c);
    drop(s->env, &s->clock); drop(s->env, &s->inspect); drop(s->env, &s->decide); drop(s->env, &s->self);
}
static void settle(struct node_call *c, napi_value lease) {
    if (c->settled || !c->deferred) return;
    c->settled = true;
    if (!c->owner->shutting_down) {
        if (lease) (void)napi_resolve_deferred(c->owner->env, c->deferred, lease);
        else {
            napi_value message, error;
            if (napi_create_string_utf8(c->owner->env, "approval_denied", NAPI_AUTO_LENGTH, &message) == napi_ok &&
                napi_create_error(c->owner->env, NULL, message, &error) == napi_ok) (void)napi_reject_deferred(c->owner->env, c->deferred, error);
        }
    }
    c->deferred = NULL;
}
static void detach_signal(struct node_call *c) {
    napi_env env = c->owner->env;
    if (c->signal && c->listener && !c->owner->shutting_down) {
        napi_value signal, listener, method, event, result;
        if (napi_get_reference_value(env, c->signal, &signal) == napi_ok && napi_get_reference_value(env, c->listener, &listener) == napi_ok &&
            field(env, signal, "removeEventListener", &method) && napi_create_string_utf8(env, "abort", NAPI_AUTO_LENGTH, &event) == napi_ok) {
            napi_value args[] = {event, listener}; (void)napi_call_function(env, signal, method, 2, args, &result);
        }
    }
    drop(env, &c->signal); drop(env, &c->listener);
}
static void finish(struct node_call *c) {
    if (!c->live) return;
    c->live = false;
    ha_call_cancel(c->call); /* synchronous NULL completion may settle once */
    settle(c, NULL);
    if (c->lease) { ha_lease_free(c->lease); c->lease = NULL; }
    detach_signal(c); drop(c->owner->env, &c->self); drop(c->owner->env, &c->parent);
}
static void collected(napi_env env, void *data, void *hint) {
    (void)env; (void)hint; struct node_call *c = data; struct node_state *state = c->owner->state;
    finish(c); state->wrappers--; release_state(state);
}
static void lease_collected(napi_env env, void *data, void *hint) {
    (void)env; (void)hint; struct node_call *c = data; struct node_state *state = c->owner->state;
    state->wrappers--; release_state(state);
}
static void server_collected(napi_env env, void *data, void *hint) {
    (void)env; (void)hint; struct node_server *s = data; struct node_state *state = s->state;
    close_server(s); state->wrappers--; release_state(state);
}
static bool wrap(napi_env env, napi_value value, void *data, napi_finalize finalizer, struct node_state *state) {
    if (napi_wrap(env, value, data, finalizer, NULL, NULL) != napi_ok) return false;
    state->wrappers++; return true;
}
static int clock_now(void *context, uint64_t *out) {
    struct node_server *s = context; napi_value fn, result, receiver;
    if (!s->live || s->clock_busy || !main_thread()) return -EACCES;
    s->clock_busy = true;
    bool ok = napi_get_reference_value(s->env, s->clock, &fn) == napi_ok && napi_get_undefined(s->env, &receiver) == napi_ok &&
        napi_call_function(s->env, receiver, fn, 0, NULL, &result) == napi_ok && integer(s->env, result, out);
    s->clock_busy = false; return ok ? 0 : -EACCES;
}
static napi_value valid(napi_env env, napi_callback_info info) {
    napi_value self, result; size_t argc = 0; void *data = NULL;
    if (napi_get_cb_info(env, info, &argc, NULL, &self, &data) != napi_ok) return fail(env);
    struct node_call *c = data;
    if (!instance(env, self, &lease_tag, c) || c->owner->env != env || c->owner->operation || c->owner->clock_busy) return fail(env);
    c->owner->operation = true;
    bool live = c->live && c->owner->live && c->lease && ha_lease_valid(c->lease) == 1;
    c->owner->operation = false;
    if (napi_get_boolean(env, live, &result) != napi_ok) return fail(env);
    return result;
}
static bool method(napi_env env, napi_value object, const char *name, napi_callback callback, void *context) {
    napi_property_descriptor descriptor = { .utf8name = name, .method = callback, .attributes = napi_default, .data = context };
    return napi_define_properties(env, object, 1, &descriptor) == napi_ok;
}
static void authorized(ha_call *call, ha_lease *lease, void *context) {
    struct node_call *c = context; napi_env env = c->owner->env; napi_value object;
    if (call != c->call || !c->live || !c->owner->live || c->settled || !lease || c->owner->shutting_down) {
        if (lease) ha_lease_free(lease);
        settle(c, NULL); return;
    }
#ifdef HA_TEST
    if (node_fault == 8u) { node_fault = 0; ha_lease_free(lease); settle(c, NULL); return; }
#endif
    c->lease = lease;
    if (napi_create_object(env, &object) != napi_ok || napi_type_tag_object(env, object, &lease_tag) != napi_ok ||
        !wrap(env, object, c, lease_collected, c->owner->state) || !method(env, object, "valid", valid, c) || napi_object_freeze(env, object) != napi_ok) {
        finish(c); close_server(c->owner); return;
    }
    settle(c, object);
#ifdef HA_TEST
    if (node_fault == 7u) { node_fault = 0; authorized(call, lease, context); }
#endif
    /* lease stays native-owned until reply/cancel, NOT resolution */
}
static napi_value abort_call(napi_env env, napi_callback_info info) {
    napi_value self; size_t argc = 0; void *data = NULL;
    if (napi_get_cb_info(env, info, &argc, NULL, &self, &data) != napi_ok) return fail(env);
    struct node_call *c = data;
    if (!main_thread() || c->owner->env != env) return fail(env);
    finish(c); return undefined(env);
}
static napi_value authorize(napi_env env, napi_callback_info info) {
    napi_value args[3], self, promise; size_t argc = 3; void *data = NULL;
    if (napi_get_cb_info(env, info, &argc, args, &self, &data) != napi_ok) return fail(env);
    struct node_call *c = data; struct node_server *s = c->owner;
    if (argc != 3 || !instance(env, self, &call_tag, c) || s->env != env || !s->live || !c->live || c->started || s->operation || s->clock_busy) return fail(env);
    s->operation = true; struct ha_binding binding = {0}; uint64_t deadline = 0;
    napi_value signal_constructor, global, flag; bool authentic = false, aborted = true;
    bool ok = exact(env, args[0], 5) && text(env, args[0], "requestId", binding.request_id, sizeof(binding.request_id)) &&
        text(env, args[0], "intentDigest", binding.intent_digest, sizeof(binding.intent_digest)) && text(env, args[0], "decision", binding.decision, sizeof(binding.decision)) &&
        text(env, args[0], "ownerId", binding.owner_id, sizeof(binding.owner_id)) && text(env, args[0], "policyDigest", binding.policy_digest, sizeof(binding.policy_digest)) &&
        !strcmp(binding.request_id, c->id) && !strcmp(binding.decision, c->decision) && integer(env, args[1], &deadline) &&
        napi_get_global(env, &global) == napi_ok && field(env, global, "AbortSignal", &signal_constructor) &&
        napi_instanceof(env, args[2], signal_constructor, &authentic) == napi_ok && authentic && field(env, args[2], "aborted", &flag) &&
        napi_get_value_bool(env, flag, &aborted) == napi_ok && !aborted;
    if (!ok || napi_create_promise(env, &c->deferred, &promise) != napi_ok) goto failed;
    c->started = true;
    napi_value listener, event, add, result;
    if (napi_create_function(env, "abort", NAPI_AUTO_LENGTH, abort_call, c, &listener) != napi_ok ||
        reference(env, args[2], 1, &c->signal) != napi_ok || reference(env, listener, 1, &c->listener) != napi_ok ||
        napi_create_string_utf8(env, "abort", NAPI_AUTO_LENGTH, &event) != napi_ok || !field(env, args[2], "addEventListener", &add)) goto failed;
    napi_value event_args[] = {event, listener};
    if (napi_call_function(env, args[2], add, 2, event_args, &result) != napi_ok || !c->live) goto failed;
    int r = ha_authorize(c->call, &binding, deadline, authorized, c);
    if (r < 0) { finish(c); settle(c, NULL); }
    s->operation = false; return promise;
failed:
    s->operation = false; finish(c); close_server(s); return fail(env);
}
static napi_value cancel(napi_env env, napi_callback_info info) {
    napi_value self; size_t argc = 0; void *data = NULL;
    if (napi_get_cb_info(env, info, &argc, NULL, &self, &data) != napi_ok) return fail(env);
    struct node_call *c = data;
    if (!instance(env, self, &call_tag, c) || c->owner->env != env || c->owner->operation || c->owner->clock_busy) return fail(env);
    finish(c); return undefined(env);
}
static napi_value reply(napi_env env, napi_callback_info info) {
    napi_value arg, self; size_t argc = 1; void *data = NULL;
    if (napi_get_cb_info(env, info, &argc, &arg, &self, &data) != napi_ok) return fail(env);
    struct node_call *c = data; struct node_server *s = c->owner;
    if (argc != 1 || !instance(env, self, &call_tag, c) || s->env != env || !c->live || !s->live || s->operation || s->clock_busy) return fail(env);
    s->operation = true;
    char state[33], receipt[33], digest[65], summary[HA_SUMMARY_BYTES + 1u];
    struct ha_reply projection = { .phase = state, .receipt_id = receipt, .intent_digest = digest, .summary_json = summary };
    bool ok = exact(env, arg, c->decision[0] ? 2u : 3u) && text(env, arg, "phase", state, sizeof(state));
    if (c->decision[0]) ok = ok && text(env, arg, "receiptId", receipt, sizeof(receipt));
    else ok = ok && text(env, arg, "intentDigest", digest, sizeof(digest)) && text(env, arg, "summary", summary, sizeof(summary));
    int r = ok ? ha_call_reply(c->call, &projection) : -EACCES;
    /* Settlement and reply attempt precede lease release, even on send error. */
    finish(c); s->operation = false;
    if (r < 0) { close_server(s); return fail(env); } return undefined(env);
}
static void dispatch(ha_call *call, const char *id, const char *decision, void *context) {
    struct node_server *s = context; napi_env env = s->env; napi_value object, callback, receiver, result, request, choice, parent;
    struct node_call *c = s->state->calls_used < HA_MAX_HANDLES ? calloc(1, sizeof(*c)) : NULL;
#ifdef HA_TEST
    if (node_fault == 6u) { node_fault = 0; free(c); c = NULL; }
#endif
    if (!c) { ha_call_cancel(call); close_server(s); return; }
    s->state->calls_used++;
    *c = (struct node_call){ .owner = s, .call = call, .live = true, .next = s->calls }; s->calls = c;
    memcpy(c->id, id, 33u); if (decision) memcpy(c->decision, decision, strlen(decision) + 1u);
    if (napi_create_object(env, &object) != napi_ok || napi_type_tag_object(env, object, &call_tag) != napi_ok ||
        !wrap(env, object, c, collected, s->state) || !method(env, object, "authorize", authorize, c) ||
        !method(env, object, "reply", reply, c) || !method(env, object, "cancel", cancel, c) || napi_object_freeze(env, object) != napi_ok ||
        reference(env, object, 1, &c->self) != napi_ok || napi_get_reference_value(env, s->self, &parent) != napi_ok ||
        reference(env, parent, 1, &c->parent) != napi_ok || napi_get_reference_value(env, decision ? s->decide : s->inspect, &callback) != napi_ok ||
        napi_get_undefined(env, &receiver) != napi_ok || napi_create_string_utf8(env, id, NAPI_AUTO_LENGTH, &request) != napi_ok) goto failed;
    napi_value args[] = {object, request, NULL}; size_t count = 2;
    if (decision) { if (napi_create_string_utf8(env, decision, NAPI_AUTO_LENGTH, &choice) != napi_ok) goto failed; args[2] = choice; count = 3; }
    if (napi_call_function(env, receiver, callback, count, args, &result) != napi_ok) goto failed;
    return;
failed:
    finish(c); close_server(s);
}
static void inspect_call(ha_call *call, const char *id, void *context) { dispatch(call, id, NULL, context); }
static void decide_call(ha_call *call, const char *id, const char *decision, void *context) { dispatch(call, id, decision, context); }
static napi_value process_once(napi_env env, napi_callback_info info) {
    napi_value self, result; size_t argc = 0; void *data = NULL;
    if (napi_get_cb_info(env, info, &argc, NULL, &self, &data) != napi_ok) return fail(env);
    struct node_server *s = data;
    if (!instance(env, self, &server_tag, s) || s->env != env || !s->live || s->processing || s->operation || s->clock_busy) return fail(env);
    s->processing = true; int r = ha_server_process(s->server, 0); s->processing = false;
    if (r < 0) { close_server(s); return fail(env); }
    if (napi_create_int32(env, r, &result) != napi_ok) { close_server(s); return fail(env); } return result;
}
static napi_value close_native(napi_env env, napi_callback_info info) {
    napi_value self; size_t argc = 0; void *data = NULL;
    if (napi_get_cb_info(env, info, &argc, NULL, &self, &data) != napi_ok) return fail(env);
    struct node_server *s = data;
    if (!instance(env, self, &server_tag, s) || s->env != env || s->processing || s->operation || s->clock_busy) return fail(env);
    close_server(s); return undefined(env);
}
static void cleanup(void *data) {
    struct node_state *state = data;
    for (struct node_server *s = state->servers; s; s = s->next) { s->shutting_down = true; close_server(s); }
    drop(state->env, &state->anchors);
    /* Wrapper finalizers can still run after cleanup hooks. Keep bounded C
     * tombstones alive through environment teardown, just like native arenas. */
}
static void release_state(struct node_state *state) {
    if (!state->finalized || state->wrappers) return;
    for (struct node_server *s = state->servers; s;) { struct node_server *next = s->next; for (struct node_call *c = s->calls; c;) { struct node_call *n = c->next; free(c); c = n; } free(s); s = next; }
    free(state);
}
static void state_finalized(napi_env env, void *data, void *hint) {
    (void)env; (void)hint; struct node_state *state = data; state->finalized = true; release_state(state);
}
static napi_value create_server(napi_env env, napi_callback_info info) {
    napi_value args[3], self, object, fn; size_t argc = 3; void *unused = NULL; struct node_state *state = NULL;
    if (!main_thread() || napi_get_cb_info(env, info, &argc, args, &self, &unused) != napi_ok || napi_get_instance_data(env, (void **)&state) != napi_ok || !state) return fail(env);
#ifndef HA_TEST
    if (argc != 2 || getuid() != 0 || geteuid() != 0) return fail(env);
#else
    if (argc != 3) return fail(env);
#endif
    if (state->servers_used >= HA_MAX_SERVERS || state->constructing) return fail(env);
    struct node_server *s = calloc(1, sizeof(*s)); if (!s) return fail(env);
    state->servers_used++; state->constructing = true;
    *s = (struct node_server){ .env = env, .state = state, .live = true, .next = state->servers }; state->servers = s;
    struct ha_config config = { .now_ms = clock_now, .clock_context = s }; uint64_t uid = 0, timeout = 0; napi_value value;
    if (!exact(env, args[0], 5) || !exact(env, args[1], 2) || !field(env, args[0], "ownerUid", &value) || !integer(env, value, &uid) || uid > UINT32_MAX ||
        !text(env, args[0], "ownerId", config.owner_id, sizeof(config.owner_id)) || !text(env, args[0], "policyDigest", config.policy_digest, sizeof(config.policy_digest)) ||
        !field(env, args[0], "authorityTimeoutMs", &value) || !integer(env, value, &timeout) || timeout > UINT32_MAX ||
        !field(env, args[0], "clock", &fn) || reference(env, fn, 0, &s->clock) != napi_ok ||
        !field(env, args[1], "inspect", &fn) || reference(env, fn, 0, &s->inspect) != napi_ok ||
        !field(env, args[1], "decide", &fn) || reference(env, fn, 0, &s->decide) != napi_ok) goto failed;
    config.owner_uid = (uid_t)uid; config.authority_timeout_ms = (uint32_t)timeout;
    struct ha_core_ops ops = { .on_inspect = inspect_call, .on_decide = decide_call, .context = s };
#ifdef HA_TEST
    char address[4096]; sd_bus *bus = NULL;
    if (!string(env, args[2], address, sizeof(address)) || sd_bus_new(&bus) < 0) goto failed;
    int r = sd_bus_set_address(bus, address);
    if (r >= 0) r = sd_bus_set_bus_client(bus, 1);
    if (r >= 0) r = sd_bus_start(bus);
    if (r >= 0) r = ha_test_server_new(&config, &ops, bus, &s->server);
    sd_bus_unref(bus);
#else
    int r = ha_server_new(&config, &ops, &s->server);
#endif
    if (r < 0 || !s->live || napi_create_object(env, &object) != napi_ok || napi_type_tag_object(env, object, &server_tag) != napi_ok ||
        !wrap(env, object, s, server_collected, state) || !method(env, object, "processOnce", process_once, s) ||
        !method(env, object, "close", close_native, s) || napi_object_freeze(env, object) != napi_ok) goto failed;
    /* WeakMap ephemeron ownership prevents a callback->server reference cycle
     * from rooting an otherwise unreachable server. Active calls pin parent. */
    napi_value anchors, set, retained, ignored;
    if (reference(env, object, 0, &s->self) != napi_ok || napi_get_reference_value(env, state->anchors, &anchors) != napi_ok ||
        !field(env, anchors, "set", &set) || napi_create_object(env, &retained) != napi_ok ||
        napi_set_named_property(env, retained, "config", args[0]) != napi_ok || napi_set_named_property(env, retained, "callbacks", args[1]) != napi_ok) goto failed;
    napi_value keep[] = {object, retained};
    if (napi_call_function(env, anchors, set, 2, keep, &ignored) != napi_ok) goto failed;
    state->constructing = false; return object;
failed:
    state->constructing = false; close_server(s); return fail(env);
}
#ifdef HA_TEST
static napi_value test_fault(napi_env env, napi_callback_info info) {
    napi_value arg, self; size_t argc = 1; void *data = NULL; uint64_t n = 0;
    if (!main_thread() || napi_get_cb_info(env, info, &argc, &arg, &self, &data) != napi_ok || argc != 1 || !integer(env, arg, &n) || n > 8u) return fail(env);
    if (n <= 4u) ha_test_fail_next((enum ha_test_fault)n); else node_fault = (unsigned)n;
    return undefined(env);
}
#endif
/* Node 18/20/22 macros define this export without declaring it first. */
NAPI_MODULE_EXPORT int32_t NODE_API_MODULE_GET_API_VERSION(void);
NAPI_MODULE_INIT() {
    if (!main_thread()) return fail(env);
    struct node_state *state = calloc(1, sizeof(*state)); if (!state) return fail(env);
    state->env = env;
    napi_value global, constructor, anchors;
    if (napi_get_global(env, &global) != napi_ok || !field(env, global, "WeakMap", &constructor) ||
        napi_new_instance(env, constructor, 0, NULL, &anchors) != napi_ok || reference(env, anchors, 1, &state->anchors) != napi_ok) { free(state); return fail(env); }
    if (napi_set_instance_data(env, state, state_finalized, NULL) != napi_ok || napi_add_env_cleanup_hook(env, cleanup, state) != napi_ok ||
        !method(env, exports, "createServer", create_server, NULL)) return fail(env);
#ifdef HA_TEST
    if (!method(env, exports, "testFault", test_fault, NULL)) return fail(env);
#endif
    if (napi_object_freeze(env, exports) != napi_ok) return fail(env);
    return exports;
}
