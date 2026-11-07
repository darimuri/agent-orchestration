/* Real disposable broker + fake Polkit. ALL session/TTY/auth/core claims here
 * are SYNTHETIC. No system bus, real Polkit, root store or executor is used. */
#include "../../job-preparation/native/host-approval-dbus.h"
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <systemd/sd-bus.h>

#define PK "org.freedesktop.PolicyKit1"
#define PP "/org/freedesktop/PolicyKit1/Authority"
#define PI "org.freedesktop.PolicyKit1.Authority"
#define EPOCH UINT64_C(1794025000000)
#define MAX_REQUESTS 160u
static const char *scenario;
static const char *address;
static const char *client_name;
static uint64_t clock_value = EPOCH;
static sd_bus *authority_bus, *server_bus, *client_bus;
static ha_server *server;
static unsigned checks, cancellations, core_inspects, core_decides, completions, grants, denies, fake_responses;
static bool hold_success;
static ha_call *last_call;
static ha_lease *last_lease;
static sd_bus_message *held[MAX_REQUESTS];
static char cancel_ids[MAX_REQUESTS][96];
static char subjects[MAX_REQUESTS][256];
struct response { bool done, error; char phase[40]; };
static struct response responses[MAX_REQUESTS];

static bool is(const char *name) { return !strcmp(scenario, name); }
static int clock_now(void *context, uint64_t *out) { (void)context; *out = clock_value; return is("clock_failure") && checks >= 2u ? -EIO : 0; }
static void fill(char *out, size_t length, char value) { memset(out, value, length); out[length] = '\0'; }
static sd_bus *connect_bus(void) {
    sd_bus *bus = NULL;
    assert(sd_bus_new(&bus) >= 0); assert(sd_bus_set_address(bus, address) >= 0); assert(sd_bus_set_bus_client(bus, 1) >= 0);
    assert(sd_bus_set_method_call_timeout(bus, UINT64_C(200000)) >= 0); assert(sd_bus_start(bus) >= 0);
    const char *unique = NULL; assert(sd_bus_get_unique_name(bus, &unique) >= 0); assert(unique && unique[0] == ':'); return bus;
}
static int reply_result(sd_bus_message *call, int authorized, int challenge, const char *key, const char *value) {
    sd_bus_message *reply = NULL;
    assert(sd_bus_message_new_method_return(call, &reply) >= 0);
    assert(sd_bus_message_open_container(reply, 'r', "bba{ss}") >= 0); assert(sd_bus_message_append(reply, "bb", authorized, challenge) >= 0);
    assert(sd_bus_message_open_container(reply, 'a', "{ss}") >= 0);
    if (key) { assert(sd_bus_message_open_container(reply, 'e', "ss") >= 0); assert(sd_bus_message_append(reply, "ss", key, value) >= 0); assert(sd_bus_message_close_container(reply) >= 0); }
    assert(sd_bus_message_close_container(reply) >= 0); assert(sd_bus_message_close_container(reply) >= 0);
    int r = sd_bus_send(authority_bus, reply, NULL); sd_bus_message_unref(reply); return r;
}
static int fake_check(sd_bus_message *m, void *context, sd_bus_error *error) {
    const char *kind = NULL, *key = NULL, *subject = NULL, *action = NULL, *cancellation = NULL; uint32_t flags = 99u;
    (void)context; (void)error; assert(checks < MAX_REQUESTS);
    assert(sd_bus_message_has_signature(m, "(sa{sv})sa{ss}us"));
    assert(sd_bus_message_enter_container(m, 'r', "sa{sv}") > 0); assert(sd_bus_message_read(m, "s", &kind) > 0); assert(!strcmp(kind, "system-bus-name"));
    assert(sd_bus_message_enter_container(m, 'a', "{sv}") > 0); assert(sd_bus_message_enter_container(m, 'e', "sv") > 0);
    assert(sd_bus_message_read(m, "s", &key) > 0 && !strcmp(key, "name")); assert(sd_bus_message_enter_container(m, 'v', "s") > 0); assert(sd_bus_message_read(m, "s", &subject) > 0);
    assert(!strcmp(subject, client_name)); assert(sd_bus_message_exit_container(m) >= 0); assert(sd_bus_message_exit_container(m) >= 0);
    assert(sd_bus_message_at_end(m, 0) > 0); assert(sd_bus_message_exit_container(m) >= 0); assert(sd_bus_message_exit_container(m) >= 0);
    assert(sd_bus_message_read(m, "s", &action) > 0); assert(!strcmp(action, is("reject") ? HA_REJECT_ACTION : HA_APPROVE_ACTION));
    assert(sd_bus_message_enter_container(m, 'a', "{ss}") > 0);
    unsigned seen = 0;
    while (sd_bus_message_enter_container(m, 'e', "ss") > 0) {
        const char *value = NULL; assert(sd_bus_message_read(m, "ss", &key, &value) > 0);
        unsigned bit = 0;
        if (!strcmp(key, "requestId")) { bit = 1u; assert(strlen(value) == 32u); }
        else if (!strcmp(key, "intentDigest")) { bit = 2u; assert(strlen(value) == 64u && value[0] == 'a'); }
        else if (!strcmp(key, "decision")) { bit = 4u; assert(!strcmp(value, is("reject") ? "reject" : "approve")); }
        else if (!strcmp(key, "ownerId")) { bit = 8u; assert(!strcmp(value, "fixture-owner")); }
        else if (!strcmp(key, "policyDigest")) { bit = 16u; assert(strlen(value) == 64u && value[0] == 'b'); }
        else assert(false);
        assert(!(seen & bit)); seen |= bit; assert(sd_bus_message_exit_container(m) >= 0);
    }
    assert(seen == 31u); assert(sd_bus_message_exit_container(m) >= 0); assert(sd_bus_message_read(m, "us", &flags, &cancellation) > 0); assert(sd_bus_message_at_end(m, 1) > 0);
    assert(flags <= 1u && strlen(cancellation) < 96u && cancellation[0]);
    for (unsigned i = 0; i < checks; i++) assert(strcmp(cancel_ids[i], cancellation));
    memcpy(cancel_ids[checks], cancellation, strlen(cancellation) + 1u); memcpy(subjects[checks], subject, strlen(subject) + 1u); checks++;
    if (is("authority_error")) return sd_bus_reply_method_errorf(m, "org.freedesktop.PolicyKit1.Error.Failed", "%s", "PRIVATE_FAKE_ERROR_CANARY");
    if (is("malformed_authority")) return sd_bus_reply_method_return(m, "s", "not-a-result");
    if (is("implicit_yes")) return reply_result(m, 1, 0, NULL, NULL);
    if (is("denied")) return reply_result(m, 0, 0, NULL, NULL);
    if (!flags) return reply_result(m, 0, 1, is("retained") ? "polkit.retains_authorization_after_challenge" : NULL, "1");
    if (is("challenge")) return reply_result(m, 0, 1, NULL, NULL);
    if (is("cached_id")) return reply_result(m, 1, 0, "polkit.temporary_authorization_id", "fake-cache");
    if (is("lease_allocation")) ha_test_fail_next(HA_FAULT_ALLOC);
    if (is("cancel") || is("disconnect") || is("replacement") || is("timeout") || is("regression") || is("clock_failure") || is("teardown") || is("duplicate") || is("inflight_bound") || is("broker_disconnect") || is("short_deadline")) {
        held[checks - 1u] = sd_bus_message_ref(m); return 1;
    }
    return reply_result(m, 1, 0, NULL, NULL);
}
static int fake_cancel(sd_bus_message *m, void *context, sd_bus_error *error) {
    const char *id = NULL; bool owned = false; (void)context; (void)error;
    assert(sd_bus_message_read(m, "s", &id) > 0);
    for (unsigned i = 0; i < checks; i++) if (!strcmp(cancel_ids[i], id)) owned = true;
    assert(owned); cancellations++; return sd_bus_reply_method_return(m, "");
}
static const sd_bus_vtable fake_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("CheckAuthorization", "(sa{sv})sa{ss}us", "(bba{ss})", fake_check, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("CancelCheckAuthorization", "s", "", fake_cancel, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_VTABLE_END
};
static void completion(ha_call *call, ha_lease *lease, void *context) {
    (void)context; completions++; last_call = call;
    if (!lease) { denies++; return; }
    last_lease = lease; assert(ha_lease_valid(lease)); grants++;
    assert(ha_authorize(call, &(struct ha_binding){0}, EPOCH + 5000u, completion, NULL) < 0);
    if (hold_success) return;
    struct ha_reply reply = { .phase = is("reject") ? "rejected" : "approved", .receipt_id = "11111111111111111111111111111111" };
    assert(ha_call_reply(call, &reply) == 0); fake_responses++; assert(ha_call_reply(call, &reply) < 0); assert(!ha_lease_valid(lease)); ha_lease_free(lease); ha_lease_free(lease);
}
static void inspect_core(ha_call *call, const char *id, void *context) {
    (void)id; (void)context; core_inspects++; last_call = call;
    assert(ha_authorize(call, &(struct ha_binding){0}, EPOCH + 5000u, completion, NULL) < 0);
    char digest[65]; fill(digest, 64u, 'a');
    char oversize[HA_SUMMARY_BYTES + 2u]; fill(oversize, HA_SUMMARY_BYTES + 1u, 'x');
    struct ha_reply reply = { .intent_digest = digest, .summary_json = is("output_bound") ? oversize : "{\"fixtureOnly\":true}", .phase = "pending" };
    if (is("output_bound")) { assert(ha_call_reply(call, &reply) < 0); ha_call_cancel(call); }
    else { assert(ha_call_reply(call, &reply) == 0); assert(ha_call_reply(call, &reply) < 0); }
}
static void decide_core(ha_call *call, const char *id, const char *decision, void *context) {
    (void)context; core_decides++; last_call = call;
    struct ha_binding binding = {0}; memcpy(binding.request_id, id, 33u); fill(binding.intent_digest, 64u, 'a');
    memcpy(binding.decision, decision, strlen(decision) + 1u); memcpy(binding.owner_id, "fixture-owner", sizeof("fixture-owner")); fill(binding.policy_digest, 64u, 'b');
    if (is("binding_owner")) memcpy(binding.owner_id, "wrong", sizeof("wrong"));
    if (is("binding_policy")) binding.policy_digest[0] = 'c';
    if (is("binding_request")) binding.request_id[0] = binding.request_id[0] == '1' ? '2' : '1';
    if (is("binding_decision")) memcpy(binding.decision, "reject", sizeof("reject"));
    if (is("allocation")) ha_test_fail_next(HA_FAULT_ALLOC);
    if (is("send")) ha_test_fail_next(HA_FAULT_SEND);
    uint64_t deadline = is("short_deadline") ? EPOCH + 2u : is("past_deadline") ? EPOCH : EPOCH + 5000u;
    int r = ha_authorize(call, &binding, deadline, completion, NULL);
    if (is("binding_owner") || is("binding_policy") || is("binding_request") || is("binding_decision") || is("past_deadline")) { assert(r < 0); ha_call_cancel(call); }
}
static int got_response(sd_bus_message *m, void *context, sd_bus_error *error) {
    struct response *result = context; (void)error; assert(!result->done); result->done = true; result->error = sd_bus_message_is_method_error(m, NULL) > 0;
    if (result->error) { const sd_bus_error *e = sd_bus_message_get_error(m); assert(!e || !e->message || !strstr(e->message, "PRIVATE_FAKE_ERROR_CANARY")); }
    else { const char *phase = NULL; assert(sd_bus_message_read(m, "s", &phase) > 0); if (strlen(phase) < sizeof(result->phase)) memcpy(result->phase, phase, strlen(phase) + 1u); }
    return 0;
}
static void request(unsigned index, const char *id, const char *method_name) {
    assert(index < MAX_REQUESTS); sd_bus_message *m = NULL;
    const char *object = is("wrong_path") ? "/org/buzz/Wrong" : HA_PATH, *interface = is("wrong_interface") ? "org.buzz.Wrong" : HA_INTERFACE;
    assert(sd_bus_message_new_method_call(client_bus, &m, HA_NAME, object, interface, method_name) >= 0);
    if (!strcmp(method_name, "Inspect")) assert(sd_bus_message_append(m, "s", id) >= 0);
    else assert(sd_bus_message_append(m, "ss", id, is("malformed_decision") ? "expire" : is("reject") ? "reject" : "approve") >= 0);
    if (is("spoof_body")) assert(sd_bus_message_append(m, "s", ":1.999") >= 0);
    if (is("spoof_sender")) assert(sd_bus_message_set_sender(m, ":1.999") >= 0);
    assert(sd_bus_call_async(client_bus, NULL, m, got_response, &responses[index], UINT64_C(5000000)) >= 0); sd_bus_message_unref(m);
}
static void pump(unsigned rounds) {
    for (unsigned i = 0; i < rounds; i++) {
        int r;
        do { r = sd_bus_process(authority_bus, NULL); assert(r >= 0); } while (r > 0);
        if (server) (void)ha_server_process(server, 0u);
        if (client_bus) { do { r = sd_bus_process(client_bus, NULL); assert(r >= 0); } while (r > 0); }
        (void)usleep(1000u);
    }
}
int main(int argc, char **argv) {
    assert(argc == 3); address = argv[1]; scenario = argv[2]; assert(!strncmp(address, "unix:", 5u));
    assert(getuid() != 0); authority_bus = connect_bus(); server_bus = connect_bus(); client_bus = connect_bus();
    assert(sd_bus_get_unique_name(client_bus, &client_name) >= 0);
    /* Regress the broker credential contract before exercising the adapter.
     * UID is proc augmentation; UnixUserID from D-Bus is EUID. */
    sd_bus_creds *broker_creds = NULL; uid_t broker_uid = (uid_t)-1;
    assert(sd_bus_get_name_creds(server_bus, client_name, SD_BUS_CREDS_EUID | SD_BUS_CREDS_PID, &broker_creds) >= 0);
    assert(sd_bus_creds_get_euid(broker_creds, &broker_uid) >= 0 && broker_uid == geteuid());
    assert(!(sd_bus_creds_get_mask(broker_creds) & SD_BUS_CREDS_UID));
    sd_bus_creds_unref(broker_creds);
    assert(sd_bus_request_name(authority_bus, PK, SD_BUS_NAME_ALLOW_REPLACEMENT) > 0);
    sd_bus_slot *pk_slot = NULL; assert(sd_bus_add_object_vtable(authority_bus, &pk_slot, PP, PI, fake_vtable, NULL) >= 0);
    struct ha_config config = { .owner_uid = getuid(), .authority_timeout_ms = 5000u, .now_ms = clock_now };
    memcpy(config.owner_id, "fixture-owner", sizeof("fixture-owner")); fill(config.policy_digest, 64u, 'b');
    struct ha_core_ops core = { .on_inspect = inspect_core, .on_decide = decide_core };
    if (is("wrong_owner")) config.owner_uid++;
    if (is("watch")) ha_test_fail_next(HA_FAULT_WATCH);
    int created = ha_test_server_new(&config, &core, server_bus, &server);
    if (is("watch")) { assert(created < 0 && server == NULL); goto cleanup; }
    assert(created == 0 && server != NULL);
    if (is("credentials")) ha_test_fail_next(HA_FAULT_CREDS);
    hold_success = is("lease_disconnect") || is("lease_replacement") || is("lease_free") || is("service_name_loss") || is("stale_handle");
    const char *id = is("malformed_id") ? "../bad" : "11111111111111111111111111111111";
    const char *method_name = is("inspect") || is("output_bound") ? "Inspect" : is("unknown_method") ? "Reserve" : "Decide";
    request(0u, id, method_name);
    if (is("duplicate")) request(1u, id, "Decide");
    if (is("distinct")) request(1u, "22222222222222222222222222222222", "Decide");
    if (is("inflight_bound")) for (unsigned i = 1; i <= HA_MAX_INFLIGHT; i++) { char rid[33]; assert(snprintf(rid, sizeof(rid), "%032x", i + 1u) == 32); request(i, rid, "Decide"); }
    pump(is("inflight_bound") ? 200u : 80u);
    if (is("inspect") || is("output_bound")) { assert(core_inspects == 1u && core_decides == 0u && checks == 0u && grants == 0u && responses[0].done); goto finish; }
    if (is("malformed_id") || is("malformed_decision") || is("unknown_method") || is("wrong_path") || is("wrong_interface") || is("spoof_body") || is("wrong_owner") || is("credentials")) { pump(250u); assert(core_decides == 0u && grants == 0u && checks == 0u); goto finish; }
    if (is("cancel") || is("duplicate") || is("inflight_bound")) {
        assert(last_call); if (is("duplicate")) assert(core_decides == 1u && responses[1].done && responses[1].error);
        if (is("inflight_bound")) assert(core_decides == HA_MAX_INFLIGHT && responses[HA_MAX_INFLIGHT].done && responses[HA_MAX_INFLIGHT].error);
        ha_call_cancel(last_call); ha_call_cancel(last_call); pump(40u); assert(cancellations >= 1u && grants == 0u);
    } else if (is("disconnect")) { client_bus = sd_bus_close_unref(client_bus); pump(60u); assert(denies == 1u && grants == 0u); }
    else if (is("broker_disconnect")) { sd_bus_close(server_bus); pump(20u); assert(grants == 0u); }
    else if (is("replacement") || is("lease_replacement")) {
        sd_bus *replacement = connect_bus(); assert(sd_bus_request_name(replacement, PK, SD_BUS_NAME_REPLACE_EXISTING) > 0);
        if (last_lease) { assert(!ha_lease_valid(last_lease)); } pump(30u); assert(!last_lease || !ha_lease_valid(last_lease)); sd_bus_close_unref(replacement);
    } else if (is("timeout") || is("short_deadline") || is("regression") || is("clock_failure")) {
        clock_value = is("regression") ? EPOCH - 1u : is("short_deadline") ? EPOCH + 2u : EPOCH + 5000u;
        pump(30u); assert(grants == 0u && denies == 1u);
    } else if (is("teardown")) { ha_server_free(server); pump(20u); assert(denies == 1u && grants == 0u); }
    else if (is("lease_disconnect")) { assert(last_lease && ha_lease_valid(last_lease)); client_bus = sd_bus_close_unref(client_bus); assert(!ha_lease_valid(last_lease)); pump(10u); }
    else if (is("service_name_loss")) { assert(last_lease); assert(sd_bus_release_name(server_bus, HA_NAME) >= 0); assert(!ha_lease_valid(last_lease)); }
    else if (is("lease_free")) { assert(last_lease && ha_lease_valid(last_lease)); ha_lease_free(last_lease); ha_lease_free(last_lease); assert(!ha_lease_valid(last_lease)); }
    else if (is("stale_handle")) {
        ha_lease *old_lease = last_lease; ha_call *old_call = last_call; assert(old_lease); ha_server_free(server); assert(!ha_lease_valid(old_lease)); ha_lease_free(old_lease); ha_call_cancel(old_call);
        server_bus = sd_bus_unref(server_bus); server_bus = connect_bus(); assert(ha_test_server_new(&config, &core, server_bus, &server) == 0);
        hold_success = false; request(1u, "22222222222222222222222222222222", "Decide"); pump(80u); assert(grants == 2u && !ha_lease_valid(old_lease) && old_lease != last_lease);
    } else if (is("happy") || is("reject") || is("spoof_sender") || is("distinct")) {
        if (!grants) fprintf(stderr, "synthetic flow: core=%u checks=%u completions=%u denies=%u responses=%u\n", core_decides, checks, completions, denies, fake_responses);
        assert(core_decides == (is("distinct") ? 2u : 1u) && denies == 0u);
        assert(grants == (is("distinct") ? 2u : 1u)); assert(fake_responses == grants); assert(checks == grants * 2u); assert(responses[0].done && !responses[0].error);
        for (unsigned i = 0; i < checks; i++) assert(!strcmp(subjects[i], client_name));
    } else { assert(grants == 0u && fake_responses == 0u); }
    /* Deliver late success after cancellation/teardown; it cannot resurrect a
     * completed operation or an instance-local lease. */
    if (!is("inflight_bound")) for (unsigned i = 0; i < checks; i++) if (held[i]) { (void)reply_result(held[i], 1, 0, NULL, NULL); }
    pump(20u);
    if (!is("inflight_bound")) assert(completions <= (is("distinct") || is("stale_handle") ? 2u : 1u));
finish:
    ha_server_free(server); assert(!last_lease || !ha_lease_valid(last_lease)); ha_call_cancel(last_call); ha_lease_free(last_lease); ha_server_free(server);
cleanup:
    for (unsigned i = 0; i < MAX_REQUESTS; i++) sd_bus_message_unref(held[i]);
    sd_bus_slot_unref(pk_slot); sd_bus_close_unref(client_bus); sd_bus_close_unref(server_bus); sd_bus_close_unref(authority_bus);
    puts("synthetic disposable-broker authority fixtures PASS; NOT live Polkit/TTY/root/store acceptance"); return 0;
}
