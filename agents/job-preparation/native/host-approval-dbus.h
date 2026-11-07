/* Private native composition only. No serialized handles or installation API. */
#ifndef BUZZ_HOST_APPROVAL_DBUS_H
#define BUZZ_HOST_APPROVAL_DBUS_H
#include <stdint.h>
#include <sys/types.h>

#define HA_NAME "org.buzz.HostApproval1"
#define HA_PATH "/org/buzz/HostApproval1"
#define HA_INTERFACE "org.buzz.HostApproval1"
#define HA_APPROVE_ACTION "org.buzz.host-approval.approve"
#define HA_REJECT_ACTION "org.buzz.host-approval.reject"
#define HA_MAX_INFLIGHT 64u
#define HA_MAX_HANDLES 4096u
#define HA_MAX_SERVERS 8u
#define HA_SUMMARY_BYTES 16384u
#define HA_METADATA_BYTES 4096u

typedef struct ha_server ha_server;
typedef struct ha_call ha_call;
typedef struct ha_lease ha_lease;
struct ha_config {
    uid_t owner_uid;                 /* Private, explicit owner mapping. */
    char owner_id[129];
    char policy_digest[65];
    uint32_t authority_timeout_ms;   /* 1..60000; never extends a call. */
    int (*now_ms)(void *context, uint64_t *epoch_ms);
    void *clock_context;
};
struct ha_binding {
    char request_id[33];
    char intent_digest[65];
    char decision[8];
    char owner_id[129];
    char policy_digest[65];
};
struct ha_reply {
    const char *intent_digest;       /* Inspect only: empty or lowercase hex64. */
    const char *summary_json;        /* Inspect: opaque escaped-renderer data. */
    const char *phase;
    const char *receipt_id;          /* Decide only: empty or lowercase hex32. */
};
struct ha_core_ops {
    void (*on_inspect)(ha_call *call, const char *request_id, void *context);
    void (*on_decide)(ha_call *call, const char *request_id, const char *decision, void *context);
    void *context;
};
typedef void (*ha_completion)(ha_call *call, ha_lease *lease, void *context);

/* Single-threaded, event-loop-affine. Successful construction explicitly attaches
 * the two methods to the FIXED system bus; import/build never calls this API. */
int ha_server_new(const struct ha_config *, const struct ha_core_ops *, ha_server **);
int ha_server_process(ha_server *, uint32_t timeout_ms);
void ha_server_free(ha_server *);
int ha_call_reply(ha_call *, const struct ha_reply *);
int ha_authorize(ha_call *, const struct ha_binding *, uint64_t absolute_deadline_ms,
                 ha_completion, void *context);
void ha_call_cancel(ha_call *);
int ha_lease_valid(ha_lease *);
void ha_lease_free(ha_lease *);

/* Private fixture transport/fault injection does not exist in production builds. */
#ifdef HA_TEST
#include <systemd/sd-bus.h>
enum ha_test_fault { HA_FAULT_NONE, HA_FAULT_ALLOC, HA_FAULT_SEND, HA_FAULT_WATCH, HA_FAULT_CREDS };
int ha_test_server_new(const struct ha_config *, const struct ha_core_ops *, sd_bus *, ha_server **);
void ha_test_fail_next(enum ha_test_fault);
#endif
#endif
