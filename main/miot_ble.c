/*
 * BLE central: connect to Xiaomi/Loock lock and execute SecurityChip authentication & operate.
 * Protocol aligned with official Mijia APK (BleSecurityChipLoginConnector, k61, l8e, bb1, ag2).
 */
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include "esp_log.h"
#include "nvs_flash.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/ble_uuid.h"
#include "host/util/util.h"
#include "services/gap/ble_svc_gap.h"
#include "security_chip.h"
#include "miot_ble.h"
#include "lock_config.h"
#include "mqtt_handler.h"

static const char *TAG = "MIOT_BLE";

static uint8_t own_addr_type;
static uint16_t conn_handle = BLE_HS_CONN_HANDLE_NONE;
static ble_addr_t peer_addr;
static bool peer_found;

static uint16_t h_auth = 36;          /* 00000010-0000-1000-8000-00805f9b34fb */
static uint16_t h_auth_cccd = 37;
static uint16_t h_channel = 39;       /* 00000016-0000-1000-8000-00805f9b34fb */
static uint16_t h_channel_cccd = 40;
static uint16_t h_lock_write = 49;    /* 00001001-0065-6c62-2e74-6f696d2e696d */
static uint16_t h_lock_op = 51;       /* 00001002-0065-6c62-2e74-6f696d2e696d */
static uint16_t h_lock_log = 54;      /* 00001003-0065-6c62-2e74-6f696d2e696d */
static uint16_t h_battery = 30;       /* 0x2A19 */
static uint16_t h_lock_status = 67;   /* 00002220-0000-6b63-6f6c-2e6b636f6f6c */
static uint16_t h_door_status = 70;   /* 00002222-0000-6b63-6f6c-2e6b636f6f6c */
static uint16_t h_device_write = 103; /* 6e400002-b5a3-f393-e0a9-e50e24dcca9e */

static ble_action_t s_current_action = BLE_ACTION_UNLOCK;
static int s_action_param = 0;
static uint16_t s_loock_seq = 0;

/* High-speed BLE connection parameters: 100% duty cycle scan + 7.5ms-15ms interval */
static const struct ble_gap_conn_params FAST_CONN_PARAMS = {
    .scan_itvl = 16,        /* 10 ms continuous scan */
    .scan_window = 16,      /* 10 ms 100% duty cycle (no missed advertisements) */
    .itvl_min = 6,          /* 7.5 ms (maximum BLE throughput / minimal round-trip latency) */
    .itvl_max = 12,         /* 15 ms */
    .latency = 0,
    .supervision_timeout = 500, /* 5000 ms */
    .min_ce_len = 0,
    .max_ce_len = 0,
};

static bool auth_cccd_enabled = false;
static bool channel_cccd_enabled = false;

static psa_key_id_t app_key_id = 0;
static uint8_t app_pub65[65];
static uint8_t ltmk[32];
static sc_session_t session;

/* Pre-generate ECDH keypair in background while idle for 0-latency unlock trigger */
static void ensure_ecdh_key_ready(void)
{
    if (app_key_id == 0) {
        if (sc_ecdh_generate(&app_key_id, app_pub65) == 0) {
            ESP_LOGI(TAG, "Pre-generated ECDH keypair ready for instant unlock");
        } else {
            ESP_LOGW(TAG, "Failed to pre-generate ECDH keypair");
        }
    }
}

/* Channel RX assembly state */
static uint8_t ch_rx_buf[256];
static size_t ch_rx_len = 0;
static uint16_t ch_rx_expected_frames = 0;
static uint16_t ch_rx_frames_received = 0;
static uint8_t ch_rx_pkg_type = 0;

/* Channel TX state */
static uint8_t  ch_tx_buf[128];
static size_t   ch_tx_len = 0;
static uint16_t ch_tx_frames = 0;
static uint8_t  ch_tx_pkg_type = 0;
static uint16_t ch_tx_handle = 0;

typedef enum {
    ST_IDLE = 0,
    ST_SCAN,
    ST_CONNECT,
    ST_EXCHANGE_MTU,
    ST_DISC_SVCS,
    ST_DISC_CHRS,
    ST_DISC_DSCS,
    ST_SUBSCRIBE_CCCD,
    ST_LOGIN_START_SENT,
    ST_LOGIN_WAIT_PUB,
    ST_LOGIN_SEND_ENC,
    ST_LOGIN_WAIT_OK,
    ST_OPERATE_SENT,
    ST_DONE,
    ST_FAIL,
} st_t;

static st_t state = ST_IDLE;

static void set_state(st_t s)
{
    ESP_LOGI(TAG, "State transition: %d -> %d", (int)state, (int)s);
    state = s;
}

static void handle_failure(const char *reason)
{
    ESP_LOGE(TAG, "BLE operation failed: %s", reason);
    set_state(ST_FAIL);
    if (s_current_action == BLE_ACTION_UNLOCK) {
        mqtt_handler_publish_state("LOCKED");
    }
    if (conn_handle != BLE_HS_CONN_HANDLE_NONE) {
        ble_gap_terminate(conn_handle, BLE_ERR_REM_USER_CONN_TERM);
    }
    set_state(ST_IDLE);
}

static int parse_mac(const char *s, ble_addr_t *addr)
{
    unsigned b[6];
    if (sscanf(s, "%02x:%02x:%02x:%02x:%02x:%02x",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6) {
        return -1;
    }
    addr->type = BLE_ADDR_PUBLIC;
    for (int i = 0; i < 6; i++) {
        addr->val[i] = (uint8_t)b[5 - i];
    }
    return 0;
}

static int write_cmd(uint16_t handle, const uint8_t *data, size_t len, bool rsp)
{
    if (conn_handle == BLE_HS_CONN_HANDLE_NONE || handle == 0) {
        ESP_LOGE(TAG, "write_cmd invalid handle=%d or no connection", handle);
        return -1;
    }
    struct os_mbuf *om = ble_hs_mbuf_from_flat(data, len);
    if (!om) {
        ESP_LOGE(TAG, "Failed to allocate os_mbuf for write (len=%zu)", len);
        return -1;
    }
    int rc;
    if (rsp) {
        rc = ble_gattc_write(conn_handle, handle, om, NULL, NULL);
    } else {
        rc = ble_gattc_write_no_rsp(conn_handle, handle, om);
    }
    ESP_LOGI(TAG, "Write handle=%d len=%u rc=%d (rsp=%d)", handle, (unsigned)len, rc, (int)rsp);
    ESP_LOG_BUFFER_HEX(TAG, data, len);
    return rc;
}

/* Forward declarations */
static int disc_svc(uint16_t conn, const struct ble_gatt_error *error,
                    const struct ble_gatt_svc *svc, void *arg);
static int disc_chr(uint16_t conn, const struct ble_gatt_error *error,
                    const struct ble_gatt_chr *chr, void *arg);
static int __attribute__((unused)) disc_dsc(uint16_t conn, const struct ble_gatt_error *error,
                    uint16_t chr_val_handle, const struct ble_gatt_dsc *dsc, void *arg);
static int gap_event(struct ble_gap_event *event, void *arg);

/* Send packet via Mijia BLE Channel framing (CTR + DATA frames + CRC32) */
/* Start sending a packet via Mijia BLE Channel: sends CTR and waits for ACK 1 */
static void start_channel_send(uint16_t handle, uint8_t pkg_type, const uint8_t *payload, size_t payload_len)
{
    ch_tx_handle = handle;
    ch_tx_pkg_type = pkg_type;
    if (payload_len > sizeof(ch_tx_buf)) {
        ESP_LOGE(TAG, "channel payload too large: %zu", payload_len);
        return;
    }
    memcpy(ch_tx_buf, payload, payload_len);
    ch_tx_len = payload_len;
    ch_tx_frames = (ch_tx_len + 17) / 18;

    uint8_t ctr[6] = {0, 0, 0, pkg_type, ch_tx_frames & 0xff, (ch_tx_frames >> 8) & 0xff};
    ESP_LOGI(TAG, ">>> Sending Channel CTR: pkg_type=%d, frameCount=%d, waiting for START_ACK (00 00 01 01)...",
             pkg_type, ch_tx_frames);
    write_cmd(handle, ctr, sizeof(ctr), false);
}

/* Transmit all channel data frames upon receiving START_ACK */
static void send_all_channel_data_frames(void)
{
    size_t chunk_size = 18;
    for (uint16_t seq = 1; seq <= ch_tx_frames; seq++) {
        size_t offset = (seq - 1) * chunk_size;
        if (offset >= ch_tx_len) break;
        size_t this_chunk = ch_tx_len - offset;
        if (this_chunk > chunk_size) this_chunk = chunk_size;

        uint8_t frame[20];
        frame[0] = seq & 0xff;
        frame[1] = (seq >> 8) & 0xff;
        memcpy(frame + 2, ch_tx_buf + offset, this_chunk);

        ESP_LOGI(TAG, ">>> Sending Channel DATA frame %d/%d (%zu bytes)", seq, ch_tx_frames, 2 + this_chunk);
        write_cmd(ch_tx_handle, frame, 2 + this_chunk, false);
    }
}

/* Retransmit a specific lost sequence requested by peer in NACK packet (00 00 01 05 seq) */
static void resend_channel_data_frame(uint16_t seq)
{
    if (seq == 0 || seq > ch_tx_frames) return;
    size_t chunk_size = 18;
    size_t offset = (seq - 1) * chunk_size;
    if (offset >= ch_tx_len) return;
    size_t this_chunk = ch_tx_len - offset;
    if (this_chunk > chunk_size) this_chunk = chunk_size;

    uint8_t frame[20];
    frame[0] = seq & 0xff;
    frame[1] = (seq >> 8) & 0xff;
    memcpy(frame + 2, ch_tx_buf + offset, this_chunk);

    ESP_LOGI(TAG, ">>> Retransmitting Channel DATA frame %d/%d (%zu bytes)", seq, ch_tx_frames, 2 + this_chunk);
    write_cmd(ch_tx_handle, frame, 2 + this_chunk, false);
}

/* Step 1 of login: send start opcode and initiate channel send for app public key */
static void step1_send_login_start(void)
{
    set_state(ST_LOGIN_START_SENT);
    ESP_LOGI(TAG, ">>> Step 3: Sending LOGIN_START (4 bytes) to Auth handle %d", h_auth);
    write_cmd(h_auth, SC_CMD_LOGIN_START, sizeof(SC_CMD_LOGIN_START), false);

    /* Step 4: Send App Public Key (64 bytes raw without 0x04) via Channel */
    uint16_t data_handle = (h_channel != 0) ? h_channel : h_auth;
    ESP_LOGI(TAG, ">>> Step 4: Starting App Public Key send via Channel (pkg_type=3) to handle %d", data_handle);
    start_channel_send(data_handle, 3, app_pub65 + 1, 64);

    set_state(ST_LOGIN_WAIT_PUB);
}

/* Sequential CCCD enabling */
static void enable_next_cccd(void);

static int on_cccd_written(uint16_t conn, const struct ble_gatt_error *error,
                           struct ble_gatt_attr *attr, void *arg)
{
    if (error->status != 0) {
        ESP_LOGW(TAG, "CCCD write failed (status=%d), clearing cached handles & falling back to discovery", error->status);
        h_auth = 0;
        h_channel = 0;
        set_state(ST_DISC_SVCS);
        ble_gattc_disc_all_svcs(conn_handle, disc_svc, NULL);
        return 0;
    }
    ESP_LOGI(TAG, "CCCD write SUCCESS!");

    if (!auth_cccd_enabled) {
        auth_cccd_enabled = true;
    } else if (!channel_cccd_enabled) {
        channel_cccd_enabled = true;
    }

    enable_next_cccd();
    return 0;
}

static void enable_next_cccd(void)
{
    static const uint8_t notify_enable[2] = {0x01, 0x00};
    if (h_auth_cccd != 0 && !auth_cccd_enabled) {
        set_state(ST_SUBSCRIBE_CCCD);
        ESP_LOGI(TAG, "Writing CCCD to enable notifications on Auth handle %d...", h_auth_cccd);
        ble_gattc_write_flat(conn_handle, h_auth_cccd, notify_enable, 2, on_cccd_written, NULL);
    } else if (h_channel_cccd != 0 && !channel_cccd_enabled) {
        set_state(ST_SUBSCRIBE_CCCD);
        ESP_LOGI(TAG, "Writing CCCD to enable notifications on Channel handle %d...", h_channel_cccd);
        ble_gattc_write_flat(conn_handle, h_channel_cccd, notify_enable, 2, on_cccd_written, NULL);
    } else {
        ESP_LOGI(TAG, "All CCCDs enabled, proceeding to login start!");
        step1_send_login_start();
    }
}

/* Process lock public key (64 bytes raw) */
static void process_peer_pubkey(const uint8_t *peer_pub, size_t len)
{
    ESP_LOGI(TAG, "Processing Lock Public Key (64 bytes):");
    ESP_LOG_BUFFER_HEX(TAG, peer_pub, 64);

    uint8_t shared[32];
    int rc = sc_ecdh_shared(app_key_id, peer_pub, shared);
    if (rc != 0) {
        handle_failure("sc_ecdh_shared failed");
        return;
    }
    psa_destroy_key(app_key_id);
    app_key_id = 0;

    ESP_LOGI(TAG, "ECDH Shared Secret (32 bytes):");
    ESP_LOG_BUFFER_HEX(TAG, shared, 32);

    rc = sc_hkdf_login(shared, ltmk, session.session);
    if (rc != 0) {
        handle_failure("sc_hkdf_login failed");
        return;
    }
    session.ready = true;
    session.tx_counter = 0;
    session.tx_epoch = 0;
    ESP_LOGI(TAG, "Derived Session Key (64 bytes):");
    ESP_LOG_BUFFER_HEX(TAG, session.session, 64);

    /* Step 6: Encrypt CRC32 of lock pubkey with AES-CCM (4-byte tag) -> 8 bytes */
    uint8_t enc_token[8];
    rc = sc_build_login_token(session.session, peer_pub, enc_token);
    if (rc != 0) {
        handle_failure("sc_build_login_token failed");
        return;
    }

    set_state(ST_LOGIN_SEND_ENC);
    uint16_t data_handle = (h_channel != 0) ? h_channel : h_auth;
    ESP_LOGI(TAG, ">>> Sending Encrypted Token (pkg_type=5, %zu bytes) to handle %d", sizeof(enc_token), data_handle);
    start_channel_send(data_handle, 5, enc_token, sizeof(enc_token));

    set_state(ST_LOGIN_WAIT_OK);
}

static void disconnect_post_op_task(void *param)
{
    vTaskDelay(pdMS_TO_TICKS(1500));
    if (conn_handle != BLE_HS_CONN_HANDLE_NONE) {
        ESP_LOGI(TAG, "Closing BLE connection post-operation...");
        ble_gap_terminate(conn_handle, BLE_ERR_REM_USER_CONN_TERM);
    }
    set_state(ST_IDLE);
    ensure_ecdh_key_ready();
    vTaskDelete(NULL);
}

static void schedule_disconnect(void)
{
    xTaskCreate(disconnect_post_op_task, "disc_post", 2048, NULL, 5, NULL);
}

static int on_door_status_read(uint16_t conn, const struct ble_gatt_error *error,
                               struct ble_gatt_attr *attr, void *arg)
{
    if (error->status == 0 && attr != NULL) {
        uint16_t len = OS_MBUF_PKTLEN(attr->om);
        uint8_t val[8] = {0};
        if (len > sizeof(val)) len = sizeof(val);
        ble_hs_mbuf_to_flat(attr->om, val, len, NULL);
        uint8_t d = val[0];
        g_lock_state.door_state = d;
        const char *d_str = "UNKNOWN";
        const char *contact = "OFF";
        if (d == 0x01) {
            d_str = "CLOSED"; contact = "OFF";
            strlcpy(g_lock_state.door_state_str, "已关好", sizeof(g_lock_state.door_state_str));
        } else if (d == 0x00) {
            d_str = "OPEN"; contact = "ON";
            strlcpy(g_lock_state.door_state_str, "门未关", sizeof(g_lock_state.door_state_str));
        } else if (d == 0xF3) {
            d_str = "AJAR"; contact = "ON";
            strlcpy(g_lock_state.door_state_str, "门虚掩", sizeof(g_lock_state.door_state_str));
        } else if (d == 0xF4) {
            d_str = "UNLOCKED_CLOSED"; contact = "OFF";
            strlcpy(g_lock_state.door_state_str, "未上锁", sizeof(g_lock_state.door_state_str));
        } else {
            snprintf(g_lock_state.door_state_str, sizeof(g_lock_state.door_state_str), "0x%02X", d);
        }
        ESP_LOGI(TAG, ">>> Read Door Status: 0x%02X (%s)", d, g_lock_state.door_state_str);
        mqtt_handler_publish_door(d_str, contact);
    } else {
        ESP_LOGW(TAG, "Read Door Status finished / status=%d", error->status);
    }
    schedule_disconnect();
    return 0;
}

static int on_lock_status_read(uint16_t conn, const struct ble_gatt_error *error,
                               struct ble_gatt_attr *attr, void *arg)
{
    if (error->status == 0 && attr != NULL) {
        uint16_t len = OS_MBUF_PKTLEN(attr->om);
        uint8_t val[8] = {0};
        if (len > sizeof(val)) len = sizeof(val);
        ble_hs_mbuf_to_flat(attr->om, val, len, NULL);
        uint8_t st = val[0];
        g_lock_state.anti_lock = (st >> 1) & 1;
        g_lock_state.child_lock = (st >> 3) & 1;
        ESP_LOGI(TAG, ">>> Read Lock Status: 0x%02X (AntiLock=%d, ChildLock=%d)",
                 st, g_lock_state.anti_lock, g_lock_state.child_lock);
        mqtt_handler_publish_anti_lock(g_lock_state.anti_lock ? "ON" : "OFF");
        mqtt_handler_publish_child_lock(g_lock_state.child_lock ? "ON" : "OFF");
    } else {
        ESP_LOGW(TAG, "Read Lock Status finished / status=%d", error->status);
    }

    /* Next in chain: Door Status */
    if (h_door_status != 0 && conn_handle != BLE_HS_CONN_HANDLE_NONE) {
        ble_gattc_read(conn_handle, h_door_status, on_door_status_read, NULL);
    } else {
        schedule_disconnect();
    }
    return 0;
}

static int on_battery_read(uint16_t conn, const struct ble_gatt_error *error,
                           struct ble_gatt_attr *attr, void *arg)
{
    if (error->status == 0 && attr != NULL) {
        uint16_t len = OS_MBUF_PKTLEN(attr->om);
        uint8_t val[8] = {0};
        if (len > sizeof(val)) len = sizeof(val);
        ble_hs_mbuf_to_flat(attr->om, val, len, NULL);
        g_lock_state.battery = val[0];
        ESP_LOGI(TAG, ">>> Read Battery Level: %u%%", g_lock_state.battery);
        mqtt_handler_publish_battery(g_lock_state.battery);
    } else {
        ESP_LOGW(TAG, "Read Battery finished / status=%d", error->status);
    }

    /* Next in chain: Lock Status */
    if (h_lock_status != 0 && conn_handle != BLE_HS_CONN_HANDLE_NONE) {
        ble_gattc_read(conn_handle, h_lock_status, on_lock_status_read, NULL);
    } else {
        schedule_disconnect();
    }
    return 0;
}

static void start_status_read_chain(void)
{
    if (conn_handle == BLE_HS_CONN_HANDLE_NONE) {
        schedule_disconnect();
        return;
    }
    ESP_LOGI(TAG, ">>> Reading status from lock (Battery -> Lock Status -> Door Status)...");
    if (h_battery != 0) {
        ble_gattc_read(conn_handle, h_battery, on_battery_read, NULL);
    } else if (h_lock_status != 0) {
        ble_gattc_read(conn_handle, h_lock_status, on_lock_status_read, NULL);
    } else if (h_door_status != 0) {
        ble_gattc_read(conn_handle, h_door_status, on_door_status_read, NULL);
    } else {
        schedule_disconnect();
    }
}

/* Notification handler for both Auth (0x0010) and Channel (0x0016) */
static void handle_rx_notify(uint16_t handle, const uint8_t *buf, uint16_t len)
{
    ESP_LOGI(TAG, "<<< NOTIFY on handle=%d, len=%u, state=%d", handle, len, (int)state);
    ESP_LOG_BUFFER_HEX(TAG, buf, len);

    /* Check for DEV_OK (0x21 00 00 00) or DEV_FAIL (0x22 00 00 00) */
    if (len >= 4 && memcmp(buf, SC_CMD_DEV_OK, 4) == 0) {
        ESP_LOGI(TAG, "===============================================================");
        ESP_LOGI(TAG, ">>> [LOGIN SUCCESS] DEV_OK received from lock! Action=%d", (int)s_current_action);
        ESP_LOGI(TAG, "===============================================================");
        set_state(ST_OPERATE_SENT);

        if (s_current_action == BLE_ACTION_UNLOCK) {
            uint8_t action = 0; /* Action: 0 = OPEN / UNLOCK */
            uint8_t op[64];
            size_t op_len = 0;
            if (sc_build_operate(&session, &action, 1, op, &op_len) == 0) {
                uint16_t target_handle = (h_lock_write != 0) ? h_lock_write : h_lock_op;
                ESP_LOGI(TAG, ">>> Sending operate unlock frame (%u bytes) to handle %d", (unsigned)op_len, target_handle);
                write_cmd(target_handle, op, op_len, true);
                set_state(ST_DONE);
                ESP_LOGI(TAG, "=== UNLOCK COMMAND EXECUTED SUCCESSFULLY ===");
                strlcpy(g_lock_state.lock_state_str, "UNLOCKED", sizeof(g_lock_state.lock_state_str));
                mqtt_handler_publish_state("UNLOCKED");
                start_status_read_chain();
            } else {
                handle_failure("sc_build_operate for unlock failed");
            }
        } else if (s_current_action == BLE_ACTION_CHILD_LOCK) {
            uint8_t val = (s_action_param ? 2 : 1);
            uint8_t l1_cmd[64];
            size_t l1_len = 0;
            sc_build_loock_cmd(1426, 0x73, &val, 1, s_loock_seq++, l1_cmd, &l1_len);
            uint8_t op[128];
            size_t op_len = 0;
            if (sc_build_operate(&session, l1_cmd, l1_len, op, &op_len) == 0) {
                uint16_t target_handle = (h_device_write != 0) ? h_device_write : 103;
                ESP_LOGI(TAG, ">>> Sending encrypted Child Lock (%s) frame (%u bytes) to handle %d",
                         s_action_param ? "ENABLE" : "DISABLE", (unsigned)op_len, target_handle);
                write_cmd(target_handle, op, op_len, true);
                set_state(ST_DONE);
                g_lock_state.child_lock = s_action_param;
                mqtt_handler_publish_child_lock(s_action_param ? "ON" : "OFF");
                start_status_read_chain();
            } else {
                handle_failure("sc_build_operate for Child Lock failed");
            }
        } else if (s_current_action == BLE_ACTION_ANTI_LOCK) {
            uint8_t val = (s_action_param ? 1 : 0);
            uint8_t l1_cmd[64];
            size_t l1_len = 0;
            sc_build_loock_cmd(1405, 0xCF, &val, 1, s_loock_seq++, l1_cmd, &l1_len);
            uint8_t op[128];
            size_t op_len = 0;
            if (sc_build_operate(&session, l1_cmd, l1_len, op, &op_len) == 0) {
                uint16_t target_handle = (h_device_write != 0) ? h_device_write : 103;
                ESP_LOGI(TAG, ">>> Sending encrypted Anti-Lock (%s) frame (%u bytes) to handle %d",
                         s_action_param ? "ENABLE" : "DISABLE", (unsigned)op_len, target_handle);
                write_cmd(target_handle, op, op_len, true);
                set_state(ST_DONE);
                g_lock_state.anti_lock = s_action_param;
                mqtt_handler_publish_anti_lock(s_action_param ? "ON" : "OFF");
                start_status_read_chain();
            } else {
                handle_failure("sc_build_operate for Anti-Lock failed");
            }
        } else if (s_current_action == BLE_ACTION_REFRESH_STATUS) {
            set_state(ST_DONE);
            start_status_read_chain();
        }
        return;
    }

    if (len >= 4 && memcmp(buf, SC_CMD_DEV_FAIL, 4) == 0) {
        ESP_LOGE(TAG, ">>> [LOGIN REJECTED] DEV_FAIL received from lock");
        set_state(ST_FAIL);
        mqtt_handler_publish_state("LOCKED");
        if (conn_handle != BLE_HS_CONN_HANDLE_NONE) {
            ble_gap_terminate(conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        }
        set_state(ST_IDLE);
        return;
    }

    /* Check for Channel ACK packet: [00 00 01 status ...] */
    if (len >= 4 && buf[0] == 0 && buf[1] == 0 && buf[2] == 1) {
        uint8_t ack_status = buf[3];
        ESP_LOGI(TAG, "Channel ACK packet: status=%d", ack_status);
        if (ack_status == 1) {
            /* START_ACK: Peer acknowledged CTR, now transmit all DATA frames! */
            ESP_LOGI(TAG, "Peer sent START_ACK (ready), transmitting %d DATA frames...", ch_tx_frames);
            send_all_channel_data_frames();
        } else if (ack_status == 5) {
            /* NACK: Retransmit requested lost frames */
            size_t n_lost = (len - 4) / 2;
            for (size_t i = 0; i < n_lost; i++) {
                uint16_t lost_seq = buf[4 + i * 2] | (buf[4 + i * 2 + 1] << 8);
                ESP_LOGW(TAG, "Peer requested retransmission of lost seq=%d", lost_seq);
                resend_channel_data_frame(lost_seq);
            }
        } else if (ack_status == 0) {
            ESP_LOGI(TAG, "Peer acknowledged data completion (status 0)");
        }
        return;
    }

    /* Check for Channel CTR packet: [00 00 00 pkg_type frameCount_lo frameCount_hi] */
    if (len >= 6 && buf[0] == 0 && buf[1] == 0 && buf[2] == 0) {
        ch_rx_pkg_type = buf[3];
        ch_rx_expected_frames = buf[4] | (buf[5] << 8);
        ch_rx_len = 0;
        ch_rx_frames_received = 0;
        ESP_LOGI(TAG, "Channel CTR packet from peer: pkg_type=%d, frameCount=%d", ch_rx_pkg_type, ch_rx_expected_frames);

        /* Send START_ACK (00 00 01 01) back to lock to indicate readiness to receive DATA */
        static const uint8_t start_ack[4] = {0, 0, 1, 1};
        ESP_LOGI(TAG, ">>> Replying with START_ACK (00 00 01 01) to handle %d", handle);
        write_cmd(handle, start_ack, sizeof(start_ack), false);
        return;
    }

    /* Check for Channel DATA frame: [seq_lo seq_hi chunk_data...] */
    if (len > 2 && (buf[0] != 0 || buf[1] != 0) && ch_rx_expected_frames > 0) {
        uint16_t seq = buf[0] | (buf[1] << 8);
        ESP_LOGI(TAG, "Channel DATA frame: seq=%d chunk_len=%u", seq, len - 2);
        if (ch_rx_len + (len - 2) <= sizeof(ch_rx_buf)) {
            memcpy(ch_rx_buf + ch_rx_len, buf + 2, len - 2);
            ch_rx_len += (len - 2);
        }
        ch_rx_frames_received++;
        if (ch_rx_frames_received >= ch_rx_expected_frames) {
            ESP_LOGI(TAG, "Channel message fully assembled: pkg_type=%d total_len=%zu", ch_rx_pkg_type, ch_rx_len);
            /* Send Channel SUCCESS ACK back to lock */
            static const uint8_t ack_pkt[4] = {0, 0, 1, 0};
            ESP_LOGI(TAG, ">>> Replying with SUCCESS_ACK (00 00 01 00) to handle %d", handle);
            write_cmd(handle, ack_pkt, sizeof(ack_pkt), false);

            if (ch_rx_pkg_type == 3) {
                /* Public key received via Channel (64B pubkey + 4B CRC32 = 68B) */
                if (ch_rx_len >= 64) {
                    process_peer_pubkey(ch_rx_buf, 64);
                }
            }
        }
        return;
    }

    /* Fallback: Direct public key notification (without Channel framing) */
    if (len >= 64) {
        const uint8_t *peer_pub = buf;
        if (len == 65 && buf[0] == 0x04) {
            peer_pub = buf + 1;
        } else if (len > 64 && buf[0] == 0x03) {
            peer_pub = buf + 1;
        }
        process_peer_pubkey(peer_pub, 64);
        return;
    }
}

/* Descriptor discovery */
static int __attribute__((unused)) disc_dsc(uint16_t conn, const struct ble_gatt_error *error,
                    uint16_t chr_val_handle, const struct ble_gatt_dsc *dsc, void *arg)
{
    if (error->status == 0 && dsc != NULL) {
        if (dsc->uuid.u.type == BLE_UUID_TYPE_16 && dsc->uuid.u16.value == 0x2902) {
            ESP_LOGI(TAG, ">>> Found CCCD (0x2902): dsc_handle=%d", dsc->handle);
            if (h_auth != 0 && dsc->handle == h_auth + 1) {
                h_auth_cccd = dsc->handle;
                ESP_LOGI(TAG, ">>> Assigned h_auth_cccd: %d", h_auth_cccd);
            } else if (h_channel != 0 && dsc->handle == h_channel + 1) {
                h_channel_cccd = dsc->handle;
                ESP_LOGI(TAG, ">>> Assigned h_channel_cccd: %d", h_channel_cccd);
            }
        }
        return 0;
    }

    if (error->status == BLE_HS_EDONE || dsc == NULL) {
        ESP_LOGI(TAG, "Descriptor discovery finished. h_auth_cccd=%d, h_channel_cccd=%d",
                 h_auth_cccd, h_channel_cccd);
        if (h_auth_cccd == 0 && h_auth != 0) {
            h_auth_cccd = h_auth + 1;
            ESP_LOGW(TAG, "Using fallback h_auth_cccd: %d", h_auth_cccd);
        }
        if (h_channel_cccd == 0 && h_channel != 0) {
            h_channel_cccd = h_channel + 1;
            ESP_LOGW(TAG, "Using fallback h_channel_cccd: %d", h_channel_cccd);
        }

        auth_cccd_enabled = false;
        channel_cccd_enabled = false;
        enable_next_cccd();
        return 0;
    }

    ESP_LOGE(TAG, "Descriptor discovery error: %d", error->status);
    set_state(ST_FAIL);
    return 0;
}

/* Characteristic discovery */
static int disc_chr(uint16_t conn, const struct ble_gatt_error *error,
                    const struct ble_gatt_chr *chr, void *arg)
{
    if (error->status == 0 && chr != NULL) {
        char u[BLE_UUID_STR_LEN];
        ble_uuid_to_str(&chr->uuid.u, u);
        ESP_LOGI(TAG, "CHR: %s val_handle=%d props=0x%02x", u, chr->val_handle, chr->properties);

        if (chr->uuid.u.type == BLE_UUID_TYPE_16) {
            if (chr->uuid.u16.value == 0x0010) {
                h_auth = chr->val_handle;
                ESP_LOGI(TAG, ">>> Found Auth Characteristic handle: %d", h_auth);
            } else if (chr->uuid.u16.value == 0x0016) {
                h_channel = chr->val_handle;
                ESP_LOGI(TAG, ">>> Found Channel Characteristic handle: %d", h_channel);
            } else if (chr->uuid.u16.value == 0x2A19) {
                h_battery = chr->val_handle;
                ESP_LOGI(TAG, ">>> Found Battery Characteristic handle: %d", h_battery);
            }
        } else if (chr->uuid.u.type == BLE_UUID_TYPE_128) {
            if (strcasecmp(u, "00000010-0000-1000-8000-00805f9b34fb") == 0) {
                h_auth = chr->val_handle;
                ESP_LOGI(TAG, ">>> Found Auth Characteristic handle: %d", h_auth);
            } else if (strcasecmp(u, "00000016-0000-1000-8000-00805f9b34fb") == 0) {
                h_channel = chr->val_handle;
                ESP_LOGI(TAG, ">>> Found Channel Characteristic handle: %d", h_channel);
            } else if (strstr(u, "00001001-0065-6c62")) {
                h_lock_write = chr->val_handle;
                ESP_LOGI(TAG, ">>> Found Lock Write Characteristic handle: %d", h_lock_write);
            } else if (strstr(u, "00001002-0065-6c62")) {
                h_lock_op = chr->val_handle;
                ESP_LOGI(TAG, ">>> Found Lock Op Notify Characteristic handle: %d", h_lock_op);
            } else if (strstr(u, "00001003-0065-6c62")) {
                h_lock_log = chr->val_handle;
                ESP_LOGI(TAG, ">>> Found Lock Log Characteristic handle: %d", h_lock_log);
            } else if (strstr(u, "00002220-0000-6b63")) {
                h_lock_status = chr->val_handle;
                ESP_LOGI(TAG, ">>> Found Lock Status Characteristic handle: %d", h_lock_status);
            } else if (strstr(u, "00002222-0000-6b63")) {
                h_door_status = chr->val_handle;
                ESP_LOGI(TAG, ">>> Found Door Status Characteristic handle: %d", h_door_status);
            } else if (strstr(u, "6e400002-b5a3-f393")) {
                h_device_write = chr->val_handle;
                ESP_LOGI(TAG, ">>> Found Device Control Write handle: %d", h_device_write);
            }
        }
        return 0;
    }

    if (error->status == BLE_HS_EDONE || chr == NULL) {
        ESP_LOGI(TAG, "All characteristics discovered: auth=%d, channel=%d, write=%d, op=%d, log=%d",
                 h_auth, h_channel, h_lock_write, h_lock_op, h_lock_log);
        if (h_auth == 0) {
            handle_failure("Auth characteristic missing!");
            return 0;
        }

        /* Fast CCCD enabling without 39s full-table discovery */
        if (h_auth_cccd == 0) h_auth_cccd = (h_auth != 0) ? (h_auth + 1) : 37;
        if (h_channel_cccd == 0) h_channel_cccd = (h_channel != 0) ? (h_channel + 1) : 40;
        ESP_LOGI(TAG, "Fast start: auth_cccd=%d, channel_cccd=%d. Enabling CCCDs immediately...",
                 h_auth_cccd, h_channel_cccd);
        auth_cccd_enabled = false;
        channel_cccd_enabled = false;
        enable_next_cccd();
        return 0;
    }

    handle_failure("Characteristic discovery failed");
    return 0;
}

/* Service discovery */
static int disc_svc(uint16_t conn, const struct ble_gatt_error *error,
                    const struct ble_gatt_svc *svc, void *arg)
{
    if (error->status == 0 && svc != NULL) {
        char u[BLE_UUID_STR_LEN];
        ble_uuid_to_str(&svc->uuid.u, u);
        ESP_LOGI(TAG, "SVC: %s start_handle=%d end_handle=%d", u, svc->start_handle, svc->end_handle);
        return 0;
    }

    if (error->status == BLE_HS_EDONE || svc == NULL) {
        ESP_LOGI(TAG, "Service discovery finished. Starting characteristic discovery...");
        set_state(ST_DISC_CHRS);
        ble_gattc_disc_all_chrs(conn_handle, 1, 0xffff, disc_chr, NULL);
        return 0;
    }

    handle_failure("Service discovery error");
    return 0;
}

/* MTU exchange completion callback */
static int on_mtu_exchanged(uint16_t conn, const struct ble_gatt_error *error,
                            uint16_t mtu, void *arg)
{
    if (error->status != 0) {
        ESP_LOGW(TAG, "MTU exchange failed, status=%d (continuing with default)", error->status);
    } else {
        ESP_LOGI(TAG, "MTU exchange success, negotiated MTU=%u", mtu);
    }

    /* Fast path: if characteristic handles are already cached, skip slow GATT discovery! */
    if (h_auth != 0 && h_channel != 0 && h_auth_cccd != 0 && h_channel_cccd != 0) {
        ESP_LOGI(TAG, ">>> GATT handles cached (auth=%d, channel=%d, cccd=%d/%d). FAST-SKIPPING discovery! <<<",
                 h_auth, h_channel, h_auth_cccd, h_channel_cccd);
        auth_cccd_enabled = false;
        channel_cccd_enabled = false;
        enable_next_cccd();
        return 0;
    }

    set_state(ST_DISC_SVCS);
    ble_gattc_disc_all_svcs(conn_handle, disc_svc, NULL);
    return 0;
}

/* GAP event handler */
static int gap_event(struct ble_gap_event *event, void *arg)
{
    switch (event->type) {
    case BLE_GAP_EVENT_DISC: {
        const struct ble_gap_disc_desc *d = &event->disc;
        if (peer_found) return 0;

        if (memcmp(d->addr.val, peer_addr.val, 6) == 0) {
            ESP_LOGI(TAG, "Found target lock in scan! Connecting with fast params...");
            peer_found = true;
            ble_gap_disc_cancel();
            set_state(ST_CONNECT);
            ble_gap_connect(own_addr_type, &d->addr, 10000, &FAST_CONN_PARAMS, gap_event, NULL);
        }
        return 0;
    }
    case BLE_GAP_EVENT_CONNECT:
        ESP_LOGI(TAG, "GAP CONNECT event, status=%d", event->connect.status);
        if (event->connect.status == 0) {
            conn_handle = event->connect.conn_handle;
            set_state(ST_EXCHANGE_MTU);
            ESP_LOGI(TAG, "Requesting MTU exchange...");
            ble_gattc_exchange_mtu(conn_handle, on_mtu_exchanged, NULL);
        } else {
            handle_failure("Connection failed");
        }
        return 0;
    case BLE_GAP_EVENT_DISCONNECT:
        ESP_LOGI(TAG, "GAP DISCONNECT event, reason=%d, state=%d", event->disconnect.reason, (int)state);
        conn_handle = BLE_HS_CONN_HANDLE_NONE;
        /* Keep cached GATT handles intact! Do NOT clear h_auth, h_channel, etc. */
        auth_cccd_enabled = false;
        channel_cccd_enabled = false;
        ch_rx_len = 0;
        ch_rx_expected_frames = 0;
        ch_rx_frames_received = 0;
        if (state != ST_DONE && state != ST_IDLE) {
            ESP_LOGW(TAG, "Disconnected before completion");
            mqtt_handler_publish_state("LOCKED");
        }
        set_state(ST_IDLE);
        ensure_ecdh_key_ready();
        return 0;
    case BLE_GAP_EVENT_DISC_COMPLETE:
        ESP_LOGI(TAG, "GAP discovery complete, reason=%d", event->disc_complete.reason);
        if (!peer_found && state == ST_SCAN) {
            handle_failure("Scan timeout - target lock not found");
        }
        return 0;
    case BLE_GAP_EVENT_NOTIFY_RX: {
        uint16_t len = OS_MBUF_PKTLEN(event->notify_rx.om);
        uint8_t buf[128];
        if (len > sizeof(buf)) len = sizeof(buf);
        ble_hs_mbuf_to_flat(event->notify_rx.om, buf, len, NULL);
        handle_rx_notify(event->notify_rx.attr_handle, buf, len);
        return 0;
    }
    default:
        return 0;
    }
}

static void on_sync(void)
{
    ESP_LOGI(TAG, "NimBLE host synched. BLE stack ready in IDLE mode (waiting for unlock command).");
    ble_hs_util_ensure_addr(0);
    ble_hs_id_infer_auto(0, &own_addr_type);
    set_state(ST_IDLE);
    ensure_ecdh_key_ready();
}

static void on_reset(int reason)
{
    ESP_LOGE(TAG, "NimBLE reset, reason=%d", reason);
}

static void host_task(void *param)
{
    nimble_port_run();
    nimble_port_freertos_deinit();
}

void miot_ble_start(void)
{
    if (sc_crypto_init() != 0) {
        ESP_LOGE(TAG, "Failed to init crypto");
        return;
    }

    nimble_port_init();
    ble_hs_cfg.sync_cb = on_sync;
    ble_hs_cfg.reset_cb = on_reset;

    nimble_port_freertos_init(host_task);
}

static TaskHandle_t s_unlock_timeout_task_h = NULL;

static void unlock_timeout_task(void *param)
{
    /* 20 seconds overall timeout */
    vTaskDelay(pdMS_TO_TICKS(20000));
    if (state != ST_IDLE && state != ST_DONE) {
        ESP_LOGW(TAG, "BLE operation timed out (20s)! Resetting to IDLE.");
        if (ble_gap_disc_active()) {
            ble_gap_disc_cancel();
        }
        if (conn_handle != BLE_HS_CONN_HANDLE_NONE) {
            ble_gap_terminate(conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        }
        set_state(ST_IDLE);
        if (s_current_action == BLE_ACTION_UNLOCK) {
            mqtt_handler_publish_state("LOCKED");
        }
    }
    s_unlock_timeout_task_h = NULL;
    vTaskDelete(NULL);
}

void miot_ble_trigger_action(ble_action_t action, int param)
{
    ESP_LOGI(TAG, "BLE action triggered: action=%d param=%d", (int)action, param);
    s_current_action = action;
    s_action_param = param;

    if (state != ST_IDLE && state != ST_FAIL && state != ST_DONE) {
        ESP_LOGW(TAG, "Operation already in progress (state=%d), ignoring duplicate request", (int)state);
        return;
    }

    if (!g_lock_cfg.is_configured || strlen(g_lock_cfg.mac) != 17) {
        ESP_LOGE(TAG, "Lock not configured (invalid MAC or LTMK)");
        return;
    }

    if (parse_mac(g_lock_cfg.mac, &peer_addr) != 0) {
        ESP_LOGE(TAG, "Failed to parse configured MAC: %s", g_lock_cfg.mac);
        return;
    }
    memcpy(ltmk, g_lock_cfg.ltmk, 32);

    /* Ensure ephemeral ECDH keypair is ready (instantly ready if pre-generated) */
    if (app_key_id == 0) {
        if (sc_ecdh_generate(&app_key_id, app_pub65) != 0) {
            ESP_LOGE(TAG, "Failed to generate ECDH keypair");
            return;
        }
    }
    ESP_LOGI(TAG, "Using App Public Key (65 bytes):");
    ESP_LOG_BUFFER_HEX(TAG, app_pub65, 65);

    if (conn_handle != BLE_HS_CONN_HANDLE_NONE) {
        ble_gap_terminate(conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        conn_handle = BLE_HS_CONN_HANDLE_NONE;
    }

    /* Reset session buffers but preserve cached GATT handles */
    auth_cccd_enabled = false;
    channel_cccd_enabled = false;
    ch_rx_len = 0;
    ch_rx_expected_frames = 0;
    ch_rx_frames_received = 0;

    peer_found = true;
    set_state(ST_CONNECT);

    /* Fast direct connect: 100% duty cycle continuous scan + 7.5ms connection interval */
    int rc = ble_gap_connect(own_addr_type, &peer_addr, 10000, &FAST_CONN_PARAMS, gap_event, NULL);
    ESP_LOGI(TAG, "Fast direct connect initiated (10s timeout), rc=%d, target=%s", rc, g_lock_cfg.mac);
    if (rc != 0) {
        ESP_LOGW(TAG, "Direct connect returned %d, falling back to discovery scan...", rc);
        peer_found = false;
        set_state(ST_SCAN);
        struct ble_gap_disc_params dp = {
            .passive = 0,
            .filter_duplicates = 1,
            .itvl = 16,
            .window = 16,
        };
        ble_gap_disc(own_addr_type, 10000, &dp, gap_event, NULL);
    }

    if (s_unlock_timeout_task_h != NULL) {
        vTaskDelete(s_unlock_timeout_task_h);
        s_unlock_timeout_task_h = NULL;
    }
    xTaskCreate(unlock_timeout_task, "unlock_to", 2048, NULL, 5, &s_unlock_timeout_task_h);
}

void miot_ble_trigger_unlock(void)
{
    miot_ble_trigger_action(BLE_ACTION_UNLOCK, 0);
}
