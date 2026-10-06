#include "lock_config.h"
#include <string.h>
#include <stdio.h>
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_rom_md5.h"
#include "psa/crypto.h"
#include "security_chip.h"

static const char *TAG = "LOCK_CFG";
static const char *NVS_NS = "lock_cfg";
static const char *DEFAULT_IV_HEX = "7aa4c68c590d4031b980d98b41023800";

lock_config_t g_lock_cfg = {0};
lock_live_state_t g_lock_state = {
    .battery = 255,
    .child_lock = -1,
    .anti_lock = -1,
    .door_state = -1,
    .door_state_str = "未知",
    .lock_state_str = "LOCKED",
    .last_update = 0,
};

static void bytes_to_hex(const uint8_t *in, size_t len, char *out)
{
    for (size_t i = 0; i < len; i++) {
        sprintf(out + i * 2, "%02x", in[i]);
    }
    out[len * 2] = '\0';
}

esp_err_t lock_config_init(void)
{
    memset(&g_lock_cfg, 0, sizeof(g_lock_cfg));

    /* Set default Wi-Fi parameters (Configure via Web UI) */
    snprintf(g_lock_cfg.wifi_ssid, sizeof(g_lock_cfg.wifi_ssid), "%s", "YOUR_WIFI_SSID");
    snprintf(g_lock_cfg.wifi_pass, sizeof(g_lock_cfg.wifi_pass), "%s", "YOUR_WIFI_PASSWORD");

    /* Set default MQTT broker parameters (Configure via Web UI) */
    snprintf(g_lock_cfg.mqtt_broker, sizeof(g_lock_cfg.mqtt_broker), "%s", "192.168.1.100");
    g_lock_cfg.mqtt_port = 1883;
    snprintf(g_lock_cfg.mqtt_user, sizeof(g_lock_cfg.mqtt_user), "%s", "mqtt_user");
    snprintf(g_lock_cfg.mqtt_pass, sizeof(g_lock_cfg.mqtt_pass), "%s", "mqtt_password");
    snprintf(g_lock_cfg.mqtt_topic, sizeof(g_lock_cfg.mqtt_topic), "%s", "lockbridge/loock");
    snprintf(g_lock_cfg.lock_name, sizeof(g_lock_cfg.lock_name), "%s", "鹿客门锁");
    g_lock_cfg.auto_lock_sec = 4;

    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NS, NVS_READWRITE, &handle);
    if (err == ESP_OK) {
        size_t len = sizeof(g_lock_cfg.mac);
        if (nvs_get_str(handle, "mac", g_lock_cfg.mac, &len) != ESP_OK) {
            snprintf(g_lock_cfg.mac, sizeof(g_lock_cfg.mac), "%s", LOCK_MAC_STR);
        }

        len = sizeof(g_lock_cfg.ltmk_hex);
        if (nvs_get_str(handle, "ltmk", g_lock_cfg.ltmk_hex, &len) == ESP_OK && strlen(g_lock_cfg.ltmk_hex) == 64) {
            sc_hex_to_bytes(g_lock_cfg.ltmk_hex, g_lock_cfg.ltmk, 32);
            g_lock_cfg.is_configured = true;
        } else {
            /* Fallback to compiled default if valid and not dummy placeholder */
            snprintf(g_lock_cfg.ltmk_hex, sizeof(g_lock_cfg.ltmk_hex), "%s", LOCK_LTMK_HEX);
            if (sc_hex_to_bytes(g_lock_cfg.ltmk_hex, g_lock_cfg.ltmk, 32) == 0 &&
                strcmp(LOCK_LTMK_HEX, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff") != 0) {
                g_lock_cfg.is_configured = true;
            } else {
                g_lock_cfg.is_configured = false;
            }
        }

        len = sizeof(g_lock_cfg.wifi_ssid);
        nvs_get_str(handle, "wifi_ssid", g_lock_cfg.wifi_ssid, &len);
        len = sizeof(g_lock_cfg.wifi_pass);
        nvs_get_str(handle, "wifi_pass", g_lock_cfg.wifi_pass, &len);

        len = sizeof(g_lock_cfg.mqtt_broker);
        nvs_get_str(handle, "mqtt_broker", g_lock_cfg.mqtt_broker, &len);
        nvs_get_u16(handle, "mqtt_port", &g_lock_cfg.mqtt_port);
        len = sizeof(g_lock_cfg.mqtt_user);
        nvs_get_str(handle, "mqtt_user", g_lock_cfg.mqtt_user, &len);
        len = sizeof(g_lock_cfg.mqtt_pass);
        nvs_get_str(handle, "mqtt_pass", g_lock_cfg.mqtt_pass, &len);
        len = sizeof(g_lock_cfg.mqtt_topic);
        nvs_get_str(handle, "mqtt_topic", g_lock_cfg.mqtt_topic, &len);
        len = sizeof(g_lock_cfg.lock_name);
        nvs_get_str(handle, "lock_name", g_lock_cfg.lock_name, &len);
        nvs_get_u16(handle, "auto_lock_sec", &g_lock_cfg.auto_lock_sec);
        if (g_lock_cfg.auto_lock_sec == 0) g_lock_cfg.auto_lock_sec = 4;

        len = sizeof(g_lock_cfg.web_pass);
        if (nvs_get_str(handle, "web_pass", g_lock_cfg.web_pass, &len) != ESP_OK || g_lock_cfg.web_pass[0] == '\0') {
            snprintf(g_lock_cfg.web_pass, sizeof(g_lock_cfg.web_pass), "%s", "admin");
        }

        nvs_close(handle);
    } else {
        /* Fallback if NVS read failed */
        snprintf(g_lock_cfg.mac, sizeof(g_lock_cfg.mac), "%s", LOCK_MAC_STR);
        snprintf(g_lock_cfg.ltmk_hex, sizeof(g_lock_cfg.ltmk_hex), "%s", LOCK_LTMK_HEX);
        g_lock_cfg.is_configured = false;
    }

    ESP_LOGI(TAG, "Config initialized: MAC=%s, KeyStatus=%s, Wi-Fi=%s, MQTT=%s:%d, Topic=%s, LockName=%s, AutoLock=%ds",
             g_lock_cfg.mac, g_lock_cfg.is_configured ? "Ready" : "Not Configured", g_lock_cfg.wifi_ssid,
             g_lock_cfg.mqtt_broker, g_lock_cfg.mqtt_port,
             g_lock_cfg.mqtt_topic, g_lock_cfg.lock_name, g_lock_cfg.auto_lock_sec);
    return ESP_OK;
}

esp_err_t lock_config_derive_and_save(const char *mac,
                                     const char *raw_ltmk_hex,
                                     int encrypt_type,
                                     const char *pin,
                                     const char *iv_hex)
{
    if (!mac || strlen(mac) != 17 || !raw_ltmk_hex || strlen(raw_ltmk_hex) != 64) {
        ESP_LOGE(TAG, "Invalid MAC or Raw LTMK length");
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t raw_ltmk[32];
    if (sc_hex_to_bytes(raw_ltmk_hex, raw_ltmk, 32) != 0) {
        ESP_LOGE(TAG, "Bad Raw LTMK hex format");
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t derived[32];
    if (encrypt_type == 0) {
        /* Plaintext LTMK: direct copy */
        memcpy(derived, raw_ltmk, 32);
        ESP_LOGI(TAG, "Encrypt type 0: using raw LTMK directly");
    } else if (encrypt_type == 1) {
        /* Encrypted with MD5(PIN): AES-128-CBC decrypt */
        if (!pin || strlen(pin) == 0) {
            ESP_LOGE(TAG, "PIN code required for encrypt_type=1");
            return ESP_ERR_INVALID_ARG;
        }

        uint8_t md5_key[16];
        md5_context_t md5_ctx;
        esp_rom_md5_init(&md5_ctx);
        esp_rom_md5_update(&md5_ctx, (const uint8_t *)pin, strlen(pin));
        esp_rom_md5_final(md5_key, &md5_ctx);

        const char *use_iv = (iv_hex && strlen(iv_hex) == 32) ? iv_hex : DEFAULT_IV_HEX;
        uint8_t iv[16];
        sc_hex_to_bytes(use_iv, iv, 16);

        psa_crypto_init();

        psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
        psa_set_key_algorithm(&attr, PSA_ALG_CBC_NO_PADDING);
        psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
        psa_set_key_bits(&attr, 128);

        psa_key_id_t key_id = 0;
        psa_status_t status = psa_import_key(&attr, md5_key, 16, &key_id);
        memset(md5_key, 0, sizeof(md5_key));

        if (status != PSA_SUCCESS) {
            ESP_LOGE(TAG, "psa_import_key failed: %d", (int)status);
            return ESP_FAIL;
        }

        psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
        status = psa_cipher_decrypt_setup(&op, key_id, PSA_ALG_CBC_NO_PADDING);
        if (status == PSA_SUCCESS) {
            status = psa_cipher_set_iv(&op, iv, 16);
        }
        size_t out_len = 0;
        if (status == PSA_SUCCESS) {
            status = psa_cipher_update(&op, raw_ltmk, 32, derived, 32, &out_len);
        }
        size_t finish_len = 0;
        if (status == PSA_SUCCESS) {
            status = psa_cipher_finish(&op, derived + out_len, 32 - out_len, &finish_len);
        }

        psa_cipher_abort(&op);
        psa_destroy_key(key_id);
        memset(iv, 0, sizeof(iv));

        if (status != PSA_SUCCESS) {
            ESP_LOGE(TAG, "PSA AES-CBC decryption failed: %d", (int)status);
            return ESP_FAIL;
        }
        ESP_LOGI(TAG, "Derived plaintext LTMK using PIN successfully (PIN NOT saved to flash)");
    } else {
        ESP_LOGE(TAG, "Unsupported encrypt_type: %d", encrypt_type);
        return ESP_ERR_NOT_SUPPORTED;
    }

    char derived_hex[65];
    bytes_to_hex(derived, 32, derived_hex);

    /* Persist ONLY mac and derived ltmk to NVS (PIN is NEVER saved) */
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NS, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS for writing: %s", esp_err_to_name(err));
        return err;
    }

    nvs_set_str(handle, "mac", mac);
    nvs_set_str(handle, "ltmk", derived_hex);
    nvs_commit(handle);
    nvs_close(handle);

    /* Update runtime active configuration */
    snprintf(g_lock_cfg.mac, sizeof(g_lock_cfg.mac), "%s", mac);
    snprintf(g_lock_cfg.ltmk_hex, sizeof(g_lock_cfg.ltmk_hex), "%s", derived_hex);
    memcpy(g_lock_cfg.ltmk, derived, 32);
    g_lock_cfg.is_configured = true;

    ESP_LOGI(TAG, "Configuration updated and saved to NVS! New MAC=%s, LTMK=%s",
             g_lock_cfg.mac, g_lock_cfg.ltmk_hex);
    return ESP_OK;
}

esp_err_t lock_config_save_wifi(const char *ssid, const char *pass)
{
    if (!ssid || strlen(ssid) == 0) return ESP_ERR_INVALID_ARG;

    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NS, NVS_READWRITE, &handle);
    if (err != ESP_OK) return err;

    nvs_set_str(handle, "wifi_ssid", ssid);
    if (pass) nvs_set_str(handle, "wifi_pass", pass);

    nvs_commit(handle);
    nvs_close(handle);

    snprintf(g_lock_cfg.wifi_ssid, sizeof(g_lock_cfg.wifi_ssid), "%s", ssid);
    if (pass) snprintf(g_lock_cfg.wifi_pass, sizeof(g_lock_cfg.wifi_pass), "%s", pass);

    ESP_LOGI(TAG, "Wi-Fi settings saved to NVS: SSID=%s", g_lock_cfg.wifi_ssid);
    return ESP_OK;
}

esp_err_t lock_config_save_mqtt(const char *broker, uint16_t port,
                               const char *user, const char *pass,
                               const char *topic, const char *name,
                               uint16_t auto_lock_sec)
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NS, NVS_READWRITE, &handle);
    if (err != ESP_OK) return err;

    if (broker) nvs_set_str(handle, "mqtt_broker", broker);
    if (port > 0) nvs_set_u16(handle, "mqtt_port", port);
    if (user) nvs_set_str(handle, "mqtt_user", user);
    if (pass) nvs_set_str(handle, "mqtt_pass", pass);
    if (topic && strlen(topic) > 0) nvs_set_str(handle, "mqtt_topic", topic);
    if (name && strlen(name) > 0) nvs_set_str(handle, "lock_name", name);
    if (auto_lock_sec > 0) nvs_set_u16(handle, "auto_lock_sec", auto_lock_sec);

    nvs_commit(handle);
    nvs_close(handle);

    if (broker) snprintf(g_lock_cfg.mqtt_broker, sizeof(g_lock_cfg.mqtt_broker), "%s", broker);
    if (port > 0) g_lock_cfg.mqtt_port = port;
    if (user) snprintf(g_lock_cfg.mqtt_user, sizeof(g_lock_cfg.mqtt_user), "%s", user);
    if (pass) snprintf(g_lock_cfg.mqtt_pass, sizeof(g_lock_cfg.mqtt_pass), "%s", pass);
    if (topic && strlen(topic) > 0) snprintf(g_lock_cfg.mqtt_topic, sizeof(g_lock_cfg.mqtt_topic), "%s", topic);
    if (name && strlen(name) > 0) snprintf(g_lock_cfg.lock_name, sizeof(g_lock_cfg.lock_name), "%s", name);
    if (auto_lock_sec > 0) g_lock_cfg.auto_lock_sec = auto_lock_sec;

    ESP_LOGI(TAG, "MQTT settings saved to NVS: broker=%s:%d, user=%s, topic=%s, name=%s, autolock=%ds",
             g_lock_cfg.mqtt_broker, g_lock_cfg.mqtt_port, g_lock_cfg.mqtt_user,
             g_lock_cfg.mqtt_topic, g_lock_cfg.lock_name, g_lock_cfg.auto_lock_sec);
    return ESP_OK;
}

esp_err_t lock_config_save_web_pass(const char *new_pass)
{
    if (!new_pass || strlen(new_pass) == 0) return ESP_ERR_INVALID_ARG;

    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NS, NVS_READWRITE, &handle);
    if (err != ESP_OK) return err;

    nvs_set_str(handle, "web_pass", new_pass);
    nvs_commit(handle);
    nvs_close(handle);

    snprintf(g_lock_cfg.web_pass, sizeof(g_lock_cfg.web_pass), "%s", new_pass);
    ESP_LOGI(TAG, "Web UI password updated in NVS: %s", g_lock_cfg.web_pass);
    return ESP_OK;
}
