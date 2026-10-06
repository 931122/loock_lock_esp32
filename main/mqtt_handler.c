#include "mqtt_handler.h"
#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "mqtt_client.h"
#include "lock_config.h"
#include "miot_ble.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "MQTT_HDL";
static esp_mqtt_client_handle_t s_mqtt_client = NULL;
static bool s_is_connected = false;

static char s_topic_set[96] = "lockbridge/loock/set";
static char s_topic_state[96] = "lockbridge/loock/state";
static char s_topic_avail[96] = "lockbridge/loock/availability";
static char s_topic_battery[96] = "lockbridge/loock/battery";
static char s_topic_child_lock_state[96] = "lockbridge/loock/child_lock/state";
static char s_topic_child_lock_set[96] = "lockbridge/loock/child_lock/set";
static char s_topic_anti_lock_state[96] = "lockbridge/loock/anti_lock/state";
static char s_topic_anti_lock_set[96] = "lockbridge/loock/anti_lock/set";
static char s_topic_door_state[96] = "lockbridge/loock/door/state";
static char s_topic_door_detail[96] = "lockbridge/loock/door/detail";
static char s_topic_refresh_set[96] = "lockbridge/loock/refresh/set";

static char s_dev_id[48] = "lockbridge_loock";

static void auto_relock_task(void *param)
{
    uint32_t delay_sec = (g_lock_cfg.auto_lock_sec > 0) ? g_lock_cfg.auto_lock_sec : 4;
    vTaskDelay(pdMS_TO_TICKS(delay_sec * 1000));
    if (s_mqtt_client && s_is_connected) {
        ESP_LOGI(TAG, "Restoring MQTT state to LOCKED after %lu seconds", (unsigned long)delay_sec);
        esp_mqtt_client_publish(s_mqtt_client, s_topic_state, "LOCKED", 0, 1, 1);
        strlcpy(g_lock_state.lock_state_str, "LOCKED", sizeof(g_lock_state.lock_state_str));
    }
    vTaskDelete(NULL);
}

void mqtt_handler_publish_state(const char *state)
{
    if (!s_mqtt_client || !s_is_connected) return;

    ESP_LOGI(TAG, "Publishing MQTT lock state: %s to %s", state, s_topic_state);
    esp_mqtt_client_publish(s_mqtt_client, s_topic_state, state, 0, 1, 1);
    strlcpy(g_lock_state.lock_state_str, state, sizeof(g_lock_state.lock_state_str));

    if (strcmp(state, "UNLOCKED") == 0) {
        xTaskCreate(auto_relock_task, "relock_task", 2048, NULL, 5, NULL);
    }
}

void mqtt_handler_publish_battery(uint8_t battery)
{
    if (!s_mqtt_client || !s_is_connected) return;
    char buf[16];
    snprintf(buf, sizeof(buf), "%u", battery);
    ESP_LOGI(TAG, "Publishing battery: %s%% to %s", buf, s_topic_battery);
    esp_mqtt_client_publish(s_mqtt_client, s_topic_battery, buf, 0, 1, 1);
}

void mqtt_handler_publish_child_lock(const char *state)
{
    if (!s_mqtt_client || !s_is_connected) return;
    ESP_LOGI(TAG, "Publishing child lock state: %s to %s", state, s_topic_child_lock_state);
    esp_mqtt_client_publish(s_mqtt_client, s_topic_child_lock_state, state, 0, 1, 1);
}

void mqtt_handler_publish_anti_lock(const char *state)
{
    if (!s_mqtt_client || !s_is_connected) return;
    ESP_LOGI(TAG, "Publishing anti lock state: %s to %s", state, s_topic_anti_lock_state);
    esp_mqtt_client_publish(s_mqtt_client, s_topic_anti_lock_state, state, 0, 1, 1);
}

void mqtt_handler_publish_door(const char *detail, const char *contact)
{
    if (!s_mqtt_client || !s_is_connected) return;
    ESP_LOGI(TAG, "Publishing door contact: %s, detail: %s", contact, detail);
    esp_mqtt_client_publish(s_mqtt_client, s_topic_door_state, contact, 0, 1, 1);
    esp_mqtt_client_publish(s_mqtt_client, s_topic_door_detail, detail, 0, 1, 1);
}

static void publish_ha_discovery(void)
{
    char topic_disc[128];
    char payload[1024];
    const char *lock_name = g_lock_cfg.lock_name[0] ? g_lock_cfg.lock_name : "鹿客门锁";

    /* Common Device JSON fragment */
    char dev_json[256];
    snprintf(dev_json, sizeof(dev_json),
        "\"device\":{\"identifiers\":[\"%s\"],\"name\":\"%s\","
        "\"manufacturer\":\"Loock / Xiaomi\",\"model\":\"loock.lock.v16\",\"sw_version\":\"2.0-esp32\"}",
        s_dev_id, lock_name);

    /* 1. Lock Entity */
    snprintf(topic_disc, sizeof(topic_disc), "homeassistant/lock/%s/config", s_dev_id);
    snprintf(payload, sizeof(payload),
        "{"
        "\"name\":\"%s\","
        "\"unique_id\":\"%s_lock\","
        "\"command_topic\":\"%s\","
        "\"state_topic\":\"%s\","
        "\"availability_topic\":\"%s\","
        "\"payload_available\":\"online\","
        "\"payload_not_available\":\"offline\","
        "\"payload_unlock\":\"UNLOCK\","
        "\"payload_lock\":\"LOCK\","
        "\"state_unlocked\":\"UNLOCKED\","
        "\"state_locked\":\"LOCKED\","
        "\"optimistic\":true,"
        "\"qos\":0,"
        "\"retain\":false,"
        "%s"
        "}",
        lock_name, s_dev_id, s_topic_set, s_topic_state, s_topic_avail, dev_json);
    esp_mqtt_client_publish(s_mqtt_client, topic_disc, payload, 0, 1, 1);

    /* 2. Battery Sensor */
    snprintf(topic_disc, sizeof(topic_disc), "homeassistant/sensor/%s_battery/config", s_dev_id);
    snprintf(payload, sizeof(payload),
        "{"
        "\"name\":\"门锁电量\","
        "\"unique_id\":\"%s_battery\","
        "\"state_topic\":\"%s\","
        "\"device_class\":\"battery\","
        "\"unit_of_measurement\":\"%%\","
        "\"availability_topic\":\"%s\","
        "%s"
        "}",
        s_dev_id, s_topic_battery, s_topic_avail, dev_json);
    esp_mqtt_client_publish(s_mqtt_client, topic_disc, payload, 0, 1, 1);

    /* 3. Child Lock Switch */
    snprintf(topic_disc, sizeof(topic_disc), "homeassistant/switch/%s_child_lock/config", s_dev_id);
    snprintf(payload, sizeof(payload),
        "{"
        "\"name\":\"门内童锁\","
        "\"unique_id\":\"%s_child_lock\","
        "\"state_topic\":\"%s\","
        "\"command_topic\":\"%s\","
        "\"payload_on\":\"ON\","
        "\"payload_off\":\"OFF\","
        "\"state_on\":\"ON\","
        "\"state_off\":\"OFF\","
        "\"icon\":\"mdi:baby-face-outline\","
        "\"availability_topic\":\"%s\","
        "%s"
        "}",
        s_dev_id, s_topic_child_lock_state, s_topic_child_lock_set, s_topic_avail, dev_json);
    esp_mqtt_client_publish(s_mqtt_client, topic_disc, payload, 0, 1, 1);

    /* 4. Anti-Lock Switch */
    snprintf(topic_disc, sizeof(topic_disc), "homeassistant/switch/%s_anti_lock/config", s_dev_id);
    snprintf(payload, sizeof(payload),
        "{"
        "\"name\":\"电子反锁\","
        "\"unique_id\":\"%s_anti_lock\","
        "\"state_topic\":\"%s\","
        "\"command_topic\":\"%s\","
        "\"payload_on\":\"ON\","
        "\"payload_off\":\"OFF\","
        "\"state_on\":\"ON\","
        "\"state_off\":\"OFF\","
        "\"icon\":\"mdi:lock-alert\","
        "\"availability_topic\":\"%s\","
        "%s"
        "}",
        s_dev_id, s_topic_anti_lock_state, s_topic_anti_lock_set, s_topic_avail, dev_json);
    esp_mqtt_client_publish(s_mqtt_client, topic_disc, payload, 0, 1, 1);

    /* 5. Door Contact Binary Sensor */
    snprintf(topic_disc, sizeof(topic_disc), "homeassistant/binary_sensor/%s_door/config", s_dev_id);
    snprintf(payload, sizeof(payload),
        "{"
        "\"name\":\"门状态\","
        "\"unique_id\":\"%s_door\","
        "\"state_topic\":\"%s\","
        "\"device_class\":\"door\","
        "\"payload_on\":\"ON\","
        "\"payload_off\":\"OFF\","
        "\"availability_topic\":\"%s\","
        "%s"
        "}",
        s_dev_id, s_topic_door_state, s_topic_avail, dev_json);
    esp_mqtt_client_publish(s_mqtt_client, topic_disc, payload, 0, 1, 1);

    /* 6. Door Detail Sensor */
    snprintf(topic_disc, sizeof(topic_disc), "homeassistant/sensor/%s_door_detail/config", s_dev_id);
    snprintf(payload, sizeof(payload),
        "{"
        "\"name\":\"门体详情\","
        "\"unique_id\":\"%s_door_detail\","
        "\"state_topic\":\"%s\","
        "\"icon\":\"mdi:door\","
        "\"availability_topic\":\"%s\","
        "%s"
        "}",
        s_dev_id, s_topic_door_detail, s_topic_avail, dev_json);
    esp_mqtt_client_publish(s_mqtt_client, topic_disc, payload, 0, 1, 1);

    ESP_LOGI(TAG, "All Home Assistant MQTT Discovery entities published successfully!");
}

static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data)
{
    esp_mqtt_event_handle_t event = event_data;
    switch ((esp_mqtt_event_id_t)event_id) {
    case MQTT_EVENT_CONNECTED:
        ESP_LOGI(TAG, "MQTT Connected to broker %s:%d!", g_lock_cfg.mqtt_broker, g_lock_cfg.mqtt_port);
        s_is_connected = true;

        /* 1. Publish Availability = online (retain) */
        esp_mqtt_client_publish(s_mqtt_client, s_topic_avail, "online", 0, 1, 1);

        /* 2. Publish Home Assistant Discovery for all entities (retain) */
        publish_ha_discovery();

        /* 3. Publish initial lock state = LOCKED (retain) */
        esp_mqtt_client_publish(s_mqtt_client, s_topic_state, "LOCKED", 0, 1, 1);

        /* 4. Subscribe to Command Topics */
        esp_mqtt_client_subscribe(s_mqtt_client, s_topic_set, 0);
        esp_mqtt_client_subscribe(s_mqtt_client, s_topic_child_lock_set, 0);
        esp_mqtt_client_subscribe(s_mqtt_client, s_topic_anti_lock_set, 0);
        esp_mqtt_client_subscribe(s_mqtt_client, s_topic_refresh_set, 0);
        ESP_LOGI(TAG, "Subscribed to MQTT control topics");
        break;

    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGW(TAG, "MQTT Disconnected from broker");
        s_is_connected = false;
        break;

    case MQTT_EVENT_DATA: {
        char data_buf[64] = {0};
        int len = event->data_len < sizeof(data_buf) - 1 ? event->data_len : sizeof(data_buf) - 1;
        memcpy(data_buf, event->data, len);
        data_buf[len] = '\0';

        char topic_buf[128] = {0};
        int tlen = event->topic_len < sizeof(topic_buf) - 1 ? event->topic_len : sizeof(topic_buf) - 1;
        memcpy(topic_buf, event->topic, tlen);
        topic_buf[tlen] = '\0';

        ESP_LOGI(TAG, "MQTT command received on %s: [%s]", topic_buf, data_buf);

        if (strcmp(topic_buf, s_topic_set) == 0) {
            if (strstr(data_buf, "UNLOCK") != NULL) {
                ESP_LOGI(TAG, "Triggering BLE unlock from Home Assistant MQTT command!");
                mqtt_handler_publish_state("UNLOCKING");
                miot_ble_trigger_action(BLE_ACTION_UNLOCK, 0);
            }
        } else if (strcmp(topic_buf, s_topic_child_lock_set) == 0) {
            bool enable = (strcasecmp(data_buf, "ON") == 0 || strcmp(data_buf, "1") == 0);
            ESP_LOGI(TAG, "Triggering BLE Child Lock set=%d from MQTT!", (int)enable);
            miot_ble_trigger_action(BLE_ACTION_CHILD_LOCK, enable ? 1 : 0);
        } else if (strcmp(topic_buf, s_topic_anti_lock_set) == 0) {
            bool enable = (strcasecmp(data_buf, "ON") == 0 || strcmp(data_buf, "1") == 0);
            ESP_LOGI(TAG, "Triggering BLE Anti Lock set=%d from MQTT!", (int)enable);
            miot_ble_trigger_action(BLE_ACTION_ANTI_LOCK, enable ? 1 : 0);
        } else if (strcmp(topic_buf, s_topic_refresh_set) == 0) {
            ESP_LOGI(TAG, "Triggering BLE status refresh from MQTT!");
            miot_ble_trigger_action(BLE_ACTION_REFRESH_STATUS, 0);
        }
        break;
    }

    default:
        break;
    }
}

esp_err_t mqtt_handler_start(void)
{
    if (s_mqtt_client != NULL) {
        return ESP_OK;
    }

    const char *base_topic = g_lock_cfg.mqtt_topic[0] ? g_lock_cfg.mqtt_topic : "lockbridge/loock";

    snprintf(s_topic_set, sizeof(s_topic_set), "%s/set", base_topic);
    snprintf(s_topic_state, sizeof(s_topic_state), "%s/state", base_topic);
    snprintf(s_topic_avail, sizeof(s_topic_avail), "%s/availability", base_topic);
    snprintf(s_topic_battery, sizeof(s_topic_battery), "%s/battery", base_topic);
    snprintf(s_topic_child_lock_state, sizeof(s_topic_child_lock_state), "%s/child_lock/state", base_topic);
    snprintf(s_topic_child_lock_set, sizeof(s_topic_child_lock_set), "%s/child_lock/set", base_topic);
    snprintf(s_topic_anti_lock_state, sizeof(s_topic_anti_lock_state), "%s/anti_lock/state", base_topic);
    snprintf(s_topic_anti_lock_set, sizeof(s_topic_anti_lock_set), "%s/anti_lock/set", base_topic);
    snprintf(s_topic_door_state, sizeof(s_topic_door_state), "%s/door/state", base_topic);
    snprintf(s_topic_door_detail, sizeof(s_topic_door_detail), "%s/door/detail", base_topic);
    snprintf(s_topic_refresh_set, sizeof(s_topic_refresh_set), "%s/refresh/set", base_topic);

    for (size_t i = 0; i < strlen(base_topic) && i < sizeof(s_dev_id) - 1; i++) {
        char c = base_topic[i];
        s_dev_id[i] = (c == '/' || c == ' ') ? '_' : c;
    }
    s_dev_id[strlen(base_topic)] = '\0';

    char uri[128];
    snprintf(uri, sizeof(uri), "mqtt://%s:%d", g_lock_cfg.mqtt_broker, g_lock_cfg.mqtt_port);

    ESP_LOGI(TAG, "Configuring MQTT client: uri=%s, user=%s, topic_base=%s, name=%s",
             uri, g_lock_cfg.mqtt_user, base_topic, g_lock_cfg.lock_name);

    esp_mqtt_client_config_t mqtt_cfg = {
        .broker = {
            .address.uri = uri,
        },
        .credentials = {
            .username = g_lock_cfg.mqtt_user,
            .authentication.password = g_lock_cfg.mqtt_pass,
        },
        .session = {
            .last_will = {
                .topic = s_topic_avail,
                .msg = "offline",
                .msg_len = 7,
                .qos = 1,
                .retain = 1,
            },
        },
    };

    s_mqtt_client = esp_mqtt_client_init(&mqtt_cfg);
    if (!s_mqtt_client) {
        ESP_LOGE(TAG, "Failed to initialize MQTT client");
        return ESP_FAIL;
    }

    esp_mqtt_client_register_event(s_mqtt_client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
    return esp_mqtt_client_start(s_mqtt_client);
}

void mqtt_handler_stop(void)
{
    if (s_mqtt_client) {
        esp_mqtt_client_stop(s_mqtt_client);
        esp_mqtt_client_destroy(s_mqtt_client);
        s_mqtt_client = NULL;
        s_is_connected = false;
    }
}
