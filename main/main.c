#include <string.h>
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lock_config.h"
#include "miot_ble.h"
#include "mqtt_handler.h"
#include "net_log.h"
#include "ota_server.h"
#include "esp_sntp.h"

static const char *TAG = "APP_MAIN";

static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        ESP_LOGI(TAG, "Wi-Fi started, connecting to SSID '%s'...", g_lock_cfg.wifi_ssid);
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_event_sta_disconnected_t *dis = (wifi_event_sta_disconnected_t *)event_data;
        ESP_LOGW(TAG, "Wi-Fi disconnected (reason=%d), reconnecting...", dis->reason);
        mqtt_handler_stop();
        ota_server_stop();
        net_log_stop();
        esp_wifi_connect();
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        char ip_str[32];
        esp_ip4addr_ntoa(&event->ip_info.ip, ip_str, sizeof(ip_str));
        ESP_LOGI(TAG, "Wi-Fi connected! Got IP: %s", ip_str);

        /* Start UDP broadcast/unicast logging now that IP is active */
        net_log_start(ip_str);

        /* Start HTTP Web UI & OTA Server */
        ota_server_start();

        /* Start Home Assistant MQTT integration */
        mqtt_handler_start();

        /* Start SNTP time sync for OTP generation */
        if (!esp_sntp_enabled()) {
            esp_sntp_setoperatingmode(ESP_SNTP_OPMODE_POLL);
            esp_sntp_setservername(0, "ntp.aliyun.com");
            esp_sntp_setservername(1, "pool.ntp.org");
            esp_sntp_init();
        }

        ESP_LOGI(TAG, "=======================================================");
        ESP_LOGI(TAG, "=== Network logging active on UDP port %d ===", NET_LOG_PORT);
        ESP_LOGI(TAG, "=== HTTP OTA Web UI active at http://%s/ ===", ip_str);
        ESP_LOGI(TAG, "=== Home Assistant MQTT connecting to %s:%d ===", g_lock_cfg.mqtt_broker, g_lock_cfg.mqtt_port);
        ESP_LOGI(TAG, "=== System ready. Waiting for explicit unlock command. ===");
        ESP_LOGI(TAG, "=======================================================");
    }
}

void app_main(void)
{
    /* 1. NVS Flash init */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_LOGI(TAG, "=== LockBridge ESP32 Starting Up ===");

    /* 2. Load Lock, Wi-Fi & MQTT runtime configuration from NVS */
    lock_config_init();

    /* 3. Initialize BLE stack (enters idle state, does NOT auto-unlock) */
    miot_ble_start();

    /* 4. Network Logging init (hooks vprintf) */
    net_log_init();

    /* 5. TCP/IP and Event Loop init */
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    /* 6. Wi-Fi init in STA mode with configured SSID & Password */
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        &instance_got_ip));

    wifi_config_t wifi_config = {0};
    strlcpy((char *)wifi_config.sta.ssid, g_lock_cfg.wifi_ssid, sizeof(wifi_config.sta.ssid));
    strlcpy((char *)wifi_config.sta.password, g_lock_cfg.wifi_pass, sizeof(wifi_config.sta.password));
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Boot complete. Connecting to Wi-Fi SSID '%s'...", g_lock_cfg.wifi_ssid);
}
