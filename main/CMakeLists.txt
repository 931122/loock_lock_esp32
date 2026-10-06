idf_component_register(
    SRCS "main.c" "security_chip.c" "miot_ble.c" "net_log.c" "ota_server.c" "lock_config.c" "mqtt_handler.c"
    INCLUDE_DIRS "."
    REQUIRES nvs_flash bt mbedtls esp_wifi esp_netif lwip esp_event esp_http_server app_update esp_partition esp_app_format mqtt esp_rom
)
