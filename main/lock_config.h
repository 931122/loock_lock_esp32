#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

typedef struct {
    char mac[18];             /* e.g. "04:CD:15:AA:BB:CC" */
    uint8_t ltmk[32];         /* 32-byte derived LTMK binary */
    char ltmk_hex[65];        /* 64-hex string of derived LTMK */
    char wifi_ssid[33];       /* Wi-Fi SSID */
    char wifi_pass[65];       /* Wi-Fi Password */
    char web_pass[33];        /* Web UI login password (default "admin") */
    char mqtt_broker[64];     /* e.g. "192.168.1.100" */
    uint16_t mqtt_port;       /* e.g. 1883 */
    char mqtt_user[32];       /* e.g. "mqtt_user" */
    char mqtt_pass[32];       /* e.g. "mqtt_password" */
    char mqtt_topic[48];      /* e.g. "lockbridge/loock" */
    char lock_name[32];       /* e.g. "鹿客门锁" */
    uint16_t auto_lock_sec;   /* e.g. 4 seconds */
    bool is_configured;
} lock_config_t;

typedef struct {
    uint8_t battery;            /* 0..100, 255 = unknown */
    int     child_lock;         /* 1 = ON, 0 = OFF, -1 = unknown */
    int     anti_lock;          /* 1 = ON, 0 = OFF, -1 = unknown */
    int     door_state;         /* 1 = CLOSED, 0 = OPEN, 0xF3 = AJAR, 0xF4 = UNLOCKED_CLOSED, -1 = unknown */
    char    door_state_str[24]; /* "CLOSED", "OPEN", "AJAR", "UNLOCKED_CLOSED", "UNKNOWN" */
    char    lock_state_str[16]; /* "LOCKED", "UNLOCKED", "UNLOCKING" */
    uint32_t last_update;       /* system tick */
} lock_live_state_t;

extern lock_config_t g_lock_cfg;
extern lock_live_state_t g_lock_state;

/* Load configuration from NVS (or fallback to compiled defaults) */
esp_err_t lock_config_init(void);

/*
 * Derives the real LTMK from (raw_ltmk_hex, encrypt_type, pin, optional iv_hex),
 * securely wipes the PIN from memory, and saves ONLY (mac, derived_ltmk) to NVS.
 * PIN is NEVER persisted to flash!
 */
esp_err_t lock_config_derive_and_save(const char *mac,
                                     const char *raw_ltmk_hex,
                                     int encrypt_type,
                                     const char *pin,
                                     const char *iv_hex);

/* Save updated MQTT settings to NVS */
esp_err_t lock_config_save_mqtt(const char *broker, uint16_t port,
                               const char *user, const char *pass,
                               const char *topic, const char *name,
                               uint16_t auto_lock_sec);

/* Save updated Wi-Fi settings to NVS */
esp_err_t lock_config_save_wifi(const char *ssid, const char *pass);

/* Save updated Web UI login password to NVS */
esp_err_t lock_config_save_web_pass(const char *new_pass);
