#pragma once
#include "esp_err.h"

typedef enum {
    BLE_ACTION_UNLOCK = 0,
    BLE_ACTION_CHILD_LOCK,       /* param: 1 = enable, 0 = disable */
    BLE_ACTION_ANTI_LOCK,        /* param: 1 = enable, 0 = disable */
    BLE_ACTION_REFRESH_STATUS,   /* connect, auth, read status handles */
} ble_action_t;

void miot_ble_start(void);
void miot_ble_trigger_action(ble_action_t action, int param);
void miot_ble_trigger_unlock(void);
