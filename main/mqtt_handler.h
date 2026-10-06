#pragma once
#include <stdbool.h>
#include "esp_err.h"

esp_err_t mqtt_handler_start(void);
void mqtt_handler_stop(void);
void mqtt_handler_publish_state(const char *state);
void mqtt_handler_publish_battery(uint8_t battery);
void mqtt_handler_publish_child_lock(const char *state);
void mqtt_handler_publish_anti_lock(const char *state);
void mqtt_handler_publish_door(const char *detail, const char *contact);
