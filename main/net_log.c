#include "net_log.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "miot_ble.h"

static const char *TAG = "NET_LOG";

static int udp_tx_sock = -1;
static int udp_rx_sock = -1;
static struct sockaddr_in bcast_addr;
static struct sockaddr_in unicast_addr;
static volatile bool s_ready = false;
static SemaphoreHandle_t s_log_mutex = NULL;
static TaskHandle_t s_rx_task_handle = NULL;

static vprintf_like_t s_default_vprintf = NULL;

static int net_log_vprintf(const char *fmt, va_list args)
{
    /* Always output to local default IDF console */
    va_list copy1, copy2;
    va_copy(copy1, args);
    va_copy(copy2, args);
    int ret = 0;
    if (s_default_vprintf) {
        ret = s_default_vprintf(fmt, copy1);
    } else {
        ret = vprintf(fmt, copy1);
    }
    va_end(copy1);

    if (!s_ready || udp_tx_sock < 0) {
        va_end(copy2);
        return ret;
    }

    char buf[512];
    int len = vsnprintf(buf, sizeof(buf), fmt, copy2);
    va_end(copy2);

    if (len > 0) {
        if (len > sizeof(buf)) len = sizeof(buf);
        if (s_log_mutex && xSemaphoreTake(s_log_mutex, pdMS_TO_TICKS(5)) == pdTRUE) {
            if (udp_tx_sock >= 0) {
                if (unicast_addr.sin_addr.s_addr != 0) {
                    sendto(udp_tx_sock, buf, len, 0, (struct sockaddr *)&unicast_addr, sizeof(unicast_addr));
                }
                sendto(udp_tx_sock, buf, len, 0, (struct sockaddr *)&bcast_addr, sizeof(bcast_addr));
            }
            xSemaphoreGive(s_log_mutex);
        }
    }
    return ret;
}

static void udp_rx_task(void *pvParameters)
{
    udp_rx_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (udp_rx_sock < 0) {
        ESP_LOGE(TAG, "Unable to create RX socket: errno %d", errno);
        s_rx_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }

    struct sockaddr_in saddr = {
        .sin_family = AF_INET,
        .sin_port = htons(NET_LOG_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };

    int opt = 1;
    setsockopt(udp_rx_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(udp_rx_sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        ESP_LOGE(TAG, "Socket unable to bind: errno %d", errno);
        close(udp_rx_sock);
        udp_rx_sock = -1;
        s_rx_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "UDP Command listener started on port %d", NET_LOG_PORT);

    char rx_buffer[128];
    while (s_ready) {
        struct sockaddr_in source_addr;
        socklen_t socklen = sizeof(source_addr);
        int len = recvfrom(udp_rx_sock, rx_buffer, sizeof(rx_buffer) - 1, 0,
                           (struct sockaddr *)&source_addr, &socklen);
        if (len > 0) {
            unicast_addr = source_addr;
            rx_buffer[len] = '\0';
            while (len > 0 && (rx_buffer[len - 1] == '\r' || rx_buffer[len - 1] == '\n')) {
                rx_buffer[--len] = '\0';
            }
            ESP_LOGI(TAG, "Received network command: '%s'", rx_buffer);
            if (strcasecmp(rx_buffer, "unlock") == 0 ||
                strcasecmp(rx_buffer, "open") == 0 ||
                strcasecmp(rx_buffer, "retry") == 0) {
                ESP_LOGI(TAG, "Triggering unlock command via network request!");
                miot_ble_trigger_unlock();
            }
        }
    }

    close(udp_rx_sock);
    udp_rx_sock = -1;
    s_rx_task_handle = NULL;
    vTaskDelete(NULL);
}

void net_log_init(void)
{
    if (!s_log_mutex) {
        s_log_mutex = xSemaphoreCreateMutex();
    }
    s_default_vprintf = esp_log_set_vprintf(net_log_vprintf);
}

void net_log_start(const char *local_ip)
{
    if (s_ready) return;

    if (!s_log_mutex) {
        s_log_mutex = xSemaphoreCreateMutex();
    }

    udp_tx_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (udp_tx_sock < 0) {
        ESP_LOGE(TAG, "Unable to create UDP TX socket: errno %d", errno);
        return;
    }

    int broadcast = 1;
    setsockopt(udp_tx_sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));

    struct timeval tv = { .tv_sec = 0, .tv_usec = 20000 };
    setsockopt(udp_tx_sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    memset(&bcast_addr, 0, sizeof(bcast_addr));
    bcast_addr.sin_family = AF_INET;
    bcast_addr.sin_port = htons(NET_LOG_PORT);
    bcast_addr.sin_addr.s_addr = inet_addr("255.255.255.255");

    memset(&unicast_addr, 0, sizeof(unicast_addr));
    unicast_addr.sin_family = AF_INET;
    unicast_addr.sin_port = htons(NET_LOG_PORT);
    unicast_addr.sin_addr.s_addr = 0; /* Dynamic learning from incoming UDP packets */

    s_ready = true;

    if (!s_rx_task_handle) {
        xTaskCreate(udp_rx_task, "udp_rx_task", 4096, NULL, 5, &s_rx_task_handle);
    }
}

void net_log_stop(void)
{
    s_ready = false;
    if (s_log_mutex) {
        xSemaphoreTake(s_log_mutex, portMAX_DELAY);
    }
    if (udp_tx_sock >= 0) {
        close(udp_tx_sock);
        udp_tx_sock = -1;
    }
    if (s_log_mutex) {
        xSemaphoreGive(s_log_mutex);
    }
}
