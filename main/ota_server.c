#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/param.h>
#include "esp_log.h"
#include "esp_http_server.h"
#include "esp_ota_ops.h"
#include "esp_app_format.h"
#include "esp_system.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lock_config.h"
#include "miot_ble.h"
#include "mqtt_handler.h"
#include "ota_server.h"
#include "security_chip.h"
#include <time.h>
#include <inttypes.h>

static const char *TAG = "OTA_SERVER";
static httpd_handle_t s_server = NULL;

static void restart_task(void *param)
{
    vTaskDelay(pdMS_TO_TICKS(2000));
    ESP_LOGI(TAG, "Restarting now...");
    esp_restart();
    vTaskDelete(NULL);
}

static bool json_get_string(const char *json, const char *key, char *out, size_t out_len)
{
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) return false;
    p = strchr(p, ':');
    if (!p) return false;
    p = strchr(p, '"');
    if (!p) return false;
    p++;
    const char *end = strchr(p, '"');
    if (!end) return false;
    size_t len = end - p;
    if (len >= out_len) len = out_len - 1;
    memcpy(out, p, len);
    out[len] = '\0';
    return true;
}

static bool json_get_int(const char *json, const char *key, int *val)
{
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) return false;
    p = strchr(p, ':');
    if (!p) return false;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    *val = atoi(p);
    return true;
}

static char s_session_token[33] = {0};

static void generate_token(char *out, size_t out_len)
{
    uint32_t r1 = esp_random();
    uint32_t r2 = esp_random();
    uint32_t r3 = esp_random();
    uint32_t r4 = esp_random();
    snprintf(out, out_len, "%08lx%08lx%08lx%08lx",
             (unsigned long)r1, (unsigned long)r2,
             (unsigned long)r3, (unsigned long)r4);
}

static bool is_authenticated(httpd_req_t *req)
{
    if (g_lock_cfg.web_pass[0] == '\0') {
        return true;
    }

    char hdr_buf[256];
    /* 1. Cookie */
    if (httpd_req_get_hdr_value_str(req, "Cookie", hdr_buf, sizeof(hdr_buf)) == ESP_OK) {
        if (s_session_token[0] != '\0') {
            const char *p = strstr(hdr_buf, "session=");
            if (p) {
                p += 8;
                if (strncmp(p, s_session_token, strlen(s_session_token)) == 0) {
                    return true;
                }
            }
        }
    }

    /* 2. X-Auth-Password header */
    if (httpd_req_get_hdr_value_str(req, "X-Auth-Password", hdr_buf, sizeof(hdr_buf)) == ESP_OK) {
        if (strcmp(hdr_buf, g_lock_cfg.web_pass) == 0) {
            return true;
        }
    }

    /* 3. Authorization: Bearer <token/pass> */
    if (httpd_req_get_hdr_value_str(req, "Authorization", hdr_buf, sizeof(hdr_buf)) == ESP_OK) {
        if (strncmp(hdr_buf, "Bearer ", 7) == 0) {
            const char *t = hdr_buf + 7;
            if (strcmp(t, g_lock_cfg.web_pass) == 0 ||
                (s_session_token[0] != '\0' && strcmp(t, s_session_token) == 0)) {
                return true;
            }
        }
    }

    /* 4. Query param ?pass=admin or ?token=... */
    if (httpd_req_get_url_query_str(req, hdr_buf, sizeof(hdr_buf)) == ESP_OK) {
        char val[64];
        if (httpd_query_key_value(hdr_buf, "pass", val, sizeof(val)) == ESP_OK) {
            if (strcmp(val, g_lock_cfg.web_pass) == 0) {
                return true;
            }
        }
        if (s_session_token[0] != '\0' && httpd_query_key_value(hdr_buf, "token", val, sizeof(val)) == ESP_OK) {
            if (strcmp(val, s_session_token) == 0) {
                return true;
            }
        }
    }

    return false;
}

static esp_err_t send_unauthorized(httpd_req_t *req)
{
    httpd_resp_set_status(req, "401 Unauthorized");
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, "{\"status\":\"error\",\"message\":\"登录凭证已过期或未授权，请重新登录\"}", HTTPD_RESP_USE_STRLEN);
}

static esp_err_t send_login_page(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    const char *html =
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>安全验证 · 鹿客智能门锁网关</title>"
        "<style>"
        "*{box-sizing:border-box;margin:0;padding:0;}"
        "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'PingFang SC','Hiragino Sans GB','Microsoft YaHei',sans-serif;background:#f5f6f8;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px;}"
        ".card{background:#ffffff;width:100%;max-width:380px;padding:36px 28px;border-radius:16px;box-shadow:0 8px 30px rgba(0,0,0,0.06);border:1px solid #eef0f3;text-align:center;}"
        ".icon{font-size:42px;margin-bottom:12px;display:inline-block;}"
        "h1{font-size:20px;color:#1d2129;margin-bottom:6px;font-weight:700;}"
        "p{font-size:13px;color:#86909c;margin-bottom:28px;}"
        ".input-box{position:relative;margin-bottom:20px;}"
        "input{width:100%;padding:13px 16px;font-size:15px;border:1.5px solid #e5e6eb;border-radius:10px;outline:none;transition:all .2s;text-align:center;background:#f7f8fa;}"
        "input:focus{border-color:#165dff;background:#ffffff;box-shadow:0 0 0 3px rgba(22,93,255,0.12);}"
        ".btn{width:100%;padding:13px;font-size:15px;font-weight:600;color:#ffffff;background:#165dff;border:none;border-radius:10px;cursor:pointer;transition:all .2s;}"
        ".btn:hover{background:#0e42d2;}"
        ".btn:active{transform:scale(0.99);}"
        ".btn:disabled{opacity:0.6;cursor:not-allowed;}"
        ".err{margin-top:14px;font-size:13px;color:#f53f3f;background:#ffece8;padding:10px 14px;border-radius:8px;display:none;border:1px solid #fde2e2;}"
        ".footer-note{font-size:12px;color:#86909c;margin-top:24px;line-height:1.4;}"
        "</style></head><body>"
        "<div class='card'>"
        "<div class='icon'>🛡️</div>"
        "<h1>鹿客智能门锁网关</h1>"
        "<p>Loock Smart Gateway · 管理安全验证</p>"
        "<div class='input-box'>"
        "<input type='password' id='pwd' placeholder='请输入访问密码' autofocus>"
        "</div>"
        "<button id='btn' class='btn' onclick='doLogin()'>登 录</button>"
        "<div id='err' class='err'></div>"
        "<div class='footer-note'>默认密码：admin · 首次登录后可在系统设置中修改</div>"
        "</div>"
        "<script>"
        "function doLogin(){"
        "  var p=document.getElementById('pwd').value;"
        "  if(!p){showErr('请输入访问密码');return;}"
        "  var btn=document.getElementById('btn');"
        "  btn.disabled=true;btn.innerText='正在验证...';"
        "  fetch('/login',{"
        "    method:'POST',"
        "    headers:{'Content-Type':'application/json'},"
        "    body:JSON.stringify({password:p})"
        "  }).then(function(r){return r.json();}).then(function(d){"
        "    if(d.status==='ok'){"
        "      location.reload();"
        "    }else{"
        "      showErr(d.message||'访问密码错误，请重新输入');"
        "      btn.disabled=false;btn.innerText='登 录';"
        "    }"
        "  }).catch(function(e){"
        "    showErr('网络通信异常，请重试');"
        "    btn.disabled=false;btn.innerText='登 录';"
        "  });"
        "}"
        "function showErr(msg){"
        "  var el=document.getElementById('err');"
        "  el.style.display='block';el.innerText=msg;"
        "}"
        "document.getElementById('pwd').addEventListener('keydown',function(e){"
        "  if(e.key==='Enter')doLogin();"
        "});"
        "</script>"
        "</body></html>";

    return httpd_resp_send(req, html, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t login_post_handler(httpd_req_t *req)
{
    char buf[128] = {0};
    int ret = httpd_req_recv(req, buf, MIN(req->content_len, sizeof(buf) - 1));
    if (ret <= 0) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"status\":\"error\",\"message\":\"Empty request\"}");
        return ESP_OK;
    }
    buf[ret] = '\0';

    char pwd[64] = {0};
    if (!json_get_string(buf, "password", pwd, sizeof(pwd))) {
        const char *p = strstr(buf, "password=");
        if (p) {
            strlcpy(pwd, p + 9, sizeof(pwd));
            char *amp = strchr(pwd, '&');
            if (amp) *amp = '\0';
        }
    }

    if (strcmp(pwd, g_lock_cfg.web_pass) == 0) {
        if (s_session_token[0] == '\0') {
            generate_token(s_session_token, sizeof(s_session_token));
        }
        char cookie_hdr[128];
        snprintf(cookie_hdr, sizeof(cookie_hdr), "session=%s; Path=/; Max-Age=2592000; SameSite=Lax", s_session_token);
        httpd_resp_set_hdr(req, "Set-Cookie", cookie_hdr);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"status\":\"ok\",\"message\":\"Login successful\"}");
        ESP_LOGI(TAG, "Web UI login successful!");
        return ESP_OK;
    }

    ESP_LOGW(TAG, "Web UI login failed: invalid password");
    httpd_resp_set_status(req, "401 Unauthorized");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"status\":\"error\",\"message\":\"密码错误，请重新输入\"}");
    return ESP_OK;
}

static esp_err_t logout_post_handler(httpd_req_t *req)
{
    generate_token(s_session_token, sizeof(s_session_token));
    httpd_resp_set_hdr(req, "Set-Cookie", "session=; Path=/; Max-Age=0; SameSite=Lax");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"status\":\"ok\",\"message\":\"已安全退出登录\"}");
    return ESP_OK;
}

static esp_err_t config_password_handler(httpd_req_t *req)
{
    if (!is_authenticated(req)) {
        return send_unauthorized(req);
    }

    char buf[128] = {0};
    int ret = httpd_req_recv(req, buf, MIN(req->content_len, sizeof(buf) - 1));
    if (ret <= 0) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"status\":\"error\",\"message\":\"请求内容为空\"}");
        return ESP_OK;
    }
    buf[ret] = '\0';

    char new_pwd[64] = {0};
    if (!json_get_string(buf, "password", new_pwd, sizeof(new_pwd))) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"status\":\"error\",\"message\":\"缺少访问密码参数\"}");
        return ESP_OK;
    }

    if (strlen(new_pwd) == 0) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"status\":\"error\",\"message\":\"新访问密码不能为空\"}");
        return ESP_OK;
    }

    lock_config_save_web_pass(new_pwd);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"status\":\"ok\",\"message\":\"控制台访问密码已成功更新！\"}");
    return ESP_OK;
}

/* GET / - Web UI using compact tabbed layout and chunked responses */
static esp_err_t index_get_handler(httpd_req_t *req)
{
    if (!is_authenticated(req)) {
        return send_login_page(req);
    }
    const esp_app_desc_t *app_desc = esp_app_get_description();
    const esp_partition_t *running = esp_ota_get_running_partition();

    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_ip_info_t ip_info;
    char ip_str[32] = "0.0.0.0";
    if (netif && esp_netif_get_ip_info(netif, &ip_info) == ESP_OK) {
        esp_ip4addr_ntoa(&ip_info.ip, ip_str, sizeof(ip_str));
    }

    httpd_resp_set_type(req, "text/html; charset=utf-8");

    const char *part1 =
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>鹿客智能门锁网关</title>"
        "<style>"
        "*{box-sizing:border-box;margin:0;padding:0;}"
        "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'PingFang SC','Hiragino Sans GB','Microsoft YaHei',sans-serif;max-width:540px;margin:20px auto;padding:0 14px;background:#f5f6f8;color:#1d2129;line-height:1.5;}"
        ".header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;padding:4px 2px;}"
        ".brand{display:flex;align-items:center;gap:10px;}"
        ".brand-icon{width:36px;height:36px;background:#165dff;border-radius:10px;display:flex;align-items:center;justify-content:center;color:#fff;font-size:20px;box-shadow:0 2px 8px rgba(22,93,255,0.25);}"
        ".brand-title{font-size:17px;font-weight:700;color:#1d2129;letter-spacing:-0.2px;}"
        ".brand-sub{font-size:11px;color:#86909c;font-weight:400;}"
        ".header-actions{display:flex;align-items:center;gap:10px;}"
        ".badge{display:inline-flex;align-items:center;gap:4px;padding:3px 8px;border-radius:20px;font-size:12px;font-weight:500;}"
        ".badge-live{background:#e8ffea;color:#00b42a;border:1px solid #aff0b5;}"
        ".badge-live::before{content:'';width:6px;height:6px;background:#00b42a;border-radius:50%;}"
        ".btn-logout{background:#fff;border:1px solid #e5e6eb;color:#4e5969;font-size:12px;padding:4px 10px;border-radius:6px;cursor:pointer;transition:all .2s;}"
        ".btn-logout:hover{background:#f2f3f5;color:#1d2129;}"
        ".tabs{display:flex;background:#e5e6eb;padding:3px;border-radius:10px;margin-bottom:16px;gap:2px;}"
        ".tab{flex:1;padding:8px 0;border:none;background:transparent;font-size:13px;font-weight:600;color:#4e5969;border-radius:7px;cursor:pointer;transition:all .2s;text-align:center;}"
        ".tab.active{background:#ffffff;color:#165dff;box-shadow:0 2px 6px rgba(0,0,0,0.06);}"
        ".panel{display:none;}"
        ".panel.active{display:block;}"
        ".card{background:#ffffff;padding:18px 20px;border-radius:14px;box-shadow:0 2px 10px rgba(0,0,0,0.03);border:1px solid #eef0f3;margin-bottom:14px;}"
        ".card-header{margin-bottom:14px;border-bottom:1px solid #f2f3f5;padding-bottom:10px;}"
        ".card-title{font-size:15px;font-weight:700;color:#1d2129;display:flex;align-items:center;gap:6px;}"
        ".card-desc{font-size:12px;color:#86909c;margin-top:2px;}"
        ".status-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px;}"
        ".status-item{background:#f7f8fa;padding:10px 12px;border-radius:8px;border:1px solid #f2f3f5;}"
        ".status-label{font-size:11px;color:#86909c;margin-bottom:2px;}"
        ".status-value{font-size:14px;font-weight:600;color:#1d2129;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}"
        ".form-grp{margin-bottom:14px;}"
        ".form-row{display:flex;gap:10px;}"
        ".form-row .form-grp{flex:1;}"
        "label{display:block;font-size:12px;font-weight:600;margin-bottom:5px;color:#4e5969;}"
        "input,select{width:100%;padding:10px 12px;border:1px solid #dcdfe6;border-radius:8px;font-size:13px;outline:none;background:#fdfdfd;transition:all .2s;}"
        "input:focus,select:focus{border-color:#165dff;box-shadow:0 0 0 3px rgba(22,93,255,0.12);background:#fff;}"
        ".tip{font-size:12px;color:#86909c;margin-top:5px;line-height:1.4;}"
        ".btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:10px 16px;background:#165dff;color:#fff;border:none;border-radius:8px;font-size:14px;cursor:pointer;font-weight:600;width:100%;transition:all .2s;}"
        ".btn:hover{background:#0e42d2;}"
        ".btn:active{transform:scale(0.99);}"
        ".btn-unlock{background:#00b42a;font-size:16px;padding:14px;margin-bottom:10px;box-shadow:0 4px 12px rgba(0,180,42,0.25);}"
        ".btn-unlock:hover{background:#009a22;}"
        ".btn-outline{background:transparent;border:1px solid #c9cdd4;color:#4e5969;}"
        ".btn-outline:hover{background:#f2f3f5;color:#1d2129;}"
        ".btn-warn{background:#ff7d00;}"
        ".btn-warn:hover{background:#e06c00;}"
        ".btn-danger{background:#f53f3f;}"
        ".btn-danger:hover{background:#d32020;}"
        ".btn-group{display:flex;gap:8px;}"
        ".btn-group .btn{flex:1;font-size:13px;padding:9px;}"
        ".otp-box{text-align:center;padding:16px 0 10px;background:#f7f8fa;border-radius:12px;margin:8px 0 14px;border:1px dashed #c9cdd4;}"
        ".otp-code{font-size:36px;font-weight:800;letter-spacing:8px;color:#165dff;font-family:Consolas,SFMono-Regular,Menlo,monospace;}"
        ".otp-timer{font-size:12px;color:#86909c;margin-top:6px;}"
        "#toast{position:fixed;top:20px;left:50%;transform:translateX(-50%);padding:10px 20px;border-radius:24px;font-size:13px;font-weight:600;color:#fff;box-shadow:0 6px 20px rgba(0,0,0,0.15);z-index:999;display:none;max-width:90%;transition:all .3s;text-align:center;}"
        ".toast-success{background:#00b42a;}"
        ".toast-error{background:#f53f3f;}"
        ".toast-info{background:#165dff;}"
        ".modal-mask{position:fixed;inset:0;background:rgba(0,0,0,0.45);display:none;align-items:center;justify-content:center;z-index:900;padding:20px;}"
        ".modal-box{background:#fff;border-radius:14px;padding:22px;max-width:340px;width:100%;box-shadow:0 12px 36px rgba(0,0,0,0.18);text-align:center;}"
        ".modal-title{font-size:16px;font-weight:700;margin-bottom:8px;color:#1d2129;}"
        ".modal-msg{font-size:13px;color:#4e5969;margin-bottom:20px;line-height:1.5;}"
        ".modal-actions{display:flex;gap:10px;}"
        ".modal-actions .btn{flex:1;}"
        "#progress{width:100%;height:10px;background:#e5e6eb;border-radius:5px;overflow:hidden;margin:12px 0 6px;display:none;}"
        "#bar{width:0%;height:100%;background:#165dff;transition:width .2s;}"
        "</style></head><body>"
        "<div id='toast'></div>"
        "<div id='modal' class='modal-mask'>"
        "<div class='modal-box'>"
        "<div id='modal-title' class='modal-title'></div>"
        "<div id='modal-msg' class='modal-msg'></div>"
        "<div class='modal-actions'>"
        "<button class='btn btn-outline' onclick='closeModal()'>取 消</button>"
        "<button id='modal-confirm' class='btn'>确 定</button>"
        "</div></div></div>"
        "<div class='header'>"
        "<div class='brand'>"
        "<div class='brand-icon'>🛡️</div>"
        "<div>"
        "<div class='brand-title'>鹿客智能门锁网关</div>"
        "<div class='brand-sub'>Loock Gateway Console</div>"
        "</div></div>"
        "<div class='header-actions'>"
        "<span class='badge badge-live'>运行中</span>"
        "<button class='btn-logout' onclick='doLogout()'>退出登录</button>"
        "</div></div>"
        "<div class='tabs'>"
        "<button class='tab active' onclick=\"sw('ctrl')\">门锁控制</button>"
        "<button class='tab' onclick=\"sw('lock')\">通信配置</button>"
        "<button class='tab' onclick=\"sw('mqtt')\">平台集成</button>"
        "<button class='tab' onclick=\"sw('net')\">网络安全</button>"
        "<button class='tab' onclick=\"sw('sys')\">系统维护</button>"
        "</div>";
    httpd_resp_send_chunk(req, part1, strlen(part1));

    /* Panel 1: Dashboard & Control */
    const char *p_ctrl_1 =
        "<div id='p-ctrl' class='panel active'><div class='card'>"
        "<div class='card-header'>"
        "<div class='card-title'>📊 设备实时状态</div>"
        "<div class='card-desc'>门锁硬件状态与本地连接实时信息</div>"
        "</div><div class='status-grid'>";
    httpd_resp_send_chunk(req, p_ctrl_1, strlen(p_ctrl_1));

    char batt_str[32];
    if (g_lock_state.battery <= 100) {
        snprintf(batt_str, sizeof(batt_str), "🔋 %u%%", g_lock_state.battery);
    } else {
        snprintf(batt_str, sizeof(batt_str), "待同步");
    }

    const char *child_str = (g_lock_state.child_lock == 1) ? "<span style='color:#ff7d00;font-weight:700;'>已开启</span>" :
                           ((g_lock_state.child_lock == 0) ? "已关闭" : "待同步");
    const char *anti_str = (g_lock_state.anti_lock == 1) ? "<span style='color:#f53f3f;font-weight:700;'>已开启</span>" :
                          ((g_lock_state.anti_lock == 0) ? "未开启" : "待同步");
    const char *lock_str = (strcmp(g_lock_state.lock_state_str, "UNLOCKED") == 0) ?
                           "<span style='color:#00b42a;font-weight:700;'>已开锁</span>" :
                           "<span style='color:#1d2129;font-weight:700;'>已上锁</span>";

    char c_buf[1536];
    snprintf(c_buf, sizeof(c_buf),
        "<div class='status-item'><div class='status-label'>网关固件</div><div class='status-value'>%s (%s)</div></div>"
        "<div class='status-item'><div class='status-label'>设备 IP</div><div class='status-value'>%s</div></div>"
        "<div class='status-item'><div class='status-label'>门锁状态</div><div class='status-value'>%s</div></div>"
        "<div class='status-item'><div class='status-label'>门体状态</div><div class='status-value'>%s</div></div>"
        "<div class='status-item'><div class='status-label'>剩余电量</div><div class='status-value'>%s</div></div>"
        "<div class='status-item'><div class='status-label'>室内童锁</div><div class='status-value'>%s</div></div>"
        "<div class='status-item'><div class='status-label'>电子反锁</div><div class='status-value'>%s</div></div>"
        "<div class='status-item'><div class='status-label'>物理 MAC</div><div class='status-value' style='font-family:monospace;font-size:12px;'>%s</div></div>"
        "</div>",
        app_desc->version, running ? running->label : "ota",
        ip_str,
        lock_str,
        g_lock_state.door_state_str[0] ? g_lock_state.door_state_str : "待同步",
        batt_str,
        child_str,
        anti_str,
        g_lock_cfg.mac[0] ? g_lock_cfg.mac : "未配置");
    httpd_resp_send_chunk(req, c_buf, strlen(c_buf));

    const char *p_ctrl_2 =
        "<button class='btn btn-unlock' onclick='triggerUnlock()'>🚪 执行一键开锁</button>"
        "<button class='btn btn-outline' style='margin-bottom:14px;' onclick='refreshStatus()'>🔄 同步门锁最新状态</button>"
        "<div style='border-top:1px solid #f2f3f5;padding-top:12px;'>"
        "<div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;'>"
        "<div style='font-size:12px;font-weight:600;color:#4e5969;'>室内童锁保护:</div>"
        "<div style='font-size:11px;color:#86909c;'>开启后门内按键无法开锁</div>"
        "</div>"
        "<div class='btn-group' style='margin-bottom:12px;'>"
        "<button class='btn btn-warn' onclick='setChildLock(1)'>开启童锁</button>"
        "<button class='btn btn-outline' onclick='setChildLock(0)'>关闭童锁</button>"
        "</div>"
        "<div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;'>"
        "<div style='font-size:12px;font-weight:600;color:#4e5969;'>室内电子反锁:</div>"
        "<div style='font-size:11px;color:#86909c;'>开启后阻止普通权限开锁</div>"
        "</div>"
        "<div class='btn-group'>"
        "<button class='btn btn-danger' onclick='setAntiLock(1)'>开启反锁</button>"
        "<button class='btn btn-outline' onclick='setAntiLock(0)'>解除反锁</button>"
        "</div></div></div>"
        "<div class='card'>"
        "<div class='card-header'>"
        "<div class='card-title'>🔑 临时访客口令 (OTP)</div>"
        "<div class='card-desc'>在门锁物理按键直接输入 6 位口令并按「#」键开锁，30 分钟内有效</div>"
        "</div>"
        "<div class='otp-box'>"
        "<div id='otp-val' class='otp-code'>------</div>"
        "<div id='otp-time' class='otp-timer'>正在计算口令...</div>"
        "</div>"
        "<div class='btn-group'>"
        "<button class='btn' onclick='copyOtp()'>📋 复制口令</button>"
        "<button class='btn btn-outline' onclick='fetchOtp()'>🔄 刷新口令</button>"
        "</div>"
        "<div class='tip' style='margin-top:10px;text-align:center;'>门锁离线认证 · 无需连接外部网络</div>"
        "</div></div>";
    httpd_resp_send_chunk(req, p_ctrl_2, strlen(p_ctrl_2));

    /* Panel 2: Lock & BLE SecurityChip */
    const char *p_lock_1 =
        "<div id='p-lock' class='panel'><div class='card'>"
        "<div class='card-header'>"
        "<div class='card-title'>🔒 门锁通信凭证配置</div>"
        "<div class='card-desc'>配置网关与鹿客门锁安全连接所需物理地址与主通信凭证 (LTMK)</div>"
        "</div>"
        "<div class='form-grp'>"
        "<label>门锁物理 MAC 地址 (Peer MAC):</label>"
        "<input id='cfg_mac' placeholder='例: 04:CD:15:AA:BB:CC' value='";
    httpd_resp_send_chunk(req, p_lock_1, strlen(p_lock_1));
    httpd_resp_send_chunk(req, g_lock_cfg.mac, strlen(g_lock_cfg.mac));

    const char *p_lock_2 =
        "'></div>"
        "<div class='form-grp'>"
        "<label>主通信凭证 (LTMK 密钥):</label>"
        "<input id='cfg_ltmk' placeholder='请输入 64 位十六进制主密钥 (32 字节)' value='";
    httpd_resp_send_chunk(req, p_lock_2, strlen(p_lock_2));
    httpd_resp_send_chunk(req, g_lock_cfg.ltmk_hex, strlen(g_lock_cfg.ltmk_hex));

    const char *p_lock_3 =
        "'>"
        "<div class='tip'>安全说明：主密钥由网关硬件安全加密存储，用于与门锁建立双向认证安全通信通道。</div>"
        "</div>"
        "<button class='btn' onclick='saveLockCfg()'>保存通信配置</button>"
        "</div></div>";
    httpd_resp_send_chunk(req, p_lock_3, strlen(p_lock_3));

    /* Panel 3: MQTT Settings */
    const char *p_mqtt_1 =
        "<div id='p-mqtt' class='panel'><div class='card'>"
        "<div class='card-header'>"
        "<div class='card-title'>📡 智能家居平台集成 (Home Assistant / MQTT)</div>"
        "<div class='card-desc'>支持 Home Assistant MQTT 自动发现，实时同步门锁状态与开锁实体</div>"
        "</div>"
        "<div class='form-row'><div class='form-grp' style='flex:2;'>"
        "<label>MQTT 服务端地址 (Broker):</label>";
    httpd_resp_send_chunk(req, p_mqtt_1, strlen(p_mqtt_1));

    char m_buf[1536];
    snprintf(m_buf, sizeof(m_buf),
        "<input id='m_host' value='%s' placeholder='例: 10.0.0.10'></div>"
        "<div class='form-grp' style='flex:1;'><label>服务端口:</label>"
        "<input id='m_port' type='number' value='%d' placeholder='1883'></div></div>"
        "<div class='form-row'><div class='form-grp'><label>认证用户名:</label>"
        "<input id='m_user' value='%s' placeholder='无用户名可留空'></div>"
        "<div class='form-grp'><label>认证密码:</label>"
        "<input id='m_pass' type='password' placeholder='留空保持原密码不变'></div></div>"
        "<div class='form-row'><div class='form-grp'><label>MQTT 基础主题 (Topic):</label>"
        "<input id='m_topic' value='%s' placeholder='lockbridge/loock'></div>"
        "<div class='form-grp'><label>设备实体名称:</label>"
        "<input id='m_name' value='%s' placeholder='鹿客智能门锁'></div></div>"
        "<div class='form-grp'><label>开锁后状态复位延迟 (秒):</label>"
        "<input id='m_autolock' type='number' min='1' max='60' value='%d'></div>",
        g_lock_cfg.mqtt_broker, g_lock_cfg.mqtt_port,
        g_lock_cfg.mqtt_user,
        g_lock_cfg.mqtt_topic,
        g_lock_cfg.lock_name,
        g_lock_cfg.auto_lock_sec);
    httpd_resp_send_chunk(req, m_buf, strlen(m_buf));

    const char *p_mqtt_2 =
        "<div class='tip' style='margin-bottom:12px;'>开锁成功后，网关将于指定秒数后自动向平台同步复位为已上锁 (LOCKED) 状态。保存后热重载生效。</div>"
        "<button class='btn' onclick='saveMqttCfg()'>保存并应用平台设置</button>"
        "</div></div>";
    httpd_resp_send_chunk(req, p_mqtt_2, strlen(p_mqtt_2));

    /* Panel 4: Network & Security */
    const char *p_net_1 =
        "<div id='p-net' class='panel'><div class='card'>"
        "<div class='card-header'>"
        "<div class='card-title'>📶 Wi-Fi 无线网络设置</div>"
        "<div class='card-desc'>配置网关连接的 2.4GHz 局域网 Wi-Fi</div>"
        "</div>"
        "<div class='form-grp'><label>Wi-Fi 网络名称 (SSID):</label>";
    httpd_resp_send_chunk(req, p_net_1, strlen(p_net_1));

    char w_buf[256];
    snprintf(w_buf, sizeof(w_buf),
        "<input id='w_ssid' value='%s' placeholder='请输入 Wi-Fi 名称'></div>",
        g_lock_cfg.wifi_ssid);
    httpd_resp_send_chunk(req, w_buf, strlen(w_buf));

    const char *p_net_2 =
        "<div class='form-grp'><label>Wi-Fi 密码:</label>"
        "<input id='w_pass' type='password' placeholder='留空保持原密码不变'></div>"
        "<div class='tip' style='margin-bottom:12px;'>⚠️ 更新网络配置后，网关将自动重启并尝试连入新 Wi-Fi 网络。请核实网络信息准确无误。</div>"
        "<button class='btn btn-warn' onclick='saveWifiCfg()'>保存网络设置并重启</button>"
        "</div>"
        "<div class='card'>"
        "<div class='card-header'>"
        "<div class='card-title'>🔑 控制台访问密码</div>"
        "<div class='card-desc'>管理网页控制台及空中升级接口的安全鉴权</div>"
        "</div>"
        "<div class='form-grp'><label>新访问密码:</label>"
        "<input id='cfg_web_pass' type='password' placeholder='设置新访问密码 (默认密码: admin)'></div>"
        "<button class='btn' onclick='saveWebPass()'>更新访问密码</button>"
        "</div></div>";
    httpd_resp_send_chunk(req, p_net_2, strlen(p_net_2));

    /* Panel 5: Maintenance & JavaScript */
    const char *part5 =
        "<div id='p-sys' class='panel'>"
        "<div class='card'>"
        "<div class='card-header'>"
        "<div class='card-title'>🚀 固件无线升级 (OTA)</div>"
        "<div class='card-desc'>通过无线网络上传并刷写网关固件镜像 (.bin 文件)</div>"
        "</div>"
        "<div class='form-grp'>"
        "<label>选择固件安装包:</label>"
        "<input type='file' id='firmware' accept='.bin'>"
        "</div>"
        "<button class='btn' onclick='startOta()'>开始升级固件</button>"
        "<div id='progress'><div id='bar'></div></div>"
        "<div id='ota-status' style='font-weight:600;margin-top:8px;font-size:12px;color:#4e5969;'></div>"
        "</div>"
        "<div class='card'>"
        "<div class='card-header'>"
        "<div class='card-title'>🔄 网关设备维护</div>"
        "<div class='card-desc'>若门锁蓝牙通信中断或需重新建立连接，可软重启网关</div>"
        "</div>"
        "<button class='btn btn-outline' onclick='rebootDev()'>重启网关设备</button>"
        "</div></div>"
        "<script>"
        "function sw(name){"
        "  document.querySelectorAll('.tab').forEach(function(t){t.classList.remove('active');});"
        "  document.querySelectorAll('.panel').forEach(function(p){p.classList.remove('active');});"
        "  event.target.classList.add('active');"
        "  document.getElementById('p-'+name).classList.add('active');"
        "}"
        "function showToast(msg,type){"
        "  var t=document.getElementById('toast');"
        "  t.className='toast-'+(type||'info');"
        "  t.innerText=msg;"
        "  t.style.display='block';"
        "  clearTimeout(t._timer);"
        "  t._timer=setTimeout(function(){t.style.display='none';},3200);"
        "}"
        "function showConfirm(title,msg,onOk){"
        "  document.getElementById('modal-title').innerText=title;"
        "  document.getElementById('modal-msg').innerText=msg;"
        "  var b=document.getElementById('modal-confirm');"
        "  b.onclick=function(){closeModal();onOk();};"
        "  document.getElementById('modal').style.display='flex';"
        "}"
        "function closeModal(){"
        "  document.getElementById('modal').style.display='none';"
        "}"
        "function triggerUnlock(){"
        "  showToast('正在向门锁发送开锁指令...','info');"
        "  fetch('/unlock',{method:'POST'}).then(function(r){return r.json();}).then(function(d){"
        "    showToast(d.message||'开锁指令已执行',d.status==='ok'?'success':'error');"
        "  }).catch(function(e){showToast('网络请求失败: '+e,'error');});"
        "}"
        "function refreshStatus(){"
        "  showToast('正在同步门锁最新状态...','info');"
        "  fetch('/refresh',{method:'POST'}).then(function(r){return r.json();}).then(function(d){"
        "    showToast(d.message||'已发送同步请求',d.status==='ok'?'success':'error');"
        "    setTimeout(function(){location.reload();},1800);"
        "  }).catch(function(e){showToast('请求失败: '+e,'error');});"
        "}"
        "function setChildLock(st){"
        "  showToast('正在下发童锁设置...','info');"
        "  fetch('/child_lock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({state:st})})"
        "  .then(function(r){return r.json();}).then(function(d){"
        "    showToast(d.message||'童锁设置已下发',d.status==='ok'?'success':'error');"
        "    setTimeout(function(){location.reload();},1800);"
        "  }).catch(function(e){showToast('请求失败: '+e,'error');});"
        "}"
        "function setAntiLock(st){"
        "  showToast('正在下发反锁设置...','info');"
        "  fetch('/anti_lock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({state:st})})"
        "  .then(function(r){return r.json();}).then(function(d){"
        "    showToast(d.message||'反锁设置已下发',d.status==='ok'?'success':'error');"
        "    setTimeout(function(){location.reload();},1800);"
        "  }).catch(function(e){showToast('请求失败: '+e,'error');});"
        "}"
        "function rebootDev(){"
        "  showConfirm('确认重启设备','网关设备将重新启动，期间网络服务将短暂中断。确定继续吗？',function(){"
        "    fetch('/reboot',{method:'POST'}).then(function(r){return r.json();}).then(function(d){"
        "      showToast(d.message||'设备正在重启...','info');"
        "      setTimeout(function(){location.reload();},4500);"
        "    }).catch(function(e){showToast('请求失败: '+e,'error');});"
        "  });"
        "}"
        "function saveWifiCfg(){"
        "  var ssid=document.getElementById('w_ssid').value.trim();"
        "  var pass=document.getElementById('w_pass').value;"
        "  if(!ssid){showToast('Wi-Fi 名称 (SSID) 不能为空','error');return;}"
        "  showConfirm('确认更新 Wi-Fi','网关将保存配置并自动重启连接至: '+ssid+'。确定继续吗？',function(){"
        "    showToast('正在保存网络配置...','info');"
        "    fetch('/config/wifi',{method:'POST',headers:{'Content-Type':'application/json'},"
        "      body:JSON.stringify({ssid:ssid,pass:pass})})"
        "    .then(function(r){return r.json();}).then(function(d){"
        "      showToast(d.message||'网络配置已保存，正在重启','success');"
        "    }).catch(function(e){showToast('保存失败: '+e,'error');});"
        "  });"
        "}"
        "function saveMqttCfg(){"
        "  var host=document.getElementById('m_host').value.trim();"
        "  var port=parseInt(document.getElementById('m_port').value);"
        "  var user=document.getElementById('m_user').value.trim();"
        "  var pass=document.getElementById('m_pass').value;"
        "  var topic=document.getElementById('m_topic').value.trim();"
        "  var name=document.getElementById('m_name').value.trim();"
        "  var autolock=parseInt(document.getElementById('m_autolock').value);"
        "  showToast('正在更新平台设置...','info');"
        "  fetch('/config/mqtt',{method:'POST',headers:{'Content-Type':'application/json'},"
        "    body:JSON.stringify({broker:host,port:port,user:user,pass:pass,topic:topic,name:name,auto_lock_sec:autolock})})"
        "  .then(function(r){return r.json();}).then(function(d){"
        "    showToast(d.message||'平台配置已更新',d.status==='ok'?'success':'error');"
        "  }).catch(function(e){showToast('保存失败: '+e,'error');});"
        "}"
        "function saveLockCfg(){"
        "  var mac=document.getElementById('cfg_mac').value.trim();"
        "  var ltmk=document.getElementById('cfg_ltmk').value.trim();"
        "  if(!mac||mac.length!==17){showToast('请输入正确的 MAC 地址 (例: 04:CD:15:AA:BB:CC)','error');return;}"
        "  if(!ltmk||ltmk.length!==64){showToast('请输入 64 位十六进制主密钥 (32 字节)','error');return;}"
        "  showToast('正在保存门锁配置...','info');"
        "  fetch('/config/lock',{method:'POST',headers:{'Content-Type':'application/json'},"
        "    body:JSON.stringify({mac:mac,encrypt_type:0,raw_ltmk:ltmk})})"
        "  .then(function(r){return r.json();}).then(function(d){"
        "    showToast(d.message||'配置已保存',d.status==='ok'?'success':'error');"
        "    if(d.status==='ok') setTimeout(function(){location.reload();},1500);"
        "  }).catch(function(e){showToast('保存失败: '+e,'error');});"
        "}"
        "function saveWebPass(){"
        "  var p=document.getElementById('cfg_web_pass').value;"
        "  if(!p){showToast('新访问密码不能为空','error');return;}"
        "  showToast('正在更新访问密码...','info');"
        "  fetch('/config/password',{"
        "    method:'POST',"
        "    headers:{'Content-Type':'application/json'},"
        "    body:JSON.stringify({password:p})"
        "  }).then(function(r){return r.json();}).then(function(d){"
        "    showToast(d.message||'访问密码更新成功',d.status==='ok'?'success':'error');"
        "    if(d.status==='ok')document.getElementById('cfg_web_pass').value='';"
        "  }).catch(function(e){showToast('更新失败: '+e,'error');});"
        "}"
        "function startOta(){"
        "  var f=document.getElementById('firmware').files[0];"
        "  if(!f){showToast('请先选择固件镜像 (.bin) 文件','error');return;}"
        "  var bar=document.getElementById('bar');"
        "  var p=document.getElementById('progress');"
        "  var st=document.getElementById('ota-status');"
        "  p.style.display='block';st.innerText='正在上传固件 ('+Math.round(f.size/1024)+' KB)...';"
        "  var xhr=new XMLHttpRequest();"
        "  xhr.open('POST','/update',true);"
        "  xhr.upload.onprogress=function(e){if(e.lengthComputable){var pct=Math.round((e.loaded/e.total)*100);bar.style.width=pct+'%';st.innerText='固件刷写中: '+pct+'%';}};"
        "  xhr.onload=function(){"
        "    if(xhr.status==200){"
        "      st.innerText='固件升级成功！网关正在重启，即将刷新页面...';"
        "      showToast('固件升级成功，正在重启','success');"
        "      setTimeout(function(){location.reload();},5000);"
        "    }else{"
        "      st.innerText='升级失败: '+xhr.responseText;"
        "      showToast('升级失败','error');"
        "    }"
        "  };"
        "  xhr.onerror=function(){"
        "    st.innerText='网络通信中断，升级失败';"
        "    showToast('上传失败','error');"
        "  };"
        "  xhr.send(f);"
        "}"
        "function fetchOtp(){"
        "  var ts=Math.floor(Date.now()/1000);"
        "  fetch('/otp?ts='+ts).then(function(r){return r.json();}).then(function(d){"
        "    if(d.status==='ok'){"
        "      document.getElementById('otp-val').innerText=d.otp;"
        "      var m=Math.floor(d.remaining/60);"
        "      var s=d.remaining%60;"
        "      document.getElementById('otp-time').innerText='⏱ 剩余有效时间: '+m+'分'+(s<10?'0':'')+s+'秒';"
        "    }else{"
        "      document.getElementById('otp-val').innerText='------';"
        "      document.getElementById('otp-time').innerText=d.message||'计算口令失败';"
        "    }"
        "  }).catch(function(e){"
        "    document.getElementById('otp-time').innerText='获取口令失败';"
        "  });"
        "}"
        "function copyOtp(){"
        "  var t=document.getElementById('otp-val').innerText;"
        "  if(!t||t==='------')return;"
        "  navigator.clipboard.writeText(t).then(function(){"
        "    showToast('口令 '+t+' 已复制到剪贴板','success');"
        "  }).catch(function(){"
        "    showToast('复制失败，请手动记录','error');"
        "  });"
        "}"
        "function doLogout(){"
        "  fetch('/logout',{method:'POST'}).then(function(){location.reload();});"
        "}"
        "setTimeout(fetchOtp,300);"
        "setInterval(fetchOtp,30000);"
        "</script></body></html>";
    httpd_resp_send_chunk(req, part5, strlen(part5));

    /* End chunked response */
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

/* POST /unlock - Trigger unlock */
static esp_err_t unlock_post_handler(httpd_req_t *req)
{
    if (!is_authenticated(req)) {
        return send_unauthorized(req);
    }
    ESP_LOGI(TAG, "HTTP /unlock called, initiating unlock sequence...");
    miot_ble_trigger_action(BLE_ACTION_UNLOCK, 0);
    const char *resp = "{\"status\":\"ok\",\"message\":\"开锁指令已下发，正在建立安全蓝牙连接...\"}";
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
}

/* POST /child_lock - Toggle Child Lock */
static esp_err_t child_lock_post_handler(httpd_req_t *req)
{
    if (!is_authenticated(req)) {
        return send_unauthorized(req);
    }
    char buf[128] = {0};
    int ret = httpd_req_recv(req, buf, MIN(req->content_len, sizeof(buf) - 1));
    int state = 1;
    if (ret > 0) {
        json_get_int(buf, "state", &state);
    }
    ESP_LOGI(TAG, "HTTP /child_lock called, state=%d", state);
    miot_ble_trigger_action(BLE_ACTION_CHILD_LOCK, state ? 1 : 0);
    const char *resp = "{\"status\":\"ok\",\"message\":\"室内童锁设置指令已下发\"}";
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
}

/* POST /anti_lock - Toggle Anti Lock */
static esp_err_t anti_lock_post_handler(httpd_req_t *req)
{
    if (!is_authenticated(req)) {
        return send_unauthorized(req);
    }
    char buf[128] = {0};
    int ret = httpd_req_recv(req, buf, MIN(req->content_len, sizeof(buf) - 1));
    int state = 1;
    if (ret > 0) {
        json_get_int(buf, "state", &state);
    }
    ESP_LOGI(TAG, "HTTP /anti_lock called, state=%d", state);
    miot_ble_trigger_action(BLE_ACTION_ANTI_LOCK, state ? 1 : 0);
    const char *resp = "{\"status\":\"ok\",\"message\":\"室内电子反锁指令已下发\"}";
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
}

/* POST /refresh - Refresh Lock Status */
static esp_err_t refresh_post_handler(httpd_req_t *req)
{
    if (!is_authenticated(req)) {
        return send_unauthorized(req);
    }
    ESP_LOGI(TAG, "HTTP /refresh called, reading lock status...");
    miot_ble_trigger_action(BLE_ACTION_REFRESH_STATUS, 0);
    const char *resp = "{\"status\":\"ok\",\"message\":\"正在同步门锁最新状态与电量...\"}";
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
}

/* GET /otp - Generate Offline Visitor OTP */
static esp_err_t otp_get_handler(httpd_req_t *req)
{
    if (!is_authenticated(req)) {
        return send_unauthorized(req);
    }
    uint32_t ts = 0;
    char query[64] = {0};
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        char ts_str[32] = {0};
        if (httpd_query_key_value(query, "ts", ts_str, sizeof(ts_str)) == ESP_OK) {
            ts = (uint32_t)strtoul(ts_str, NULL, 10);
        }
    }
    if (ts == 0) {
        time_t now = time(NULL);
        if (now > 1600000000) {
            ts = (uint32_t)now;
        }
    }

    if (ts == 0) {
        httpd_resp_set_type(req, "application/json");
        const char *resp = "{\"status\":\"error\",\"message\":\"网关时钟尚未同步，请在控制台页面刷新\"}";
        return httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
    }

    uint32_t otp = 0;
    uint32_t rem = 0;
    int rc = sc_generate_otp(g_lock_cfg.ltmk, ts, &otp, &rem);
    if (rc != 0) {
        httpd_resp_set_type(req, "application/json");
        const char *resp = "{\"status\":\"error\",\"message\":\"计算临时访客口令失败\"}";
        return httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
    }

    char resp[128];
    snprintf(resp, sizeof(resp),
             "{\"status\":\"ok\",\"otp\":\"%06" PRIu32 "\",\"remaining\":%" PRIu32 "}",
             otp, rem);
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
}

/* POST /config/wifi - Save Wi-Fi settings & reboot */
static esp_err_t config_wifi_handler(httpd_req_t *req)
{
    if (!is_authenticated(req)) {
        return send_unauthorized(req);
    }
    char buf[512] = {0};
    int ret = httpd_req_recv(req, buf, MIN(req->content_len, sizeof(buf) - 1));
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Empty request body");
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    char ssid[64] = {0};
    char pass[64] = {0};

    json_get_string(buf, "ssid", ssid, sizeof(ssid));
    json_get_string(buf, "pass", pass, sizeof(pass));

    memset(buf, 0, sizeof(buf));

    if (strlen(ssid) == 0) {
        httpd_resp_set_type(req, "application/json");
        const char *resp = "{\"status\":\"error\",\"message\":\"Wi-Fi 名称 (SSID) 不能为空！\"}";
        return httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
    }

    esp_err_t err = lock_config_save_wifi(ssid, pass[0] ? pass : NULL);
    memset(pass, 0, sizeof(pass));

    httpd_resp_set_type(req, "application/json");
    if (err == ESP_OK) {
        const char *resp = "{\"status\":\"ok\",\"message\":\"网络设置已保存！网关将在 2 秒后重启连接新网络...\"}";
        httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
        xTaskCreate(restart_task, "restart_task", 2048, NULL, 5, NULL);
        return ESP_OK;
    } else {
        const char *resp = "{\"status\":\"error\",\"message\":\"网络配置保存失败\"}";
        return httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
    }
}

/* POST /reboot - Reboot device */
static esp_err_t reboot_post_handler(httpd_req_t *req)
{
    if (!is_authenticated(req)) {
        return send_unauthorized(req);
    }
    ESP_LOGI(TAG, "HTTP /reboot called, device restarting...");
    const char *resp = "{\"status\":\"ok\",\"message\":\"网关设备正在重启...\"}";
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
    xTaskCreate(restart_task, "restart_task", 2048, NULL, 5, NULL);
    return ESP_OK;
}

/* POST /config/lock - Save lock parameters (Direct LTMK) */
static esp_err_t config_lock_handler(httpd_req_t *req)
{
    if (!is_authenticated(req)) {
        return send_unauthorized(req);
    }
    char buf[512] = {0};
    int ret = httpd_req_recv(req, buf, MIN(req->content_len, sizeof(buf) - 1));
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Empty request body");
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    char mac[32] = {0};
    char pin[32] = {0};
    char raw_ltmk[80] = {0};
    char iv[64] = {0};
    int encrypt_type = 0;

    json_get_string(buf, "mac", mac, sizeof(mac));
    json_get_int(buf, "encrypt_type", &encrypt_type);
    json_get_string(buf, "pin", pin, sizeof(pin));
    if (!json_get_string(buf, "raw_ltmk", raw_ltmk, sizeof(raw_ltmk))) {
        json_get_string(buf, "ltmk", raw_ltmk, sizeof(raw_ltmk));
    }
    json_get_string(buf, "iv", iv, sizeof(iv));

    /* Wipe request buffer now that fields are extracted */
    memset(buf, 0, sizeof(buf));

    esp_err_t err = lock_config_derive_and_save(mac, raw_ltmk, encrypt_type, pin[0] ? pin : NULL, iv[0] ? iv : NULL);

    /* Immediately wipe PIN, raw_ltmk and IV from RAM */
    memset(pin, 0, sizeof(pin));
    memset(raw_ltmk, 0, sizeof(raw_ltmk));
    memset(iv, 0, sizeof(iv));

    httpd_resp_set_type(req, "application/json");
    if (err == ESP_OK) {
        const char *resp = "{\"status\":\"ok\",\"message\":\"门锁通信凭证已成功保存并生效！\"}";
        return httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
    } else {
        const char *resp = "{\"status\":\"error\",\"message\":\"配置保存失败，请检查 MAC 地址或 64 位密钥格式！\"}";
        return httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
    }
}

/* POST /config/mqtt - Save MQTT broker settings (hot-reload) */
static esp_err_t config_mqtt_handler(httpd_req_t *req)
{
    if (!is_authenticated(req)) {
        return send_unauthorized(req);
    }
    char buf[512] = {0};
    int ret = httpd_req_recv(req, buf, MIN(req->content_len, sizeof(buf) - 1));
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Empty request body");
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    char broker[64] = {0};
    char user[32] = {0};
    char pass[32] = {0};
    char topic[48] = {0};
    char name[32] = {0};
    int port = 1883;
    int auto_lock_sec = 4;

    json_get_string(buf, "broker", broker, sizeof(broker));
    json_get_int(buf, "port", &port);
    json_get_string(buf, "user", user, sizeof(user));
    json_get_string(buf, "pass", pass, sizeof(pass));
    json_get_string(buf, "topic", topic, sizeof(topic));
    json_get_string(buf, "name", name, sizeof(name));
    json_get_int(buf, "auto_lock_sec", &auto_lock_sec);

    esp_err_t err = lock_config_save_mqtt(broker, port > 0 ? (uint16_t)port : 1883,
                                         user[0] ? user : NULL,
                                         pass[0] ? pass : NULL,
                                         topic[0] ? topic : NULL,
                                         name[0] ? name : NULL,
                                         auto_lock_sec > 0 ? (uint16_t)auto_lock_sec : 4);

    /* Restart MQTT client with new settings */
    mqtt_handler_stop();
    mqtt_handler_start();

    memset(buf, 0, sizeof(buf));
    memset(pass, 0, sizeof(pass));

    httpd_resp_set_type(req, "application/json");
    if (err == ESP_OK) {
        const char *resp = "{\"status\":\"ok\",\"message\":\"平台配置已更新并成功重新连接！\"}";
        return httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
    } else {
        const char *resp = "{\"status\":\"error\",\"message\":\"平台配置保存失败\"}";
        return httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
    }
}

/* GET /status - Device status */
static esp_err_t status_get_handler(httpd_req_t *req)
{
    if (!is_authenticated(req)) {
        return send_unauthorized(req);
    }
    const esp_app_desc_t *app_desc = esp_app_get_description();
    const esp_partition_t *running = esp_ota_get_running_partition();

    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_ip_info_t ip_info;
    char ip_str[32] = "0.0.0.0";
    if (netif && esp_netif_get_ip_info(netif, &ip_info) == ESP_OK) {
        esp_ip4addr_ntoa(&ip_info.ip, ip_str, sizeof(ip_str));
    }

    char resp[1024];
    snprintf(resp, sizeof(resp),
        "{\"app\":\"%s\",\"version\":\"%s\",\"date\":\"%s %s\",\"partition\":\"%s\",\"wifi_ssid\":\"%s\",\"ip\":\"%s\",\"mac\":\"%s\",\"configured\":%s,\"mqtt_broker\":\"%s\",\"mqtt_topic\":\"%s\",\"lock_name\":\"%s\",\"auto_lock_sec\":%d,\"battery\":%d,\"child_lock\":%d,\"anti_lock\":%d,\"door_state\":%d,\"door_desc\":\"%s\",\"lock_state\":\"%s\",\"free_heap\":%lu}",
        app_desc->project_name, app_desc->version, app_desc->date, app_desc->time,
        running ? running->label : "unknown",
        g_lock_cfg.wifi_ssid, ip_str,
        g_lock_cfg.mac,
        g_lock_cfg.is_configured ? "true" : "false",
        g_lock_cfg.mqtt_broker,
        g_lock_cfg.mqtt_topic,
        g_lock_cfg.lock_name,
        g_lock_cfg.auto_lock_sec,
        (int)g_lock_state.battery,
        g_lock_state.child_lock,
        g_lock_state.anti_lock,
        g_lock_state.door_state,
        g_lock_state.door_state_str[0] ? g_lock_state.door_state_str : "未知",
        g_lock_state.lock_state_str,
        (unsigned long)esp_get_free_heap_size());
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
}

/* POST /update - Stream OTA binary to next partition */
static esp_err_t update_post_handler(httpd_req_t *req)
{
    if (!is_authenticated(req)) {
        httpd_resp_set_status(req, "401 Unauthorized");
        httpd_resp_sendstr(req, "未授权，请先登录控制台或携带 X-Auth-Password 请求头\n");
        return ESP_FAIL;
    }
    esp_ota_handle_t update_handle = 0;
    const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);

    if (update_partition == NULL) {
        ESP_LOGE(TAG, "Cannot find next OTA update partition");
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "No OTA partition available");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Writing OTA to partition '%s' at offset 0x%08lx (size 0x%08lx)",
             update_partition->label,
             (unsigned long)update_partition->address,
             (unsigned long)update_partition->size);

    int total_len = req->content_len;
    int remaining = total_len;
    char ota_buf[1024];
    bool is_first_block = true;
    esp_err_t err = ESP_OK;

    while (remaining > 0) {
        int to_read = MIN(remaining, sizeof(ota_buf));
        int recv_len = httpd_req_recv(req, ota_buf, to_read);
        if (recv_len <= 0) {
            if (recv_len == HTTPD_SOCK_ERR_TIMEOUT) {
                continue;
            }
            ESP_LOGE(TAG, "HTTP receive timeout or connection closed");
            if (update_handle) esp_ota_abort(update_handle);
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Connection error during upload");
            return ESP_FAIL;
        }

        if (is_first_block) {
            is_first_block = false;
            if (recv_len > sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t) + sizeof(esp_app_desc_t)) {
                esp_app_desc_t new_app_info;
                memcpy(&new_app_info,
                       ota_buf + sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t),
                       sizeof(esp_app_desc_t));
                ESP_LOGI(TAG, "New firmware details: Project: %s, Version: %s",
                         new_app_info.project_name, new_app_info.version);
            }

            err = esp_ota_begin(update_partition, OTA_WITH_SEQUENTIAL_WRITES, &update_handle);
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "esp_ota_begin failed (%s)", esp_err_to_name(err));
                httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "esp_ota_begin failed");
                return ESP_FAIL;
            }
        }

        err = esp_ota_write(update_handle, (const void *)ota_buf, recv_len);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "esp_ota_write failed (%s)", esp_err_to_name(err));
            esp_ota_abort(update_handle);
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "esp_ota_write failed");
            return ESP_FAIL;
        }

        remaining -= recv_len;
    }

    err = esp_ota_end(update_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_end failed (%s)", esp_err_to_name(err));
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OTA validation failed");
        return ESP_FAIL;
    }

    err = esp_ota_set_boot_partition(update_partition);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition failed (%s)", esp_err_to_name(err));
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Setting boot partition failed");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "OTA upgrade successful! Boot partition set to '%s'", update_partition->label);
    const char *resp = "固件升级成功！设备正在重启...";
    httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);

    /* Launch async reboot task */
    xTaskCreate(restart_task, "restart_task", 2048, NULL, 5, NULL);
    return ESP_OK;
}

esp_err_t ota_server_start(void)
{
    if (s_server != NULL) {
        return ESP_OK;
    }

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = 80;
    config.max_uri_handlers = 24;
    config.stack_size = 8192;

    ESP_LOGI(TAG, "Starting HTTP OTA server on port %d...", config.server_port);
    esp_err_t ret = httpd_start(&s_server, &config);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start HTTP server (%s)", esp_err_to_name(ret));
        return ret;
    }

    httpd_uri_t login_uri = {
        .uri = "/login",
        .method = HTTP_POST,
        .handler = login_post_handler,
    };
    httpd_register_uri_handler(s_server, &login_uri);

    httpd_uri_t logout_uri = {
        .uri = "/logout",
        .method = HTTP_POST,
        .handler = logout_post_handler,
    };
    httpd_register_uri_handler(s_server, &logout_uri);

    httpd_uri_t cfg_pass_uri = {
        .uri = "/config/password",
        .method = HTTP_POST,
        .handler = config_password_handler,
    };
    httpd_register_uri_handler(s_server, &cfg_pass_uri);

    httpd_uri_t index_uri = {
        .uri = "/",
        .method = HTTP_GET,
        .handler = index_get_handler,
    };
    httpd_register_uri_handler(s_server, &index_uri);

    httpd_uri_t status_uri = {
        .uri = "/status",
        .method = HTTP_GET,
        .handler = status_get_handler,
    };
    httpd_register_uri_handler(s_server, &status_uri);

    httpd_uri_t unlock_post_uri = {
        .uri = "/unlock",
        .method = HTTP_POST,
        .handler = unlock_post_handler,
    };
    httpd_register_uri_handler(s_server, &unlock_post_uri);

    httpd_uri_t unlock_get_uri = {
        .uri = "/unlock",
        .method = HTTP_GET,
        .handler = unlock_post_handler,
    };
    httpd_register_uri_handler(s_server, &unlock_get_uri);

    httpd_uri_t child_lock_uri = {
        .uri = "/child_lock",
        .method = HTTP_POST,
        .handler = child_lock_post_handler,
    };
    httpd_register_uri_handler(s_server, &child_lock_uri);

    httpd_uri_t anti_lock_uri = {
        .uri = "/anti_lock",
        .method = HTTP_POST,
        .handler = anti_lock_post_handler,
    };
    httpd_register_uri_handler(s_server, &anti_lock_uri);

    httpd_uri_t refresh_uri = {
        .uri = "/refresh",
        .method = HTTP_POST,
        .handler = refresh_post_handler,
    };
    httpd_register_uri_handler(s_server, &refresh_uri);

    httpd_uri_t otp_uri = {
        .uri = "/otp",
        .method = HTTP_GET,
        .handler = otp_get_handler,
    };
    httpd_register_uri_handler(s_server, &otp_uri);

    httpd_uri_t reboot_post_uri = {
        .uri = "/reboot",
        .method = HTTP_POST,
        .handler = reboot_post_handler,
    };
    httpd_register_uri_handler(s_server, &reboot_post_uri);

    httpd_uri_t cfg_wifi_uri = {
        .uri = "/config/wifi",
        .method = HTTP_POST,
        .handler = config_wifi_handler,
    };
    httpd_register_uri_handler(s_server, &cfg_wifi_uri);

    httpd_uri_t cfg_lock_uri = {
        .uri = "/config/lock",
        .method = HTTP_POST,
        .handler = config_lock_handler,
    };
    httpd_register_uri_handler(s_server, &cfg_lock_uri);

    httpd_uri_t cfg_mqtt_uri = {
        .uri = "/config/mqtt",
        .method = HTTP_POST,
        .handler = config_mqtt_handler,
    };
    httpd_register_uri_handler(s_server, &cfg_mqtt_uri);

    httpd_uri_t update_uri = {
        .uri = "/update",
        .method = HTTP_POST,
        .handler = update_post_handler,
    };
    httpd_register_uri_handler(s_server, &update_uri);

    ESP_LOGI(TAG, "HTTP OTA server started successfully! Web UI at http://<ip>/");
    return ESP_OK;
}

void ota_server_stop(void)
{
    if (s_server) {
        httpd_stop(s_server);
        s_server = NULL;
    }
}
