# ESP32-S3 Xiaomi / Loock BLE SecurityChip 独立开锁与 OTA 网关

本项目实现了在 ESP32-S3 上独立与米家/鹿客智能门锁（`loock.lock.v16` 等 Miot BLE 安全芯片门锁）完成全套 SecurityChip BLE 双向非对称认证握手并安全执行近场开锁，完全脱离手机米家 App 与云端依赖，支持 Home Assistant MQTT 自动发现接入、Web 紧凑选项卡管理与无线双分区 OTA 升级。

---

## 核心特性

1. **完整 SecurityChip 加密栈 (纯 C / PSA Crypto / NimBLE)**：
   - **ECDH P-256**：动态生成密钥对，并完成通道 64 字节公钥帧分片传输。
   - **HKDF-SHA256**：结合 ECDH 协商秘钥与明文 LTMK 派生 64 字节 Session Key。
   - **CRC32 (Little-Endian)**：计算对端公钥校验和。
   - **AES-128-CCM**：构建 8 字节 Login Token 并通过 Channel 流式上报。
   - **DEV_OK 认证**：门锁返回 `21 00 00 00` 即认证成功。
   - **Operate 解锁**：组装 AES-CCM 加密帧写至 Characteristic `49`，门锁电机物理开锁。

2. **多参数动态可配置 (零硬编码，NVS 持久化)**：
   - **门锁配置**：MAC 地址、加密类型（0明文/1云端密文派生）、临时 PIN 码、LTMK、AES IV。
   - **MQTT / HA 配置**：Broker IP、端口、用户、密码、Topic 前缀、HA 锁实体名称、自动回锁延时（秒），支持热重载。
   - **网络配置**：Wi-Fi SSID 与密码（保存后自动安全重启连接）。

3. **单屏紧凑 Web 管理后台**：
   - 顶部导航栏划分为 5 大选项卡：`🚪 控制` / `🔒 门锁` / `📡 MQTT` / `📶 网络` / `🚀 升级`。
   - 界面高度保持在单屏内（约 400px），无需冗长滚动。
   - 提供状态卡片、一键开锁测试与设备软重启按钮。

4. **Home Assistant MQTT 自动发现 (MQTT Discovery)**：
   - 启动时自动向 `homeassistant/lock/<dev_id>/config` 发布 Discovery 载荷。
   - HA 自动生成 Lock 实体，支持开锁操作与自动恢复锁定状态展示。

5. **无线双分区 OTA 固件升级**：
   - 16MB Flash 定制分区表：`ota_0` (3MB) 与 `ota_1` (3MB)。
   - 内置 HTTP 服务器（端口 80），支持流式写入、自动校验与无缝热重启。
   - 包含一键刷机脚本 `ota.py`，无需连接 USB 即可通过 Wi-Fi 升级固件。

6. **实时 UDP 远程调试日志**：
   - ESP32 通过 UDP（端口 8888）向局域网广播日志，并动态学习监听客户端 IP，便于脱机调试。

---

## 🔑 门锁 LTMK 密钥获取指南

### 1. 什么是 LTMK？有有效期吗？
- **LTMK (Long Term Master Key，长期主密钥)**：门锁在绑定到米家时与云端协商生成的 32 字节（64 位十六进制）核心硬件绑定密钥。
- **有效期**：**永久有效，没有时间过期概念**。门锁属于纯离线蓝牙设备，只要你不在米家 App 中“解绑/删除门锁”或长按门锁物理 Reset 键恢复出厂设置，该密钥将永久生效。日常断电、更换电池、修改米家密码、Wi-Fi 变更均不会导致其失效。

### 2. 获取 LTMK 的三种途径

#### 方式一：从 Android 手机米家 App 本地数据提取（最精准）
在已 Root 的安卓手机或电脑安卓模拟器中，打开米家 App 并进入门锁插件开过一次锁后，密钥已缓存在本地：
- **查看 MMKV 缓存**：
  文件路径：`/data/data/com.xiaomi.smarthome/files/mmkv/bluetooth_token_sync`
  在文件中搜索你的门锁 MAC（如 `04:CD:15:AA:BB:CC`），紧随其后的 64 位 Hex 字符串即为该锁的 Key。
- **查看 SharedPreferences 缓存**：
  文件路径：`/data/data/com.xiaomi.smarthome/shared_prefs/ble_device_prop_cache.*.xml`
  搜索门锁 MAC，在对应的 JSON 节点中即可看到 `key` 或 `encryptedLtmk` 字段。

#### 方式二：使用云端工具提取（开源工具）
使用开源 Python 工具 [Xiaomi Cloud Tokens Extractor](https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor)：
```bash
python3 token_extractor.py
```
- 输入小米账号和密码登录后，找到门锁条目。
- 注意：门锁在基础设备列表中通常显示 12 字节的通用 `TOKEN`；若工具支持拉取 BLE BeaconKey/SecureKey 接口（`https://api.io.mi.com/app/v2/device/blt_get_beaconkey`，入参为门锁的 `did`），则返回的 `key` 字段即为 64 位 Hex。

#### 方式三：米家 App 下拉刷新抓包
使用 Charles / Fiddler / Mitmproxy 对手机米家 App 抓包：
- 下拉刷新设备列表，拦截 `POST https://api.io.mi.com/app/v2/home/device_list` 或 `POST https://api.io.mi.com/app/v2/device/blt_get_beaconkey`。
- 响应 JSON 的门锁对象 `extra` 中即包含 64 位 `key`。

### 3. 云端密文与明文派生关系
从云端或本地抓取到的 64 位 Hex 通常根据 `encrypt_type` 分为两种形态：
- **加密类型 0（明文 LTMK）**：直接为真实 32 字节通信密钥。
- **加密类型 1（云端加密 LTMK）**：由你的开门数字 PIN 码加密：
  - 算法：`AES-128-CBC`（无填充，NoPadding）
  - 密钥：`MD5(开门PIN码)`（例如 `MD5("123456")` -> 16 字节）
  - 固定 IV：`7aa4c68c590d4031b980d98b41023800`

> 🛡️ **安全保证**：在 ESP32 Web 后台（`http://<ESP32_IP>/`）的“门锁”选项卡中，选择类型 1 并输入 PIN 码与云端密文后，ESP32 仅在内存中临时计算出明文 LTMK 保存至 Flash，**PIN 码会被立即擦除清零，绝不存入 Flash**。

---

## 局域网 HTTP 接口

| 路径 | 方法 | 功能描述 | 示例 / 说明 |
|---|---|---|---|
| `/` | `GET` | 选项卡式 Web 管理与 OTA 上传界面 | 浏览器直接打开 `http://<ESP32_IP>/` |
| `/unlock` | `POST` / `GET` | 触发门锁蓝牙连接并开锁 | `curl -X POST http://<ESP32_IP>/unlock` |
| `/reboot` | `POST` | 重启 ESP32 设备 | `curl -X POST http://<ESP32_IP>/reboot` |
| `/config/lock` | `POST` | 配置门锁 MAC、加密类型、PIN 与 LTMK | JSON 提交，PIN 仅在内存派生后销毁 |
| `/config/mqtt` | `POST` | 配置 MQTT Broker、端口、主题、名称等 | 热重载，即时重新连接 Broker |
| `/config/wifi` | `POST` | 配置 Wi-Fi SSID 与密码 | 保存后设备自动重启连接新网络 |
| `/status` | `GET` | 获取当前设备系统与运行状态 JSON | `curl http://<ESP32_IP>/status` |
| `/update` | `POST` | 无线 OTA 刷入固件二进制流 | `python3 ota.py <ESP32_IP>` |

---

## 命令行 OTA 升级使用方式

代码编译与升级完全支持无线操作：
```bash
# 1. 编译生成二进制固件
cd esp32_securitychip
idf.py build

# 2. 通过 Wi-Fi 推送升级到 ESP32
python3 ota.py [ESP32_IP]
```
ESP32 将在约 15 秒内流式写入备用分区、校验并自动重启生效。

