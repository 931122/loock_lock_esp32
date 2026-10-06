#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "psa/crypto.h"

/* Target Lock MAC and Keys (Default placeholders; configure real values via Web UI) */
#define LOCK_MAC_STR           "04:CD:15:AA:BB:CC"
#define LOCK_LTMK_HEX          "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
#define LOCK_TOKEN_HEX         "00112233445566778899aabb"

/* Auth Service & Characteristic (FE95) */
#define UUID_SVC_FE95          "0000fe95-0000-1000-8000-00805f9b34fb"
#define UUID_CHR_AUTH          "00000010-0000-1000-8000-00805f9b34fb"
#define UUID_CHR_CHANNEL       "00000016-0000-1000-8000-00805f9b34fb"

/* Lock Service & Characteristics (miot.ble) */
#define UUID_SVC_LOCK          "00001000-0065-6c62-2e74-6f696d2e696d"
#define UUID_CHR_LOCK_STATE    "00001001-0065-6c62-2e74-6f696d2e696d"
#define UUID_CHR_LOCK_OP       "00001002-0065-6c62-2e74-6f696d2e696d"
#define UUID_CHR_LOCK_LOG      "00001003-0065-6c62-2e74-6f696d2e696d"

/* Login opcodes */
static const uint8_t SC_CMD_LOGIN_START[4] = {32, 0, 0, 0};
static const uint8_t SC_CMD_DEV_OK[4]      = {33, 0, 0, 0};
static const uint8_t SC_CMD_DEV_FAIL[4]    = {34, 0, 0, 0};

typedef struct {
    uint8_t session[64];
    bool    ready;
    uint16_t tx_counter;
    uint16_t tx_epoch;
} sc_session_t;

int sc_crypto_init(void);
int sc_hex_to_bytes(const char *hex, uint8_t *out, size_t out_len);
int sc_ecdh_generate(psa_key_id_t *key_id, uint8_t pub65[65]);
int sc_ecdh_shared(psa_key_id_t key_id, const uint8_t peer_pub64[64], uint8_t shared32[32]);
int sc_hkdf_login(const uint8_t shared32[32], const uint8_t ltmk32[32], uint8_t out64[64]);
uint32_t sc_crc32(const uint8_t *data, size_t len);
int sc_aes_ccm_encrypt(const uint8_t key16[16], const uint8_t iv12[12],
                       const uint8_t *plain, size_t plain_len,
                       uint8_t *out, size_t *out_len);
int sc_build_login_token(const uint8_t session64[64], const uint8_t peer_pub64[64], uint8_t enc8[8]);
int sc_build_operate(sc_session_t *s, const uint8_t *plain, size_t plain_len,
                     uint8_t *out, size_t *out_len);
uint16_t sc_crc16(const uint8_t *data, size_t len);
int sc_build_loock_cmd(uint16_t cmd_id, uint8_t key, const uint8_t *val, size_t val_len,
                       uint16_t seq_id, uint8_t *out, size_t *out_len);
int sc_generate_otp(const uint8_t ltmk32[32], uint32_t epoch_sec, uint32_t *otp_out, uint32_t *remaining_sec);
