#include "security_chip.h"
#include <string.h>
#include <stdio.h>
#include "esp_log.h"
#include "psa/crypto.h"

static const char *TAG = "SC";

int sc_crypto_init(void)
{
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "psa_crypto_init failed: %d", (int)status);
        return -1;
    }
    return 0;
}

int sc_hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
    size_t n = strlen(hex);
    if (n != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        unsigned v;
        if (sscanf(hex + i * 2, "%02x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

int sc_ecdh_generate(psa_key_id_t *key_id, uint8_t pub65[65])
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);

    psa_status_t status = psa_generate_key(&attr, key_id);
    psa_reset_key_attributes(&attr);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "psa_generate_key failed: %d", (int)status);
        return -1;
    }

    size_t pub_len = 0;
    status = psa_export_public_key(*key_id, pub65, 65, &pub_len);
    if (status != PSA_SUCCESS || pub_len != 65) {
        ESP_LOGE(TAG, "psa_export_public_key failed: %d len=%zu", (int)status, pub_len);
        psa_destroy_key(*key_id);
        *key_id = 0;
        return -1;
    }
    return 0;
}

int sc_ecdh_shared(psa_key_id_t key_id, const uint8_t peer_pub64[64], uint8_t shared32[32])
{
    uint8_t peer65[65];
    peer65[0] = 0x04;
    memcpy(peer65 + 1, peer_pub64, 64);

    size_t out_len = 0;
    psa_status_t status = psa_raw_key_agreement(PSA_ALG_ECDH, key_id,
                                                peer65, 65,
                                                shared32, 32, &out_len);
    if (status != PSA_SUCCESS || out_len != 32) {
        ESP_LOGE(TAG, "psa_raw_key_agreement failed: %d (out_len=%zu)", (int)status, out_len);
        return -1;
    }
    return 0;
}

int sc_hkdf_login(const uint8_t shared32[32], const uint8_t ltmk32[32], uint8_t out64[64])
{
    uint8_t ikm[64];
    memcpy(ikm, shared32, 32);
    memcpy(ikm + 32, ltmk32, 32);

    const uint8_t *salt = (const uint8_t *)"smartcfg-login-salt";
    const uint8_t *info = (const uint8_t *)"smartcfg-login-info";

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);
    psa_set_key_algorithm(&attr, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);

    psa_key_id_t ikm_key = 0;
    psa_status_t status = psa_import_key(&attr, ikm, sizeof(ikm), &ikm_key);
    psa_reset_key_attributes(&attr);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "psa_import_key for HKDF failed: %d", (int)status);
        return -1;
    }

    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    status = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (status == PSA_SUCCESS) {
        status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,
                                                salt, strlen((const char *)salt));
    }
    if (status == PSA_SUCCESS) {
        status = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET, ikm_key);
    }
    if (status == PSA_SUCCESS) {
        status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                                info, strlen((const char *)info));
    }
    if (status == PSA_SUCCESS) {
        status = psa_key_derivation_output_bytes(&op, out64, 64);
    }

    psa_key_derivation_abort(&op);
    psa_destroy_key(ikm_key);

    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "HKDF failed: %d", (int)status);
        return -1;
    }
    return 0;
}

uint32_t sc_crc32(const uint8_t *data, size_t len)
{
    uint32_t crc = 0xffffffff;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int k = 0; k < 8; k++) {
            crc = (crc >> 1) ^ (0xedb88320 & (-(int)(crc & 1)));
        }
    }
    return ~crc;
}

int sc_aes_ccm_encrypt(const uint8_t key16[16], const uint8_t iv12[12],
                       const uint8_t *plain, size_t plain_len,
                       uint8_t *out, size_t *out_len)
{
    psa_algorithm_t alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 4);
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 128);
    psa_set_key_algorithm(&attr, alg);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);

    psa_key_id_t key_id = 0;
    psa_status_t status = psa_import_key(&attr, key16, 16, &key_id);
    psa_reset_key_attributes(&attr);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "psa_import_key for CCM failed: %d", (int)status);
        return -1;
    }

    size_t enc_len = 0;
    status = psa_aead_encrypt(key_id, alg,
                              iv12, 12,
                              NULL, 0,
                              plain, plain_len,
                              out, plain_len + 4,
                              &enc_len);
    psa_destroy_key(key_id);

    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "psa_aead_encrypt (CCM) failed: %d", (int)status);
        return -1;
    }
    *out_len = enc_len;
    return 0;
}

int sc_build_login_token(const uint8_t session64[64], const uint8_t peer_pub64[64], uint8_t enc8[8])
{
    /* 1. Calculate CRC32 of peer public key (4 bytes, little-endian) */
    uint32_t crc = sc_crc32(peer_pub64, 64);
    uint8_t plain_crc[4];
    plain_crc[0] = crc & 0xff;
    plain_crc[1] = (crc >> 8) & 0xff;
    plain_crc[2] = (crc >> 16) & 0xff;
    plain_crc[3] = (crc >> 24) & 0xff;
    ESP_LOGI(TAG, "Peer public key CRC32: 0x%08" PRIx32 " -> %02x %02x %02x %02x",
             crc, plain_crc[0], plain_crc[1], plain_crc[2], plain_crc[3]);

    /* 2. Key is session[16..32] */
    uint8_t key[16];
    memcpy(key, session64 + 16, 16);

    /* 3. Nonce is fixed 12 bytes: {16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27} */
    static const uint8_t login_nonce[12] = {16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27};

    /* 4. Encrypt plain_crc (4 bytes) -> out (8 bytes: 4B ciphertext + 4B MAC tag) */
    size_t out_len = 0;
    int rc = sc_aes_ccm_encrypt(key, login_nonce, plain_crc, 4, enc8, &out_len);
    if (rc != 0 || out_len != 8) {
        ESP_LOGE(TAG, "sc_aes_ccm_encrypt for login token failed: rc=%d len=%zu", rc, out_len);
        return -1;
    }
    ESP_LOGI(TAG, "Built login token (8 bytes): %02x%02x%02x%02x%02x%02x%02x%02x",
             enc8[0], enc8[1], enc8[2], enc8[3], enc8[4], enc8[5], enc8[6], enc8[7]);
    return 0;
}

int sc_build_operate(sc_session_t *s, const uint8_t *plain, size_t plain_len,
                     uint8_t *out, size_t *out_len)
{
    if (!s->ready) return -1;

    uint8_t key[16];
    memcpy(key, s->session + 16, 16);

    uint8_t iv[12] = {0};
    memcpy(iv, s->session + 36, 4);
    uint16_t seq = s->tx_counter;
    uint16_t epoch = s->tx_epoch;
    iv[8] = seq & 0xff;
    iv[9] = (seq >> 8) & 0xff;
    iv[10] = epoch & 0xff;
    iv[11] = (epoch >> 8) & 0xff;

    uint8_t enc[64];
    size_t enc_len = 0;
    int rc = sc_aes_ccm_encrypt(key, iv, plain, plain_len, enc, &enc_len);
    if (rc != 0) {
        ESP_LOGE(TAG, "sc_aes_ccm_encrypt for operate failed: %d", rc);
        return rc;
    }

    /* packet: LE seq(2) + ciphertext(plain_len) + tag(4) */
    out[0] = seq & 0xff;
    out[1] = (seq >> 8) & 0xff;
    memcpy(out + 2, enc, enc_len);
    *out_len = 2 + enc_len;

    s->tx_counter++;
    if (s->tx_counter == 0) s->tx_epoch++;
    return 0;
}

uint16_t sc_crc16(const uint8_t *data, size_t len)
{
    uint16_t crc = 0;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int k = 0; k < 8; k++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    return crc;
}

int sc_build_loock_cmd(uint16_t cmd_id, uint8_t key, const uint8_t *val, size_t val_len,
                       uint16_t seq_id, uint8_t *out, size_t *out_len)
{
    uint8_t l2_buf[64];
    size_t l2_len = 0;

    /* L2 Header: [0x55, 0x40] */
    l2_buf[l2_len++] = 0x55;
    l2_buf[l2_len++] = 0x40;

    /* KLV 1: BLE_CMD_ID (0xDF), len=2, val=cmd_id (big-endian) */
    l2_buf[l2_len++] = 0xDF;
    l2_buf[l2_len++] = 0x00;
    l2_buf[l2_len++] = 0x02;
    l2_buf[l2_len++] = (cmd_id >> 8) & 0xff;
    l2_buf[l2_len++] = cmd_id & 0xff;

    /* KLV 2: key, len=val_len (big-endian 16-bit), val */
    l2_buf[l2_len++] = key;
    l2_buf[l2_len++] = (val_len >> 8) & 0xff;
    l2_buf[l2_len++] = val_len & 0xff;
    memcpy(l2_buf + l2_len, val, val_len);
    l2_len += val_len;

    /* L1 Framing: [0xAB, 0x00, len_hi, len_lo, crc_hi, crc_lo, seq_hi, seq_lo] + l2_buf */
    uint16_t crc = sc_crc16(l2_buf, l2_len);

    out[0] = 0xAB;
    out[1] = 0x00;
    out[2] = (l2_len >> 8) & 0xff;
    out[3] = l2_len & 0xff;
    out[4] = (crc >> 8) & 0xff;
    out[5] = crc & 0xff;
    out[6] = (seq_id >> 8) & 0xff;
    out[7] = seq_id & 0xff;

    memcpy(out + 8, l2_buf, l2_len);
    *out_len = 8 + l2_len;

    return 0;
}

int sc_generate_otp(const uint8_t ltmk32[32], uint32_t epoch_sec, uint32_t *otp_out, uint32_t *remaining_sec)
{
    const uint8_t *salt = (const uint8_t *)"mi-lock-otp-salt";
    const uint8_t *info = (const uint8_t *)"mi-lock-otp-info";

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);
    psa_set_key_algorithm(&attr, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);

    psa_key_id_t ikm_key = 0;
    psa_status_t status = psa_import_key(&attr, ltmk32, 32, &ikm_key);
    psa_reset_key_attributes(&attr);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "psa_import_key for OTP failed: %d", (int)status);
        return -1;
    }

    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    status = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (status == PSA_SUCCESS) {
        status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,
                                                salt, strlen((const char *)salt));
    }
    if (status == PSA_SUCCESS) {
        status = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET, ikm_key);
    }
    if (status == PSA_SUCCESS) {
        status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                                info, strlen((const char *)info));
    }
    uint8_t derived_key[32];
    if (status == PSA_SUCCESS) {
        status = psa_key_derivation_output_bytes(&op, derived_key, 32);
    }
    psa_key_derivation_abort(&op);
    psa_destroy_key(ikm_key);

    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "OTP HKDF failed: %d", (int)status);
        return -1;
    }

    /* 30 minutes = 1800 seconds per slot */
    uint32_t slot = epoch_sec / 1800;
    uint8_t slot_le[4];
    slot_le[0] = slot & 0xff;
    slot_le[1] = (slot >> 8) & 0xff;
    slot_le[2] = (slot >> 16) & 0xff;
    slot_le[3] = (slot >> 24) & 0xff;

    psa_key_attributes_t hmac_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&hmac_attr, PSA_KEY_TYPE_HMAC);
    psa_set_key_algorithm(&hmac_attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_usage_flags(&hmac_attr, PSA_KEY_USAGE_SIGN_MESSAGE);

    psa_key_id_t hmac_key = 0;
    status = psa_import_key(&hmac_attr, derived_key, 32, &hmac_key);
    psa_reset_key_attributes(&hmac_attr);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "psa_import_key for HMAC failed: %d", (int)status);
        return -1;
    }

    uint8_t mac[32];
    size_t mac_len = 0;
    status = psa_mac_compute(hmac_key, PSA_ALG_HMAC(PSA_ALG_SHA_256),
                             slot_le, 4,
                             mac, sizeof(mac), &mac_len);
    psa_destroy_key(hmac_key);

    if (status != PSA_SUCCESS || mac_len < 4) {
        ESP_LOGE(TAG, "psa_mac_compute failed: %d", (int)status);
        return -1;
    }

    uint32_t raw_val = (uint32_t)mac[0] |
                       ((uint32_t)mac[1] << 8) |
                       ((uint32_t)mac[2] << 16) |
                       ((uint32_t)mac[3] << 24);
    if (otp_out) {
        *otp_out = raw_val % 1000000;
    }

    if (remaining_sec) {
        *remaining_sec = (slot + 1) * 1800 - epoch_sec;
    }

    return 0;
}
