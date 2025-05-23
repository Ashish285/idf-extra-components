/*
 * SPDX-FileCopyrightText: 2025 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "test_mocks.h"
#include <string.h>

uint8_t dummy_pbkdf2_output[32] = {
    0x83, 0x17, 0x93, 0x66, 0x0d, 0xe4, 0x91, 0x33, 0x66, 0xae, 0x1e, 0x37, 0x9b, 0x2c, 0xeb, 0x43,
    0x17, 0xc8, 0x87, 0x00, 0xcc, 0x07, 0x91, 0xd9, 0x8e, 0x5a, 0x2a, 0x2d, 0x5c, 0x71, 0xaf, 0x66
};

bool esp_encrypted_is_hmac_key_burnt_in_efuse(hmac_key_id_t hmac_key_id)
{
    // Simulate the behavior of checking if the HMAC key is burnt in efuse
    // For this example, we'll assume that the key is always burnt
    if (hmac_key_id == 2) {
        return true;
    }
    return false;
}

int esp_encrypted_img_pbkdf2_hmac_sha256(hmac_key_id_t hmac_key_id, const unsigned char *salt, size_t salt_len,
        size_t iteration_count, size_t key_length, unsigned char *output)
{
    // Simulate the behavior of PBKDF2 HMAC-SHA256 key derivation
    // For this example, we'll just fill the output with a known pattern
    memcpy(output, dummy_pbkdf2_output, key_length);
    return 0; // Indicate success
}

esp_err_t esp_ds_start_sign(const void *message,
    const esp_ds_data_t *data,
    hmac_key_id_t key_id,
    esp_ds_context_t **esp_ds_ctx)
{
    return 0;
}

unsigned int expected_signature[] = {
    0x006c3450, 0xdea677a2, 0x926820c4, 0x6d785259, 0x4b843538, 0x615aec9d, 0x56e0fcad, 0x749b45da,
    0x3f791700, 0x967ce676, 0x58b031b8, 0xef426f54, 0xb4f2fd90, 0x75a7a818, 0xb39fa150, 0x21e1502e,
    0xf7108fa4, 0x8c46f51c, 0x14e98795, 0x22667e59, 0xcb6cab5e, 0xdb961c2f, 0x0bdf10a7, 0xecc2fcc7,
    0x570753d3, 0xcbc6e011, 0x2ea88de6, 0xd7c81c73, 0xa2d9f65c, 0xa74fd309, 0x2a7a764b, 0x750bc352,
    0x8b27341a, 0x9ab95d23, 0x9caebeea, 0x5b410b4e, 0x5f26d119, 0xf1946d20, 0x8037e8f1, 0x5955b934,
    0x2b7ef75d, 0x69b7e85a, 0x330f056c, 0x92e47389, 0xcb715480, 0xb551e0fe, 0x4c7b3beb, 0xed67a7d1,
    0x53d19879, 0x3712444b, 0x25f6d982, 0x525ee85c, 0xba7d8521, 0xfcd73dbd, 0xe0ee096b, 0x779b61c7,
    0xba30c40d, 0xf9d53b71, 0x1581062b, 0x15163231, 0x65dc89e5, 0x6de575fc, 0x32058194, 0x550b64da,
    0xbff2ec40, 0x5fbd699d, 0x133656ff, 0xf34e3ac7, 0xbd054ce3, 0x8b89110d, 0xb9804481, 0xb7600a29,
    0x78435580, 0x3e1e3757, 0xd2d619a0, 0x8f2c327c, 0xb1c4901d, 0xf319e804, 0x966adf5b, 0x1ac533a0,
    0x76696abd, 0xe6289296, 0xcdbec067, 0xf77a5edd, 0xed0df021, 0xdd7cb0c2, 0x8bbc8f9b, 0xb9c41aaa,
    0xc7eca1e0, 0xe4238236, 0x4b22b649, 0x0897f841, 0xb94c9516, 0x2344ab37, 0xa73de816, 0x00029aa6
};

esp_ds_data_ctx_t *esp_secure_cert_get_ds_ctx()
{
    esp_ds_data_ctx_t *ds_ctx = (esp_ds_data_ctx_t *)malloc(sizeof(esp_ds_data_ctx_t));
    if (ds_ctx == NULL) {
        return NULL;
    }
    ds_ctx->esp_ds_data = calloc(1, sizeof(esp_ds_data_t));
    if (ds_ctx->esp_ds_data == NULL) {
        free(ds_ctx);
        return NULL;
    }

    ds_ctx->efuse_key_id = 0;
    ds_ctx->rsa_length_bits = 3072;
    return ds_ctx;
}

void esp_secure_cert_free_ds_ctx(esp_ds_data_ctx_t *ds_ctx)
{
    if (ds_ctx) {
        if (ds_ctx->esp_ds_data) {
            free(ds_ctx->esp_ds_data);
        }
        free(ds_ctx);
    }
}

esp_err_t esp_ds_finish_sign(void *signature, esp_ds_context_t *esp_ds_ctx)
{
    memcpy(signature, expected_signature, sizeof(expected_signature));
    return 0;
}

int esp_ds_rsaes_pkcs1_v15_unpadding(unsigned char *input,
    size_t ilen,
    unsigned char *output,
    size_t output_max_len,
    size_t *olen)
{
    int ret = 0;

    if (ilen < 11) {
        return -1;
    }

    /* Skip the first byte (0x00) */
    input++;

    /* Check the padding type */
    if (*input != 2) {
        return -1;
    }

    /* Check the padding length */
    for (int i = 2; i < ilen; i++) {
        if (input[i] == 0x00) {
            /* Found the end of the padding */
            if (i + 1 >= ilen) {
                return -1;
            }
            *olen = ilen - i - 2;
            memcpy(output, input + i + 1, *olen);
            return 0;
        }
    }
    /* No valid padding found */
    return -1;
}
