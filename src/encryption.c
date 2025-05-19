#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <string.h>
#include "encryption.h"

// RSA keygen
void generate_rsa_keys(const char* pubfile, const char* privfile) {
    int bits = 2048;
    unsigned long e = RSA_F4;
    RSA* rsa = RSA_new();
    BIGNUM* bne = BN_new();
    BN_set_word(bne, e);
    RSA_generate_key_ex(rsa, bits, bne, NULL);
    // write pub
    FILE* pub = fopen(pubfile, "wb");
    PEM_write_RSAPublicKey(pub, rsa);
    fclose(pub);
    // write priv
    FILE* priv = fopen(privfile, "wb");
    PEM_write_RSAPrivateKey(priv, rsa, NULL, NULL, 0, NULL, NULL);
    fclose(priv);
    RSA_free(rsa);
    BN_free(bne);
}

// RSA encrypt in-memory PEM
int rsa_encrypt_mem(unsigned char* pubkey_pem, long pem_len,
                    unsigned char* data, int data_len, unsigned char* encrypted) {
    BIO* bio = BIO_new_mem_buf(pubkey_pem, pem_len);
    RSA* rsa = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    int len = RSA_public_encrypt(data_len, data, encrypted, rsa, RSA_PKCS1_OAEP_PADDING);
    RSA_free(rsa);
    return len;
}

// RSA decrypt from file
int rsa_decrypt_file(const char* privfile,
                     unsigned char* enc_data, int data_len, unsigned char* decrypted) {
    FILE* priv = fopen(privfile, "rb");
    RSA* rsa = PEM_read_RSAPrivateKey(priv, NULL, NULL, NULL);
    fclose(priv);
    int len = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, RSA_PKCS1_OAEP_PADDING);
    RSA_free(rsa);
    return len;
}

// AES keygen
void generate_aes_key(unsigned char* key, unsigned char* iv) {
    RAND_bytes(key, AES_BLOCK_SIZE);
    RAND_bytes(iv,  AES_BLOCK_SIZE);
}

// AES encrypt (CFB128)
int aes_encrypt(unsigned char* plaintext, int plaintext_len,
                unsigned char* key, unsigned char* iv, unsigned char* ciphertext) {
    AES_KEY enc_key;
    unsigned char iv_copy[AES_BLOCK_SIZE];
    memcpy(iv_copy, iv, AES_BLOCK_SIZE);
    AES_set_encrypt_key(key, 128, &enc_key);
    int num = 0;
    AES_cfb128_encrypt(plaintext, ciphertext, plaintext_len, &enc_key, iv_copy, &num, AES_ENCRYPT);
    return plaintext_len;
}

// ---------------- AES DECRYPTION (CFB128) ----------------
int aes_decrypt(unsigned char* ciphertext, int ciphertext_len,
    unsigned char* key, unsigned char* iv,
    unsigned char* plaintext) {
AES_KEY cfb_key;
// Use AES_set_encrypt_key, not AES_set_decrypt_key
AES_set_encrypt_key(key, 128, &cfb_key);

unsigned char iv_copy[AES_BLOCK_SIZE];
memcpy(iv_copy, iv, AES_BLOCK_SIZE);

int num = 0;
AES_cfb128_encrypt(
ciphertext,
plaintext,
ciphertext_len,
&cfb_key,
iv_copy,
&num,
AES_DECRYPT
);
return ciphertext_len;
}

