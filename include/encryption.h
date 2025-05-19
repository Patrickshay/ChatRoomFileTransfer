#ifndef ENCRYPTION_H
#define ENCRYPTION_H

void generate_rsa_keys(const char* pubkey_file, const char* privkey_file);
int  rsa_encrypt_mem(unsigned char* pubkey_pem, long pem_len,
                     unsigned char* data, int data_len, unsigned char* encrypted);
int  rsa_decrypt_file(const char* privkey_file,
                      unsigned char* enc_data, int data_len, unsigned char* decrypted);

void generate_aes_key(unsigned char* key, unsigned char* iv);
int  aes_encrypt(unsigned char* plaintext, int plaintext_len,
                 unsigned char* key, unsigned char* iv, unsigned char* ciphertext);
int  aes_decrypt(unsigned char* ciphertext, int ciphertext_len,
                 unsigned char* key, unsigned char* iv, unsigned char* plaintext);

#endif // ENCRYPTION_H
