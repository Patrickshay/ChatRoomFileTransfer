#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include "common.h"
#include "encryption.h"
#include "p2p.h"

#define BUF_SIZE 1024

extern unsigned char aes_key[16];
extern unsigned char aes_iv[16];

// Thread: listens on P2P port, reads framed MSG or FILE
void* p2p_listener_thread(void* arg) {
    int port = *(int*)arg; 
    free(arg);

    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1; setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in sa = { .sin_family=AF_INET,
                              .sin_port=htons(port),
                              .sin_addr.s_addr=INADDR_ANY };
    bind(sfd, (struct sockaddr*)&sa, sizeof(sa));
    listen(sfd, 5);
    printf("[P2P] Listening on %d...\n", port);

    while (1) {
        int cfd = accept(sfd, NULL, NULL);

        // 1) Read message type (3 chars + NUL)
        char type[4] = {0};
        if (recv(cfd, type, 3, MSG_WAITALL) != 3) { close(cfd); continue; }
        type[3] = '\0';

        // 2) Read payload length (uint32_t network order)
        uint32_t net_len;
        if (recv(cfd, &net_len, 4, MSG_WAITALL) != 4) { close(cfd); continue; }
        int payload_len = ntohl(net_len);
        if (payload_len <= 0 || payload_len > BUF_SIZE*10) { close(cfd); continue; }

        // 3) Read the encrypted payload
        unsigned char *enc = malloc(payload_len);
        if (recv(cfd, enc, payload_len, MSG_WAITALL) != payload_len) {
            free(enc);
            close(cfd);
            continue;
        }

        if (strcmp(type, "MSG") == 0) {
            unsigned char *dec = malloc(payload_len+1);
            aes_decrypt(enc, payload_len, aes_key, aes_iv, dec);
            dec[payload_len] = '\0';
            printf("\n[MSG] %s\n> ", dec);
            fflush(stdout);
            free(dec);
        } 
        else if (strcmp(type, "FIL") == 0) {
            // First payload is filename length + filename
            uint32_t fn_len = ntohl(*(uint32_t*)enc);
            char filename[256] = {0};
            memcpy(filename, enc+4, fn_len);
            FILE* fp = fopen(filename, "wb");
            int offset = 4 + fn_len;
            while (offset < payload_len) {
                int chunk = payload_len - offset;
                unsigned char dec[BUF_SIZE];
                int dl = aes_decrypt(enc+offset, chunk, aes_key, aes_iv, dec);
                fwrite(dec,1,dl,fp);
                offset += chunk;
            }
            fclose(fp);
            printf("\n[FILE] %s received\n> ", filename);
        }

        free(enc);
        close(cfd);
    }
    return NULL;
}

// Helper: send a framed MSG
void send_message_to_peer(const char* ip, int port, const char* message) {
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = { .sin_family=AF_INET,
                              .sin_port=htons(port) };
    inet_pton(AF_INET, ip, &sa.sin_addr);
    if (connect(sfd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        perror("[P2P] connect");
        close(sfd);
        return;
    }

    // Encrypt payload
    int mlen = strlen(message);
    unsigned char *enc = malloc(mlen);
    aes_encrypt((unsigned char*)message, mlen, aes_key, aes_iv, enc);

    // Build frame: "MSG"+len32+payload
    char hdr[3] = {'M','S','G'};
    uint32_t net_len = htonl(mlen);
    send(sfd, hdr,       3,           0);
    send(sfd, &net_len,  4,           0);
    send(sfd, enc,       mlen,        0);

    free(enc);
    close(sfd);
}

// Helper: send a framed FILE
void send_file_to_peer(const char* ip, int port, const char* filename) {
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = { .sin_family=AF_INET,
                              .sin_port=htons(port) };
    inet_pton(AF_INET, ip, &sa.sin_addr);

    printf("[DEBUG] send_file_to_peer: target %s:%d, file='%s'\n",
        ip, port, filename);
    fflush(stdout);

    if (connect(sfd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        perror("[P2P] connect");
        close(sfd);
        return;
    }

    printf("[DEBUG] Connected to peer %s:%d\n", ip, port);
    fflush(stdout);

    // Read file into memory (small files)
    FILE* fp = fopen(filename,"rb");
    if (!fp) { perror("[P2P] fopen"); close(sfd); return; }
    else {
        printf("[DEBUG] fopen succeeded, reading file...\n");
        fflush(stdout);
    }
    fseek(fp,0,SEEK_END);
    int flen = ftell(fp);
    rewind(fp);

    printf("[DEBUG] File size is %d bytes\n", flen);
    fflush(stdout);

    unsigned char *fbuf = malloc(flen);
    fread(fbuf,1,flen,fp);
    fclose(fp);

    // Encrypt file data
    unsigned char *enc = malloc(flen);
    aes_encrypt(fbuf, flen, aes_key, aes_iv, enc);
    free(fbuf);

    // Build filename part: length + bytes
    uint32_t fn_len = strlen(filename);
    uint32_t payload_len = 4 + fn_len + flen;

    char *payload = malloc(payload_len);
    // filename length
    *(uint32_t*)payload = htonl(fn_len);
    // filename bytes
    memcpy(payload+4, filename, fn_len);
    // encrypted file data
    memcpy(payload+4+fn_len, enc, flen);
    free(enc);

    // Frame: "FILE"+len32+payload
    char hdr[3] = {'F','I','L'};  // we check "FILE" by first 3, ignore last
    uint32_t net_len = htonl(payload_len);
    send(sfd, hdr,       3,           0);
    send(sfd, &net_len,  4,           0);
    send(sfd, payload,   payload_len, 0);

        // after sending the framed payload
    printf("[P2P] File '%s' sent to %s:%d successfully\n> ",
            filename, ip, port);
     fflush(stdout); 
    free(payload);
    close(sfd);
}
