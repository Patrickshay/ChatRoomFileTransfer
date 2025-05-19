#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include "common.h"
#include "encryption.h"

// 1) Static AES key/IV for the room
static unsigned char static_aes_key[16];
static unsigned char static_aes_iv[16];

ClientInfo clients[MAX_CLIENTS];
int client_count = 0;
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

Chatroom       rooms[MAX_ROOMS];
int            room_count = 0;
pthread_mutex_t rooms_mutex = PTHREAD_MUTEX_INITIALIZER;

// Utility: duplicate PEM to heap
static char* mem_dup(const char* src, long len) {
    char* p = malloc(len);
    memcpy(p, src, len);
    return p;
}

void *handle_client(void *arg) {
    int client_fd = *(int *)arg;
    free(arg);

    // Identify client IP
    struct sockaddr_in sa;
    socklen_t sl = sizeof(sa);
    getpeername(client_fd, (struct sockaddr*)&sa, &sl);

    // 2) Register client
    pthread_mutex_lock(&clients_mutex);
    int idx = client_count++;
    clients[idx].sockfd         = client_fd;
    clients[idx].client_number  = idx + 1;
    strcpy(clients[idx].ip, inet_ntoa(sa.sin_addr));
    pthread_mutex_unlock(&clients_mutex);

    // 3) Send client number
    send(client_fd, &clients[idx].client_number, sizeof(int), 0);

    // 4) Receive P2P port
    recv(client_fd, &clients[idx].p2p_port, sizeof(int), 0);

    // 5) Receive RSA public key PEM
    long pem_len;
    recv(client_fd, &pem_len, sizeof(long), 0);
    char* pem = malloc(pem_len);
    recv(client_fd, pem, pem_len, 0);
    clients[idx].public_key_pem = mem_dup(pem, pem_len);
    clients[idx].public_key_len = pem_len;
    free(pem);

    // ─── DEBUG: Print AES key/IV ───
    printf("[Server] AES Key = ");
    for(int i=0;i<16;i++) printf("%02X", static_aes_key[i]);
    printf("\n");
    printf("[Server] AES IV  = ");
    for(int i=0;i<16;i++) printf("%02X", static_aes_iv[i]);
    printf("\n");

    // 6) Encrypt & send AES key + IV
    unsigned char ekey[256], eiv[256];
    int eklen = rsa_encrypt_mem(
        (unsigned char*)clients[idx].public_key_pem,
        clients[idx].public_key_len,
        static_aes_key, 16, ekey
    );
    int eilen = rsa_encrypt_mem(
        (unsigned char*)clients[idx].public_key_pem,
        clients[idx].public_key_len,
        static_aes_iv, 16, eiv
    );
    send(client_fd, &eklen, sizeof(int), 0);
    send(client_fd, ekey, eklen, 0);
    send(client_fd, &eilen, sizeof(int), 0);
    send(client_fd, eiv, eilen, 0);

    // 7) Serve only discovery commands
    char buffer[MAX_MSG_LEN];
    int n;
    while((n=recv(client_fd, buffer, MAX_MSG_LEN, 0))>0) {
        buffer[n]='\0';
        // Create a new chatroom
        if (strncmp(buffer, "/createroom", 11) == 0) {
    char roomname[MAX_ROOM_NAME_LEN];
    if (sscanf(buffer, "/createroom %31[^\n]", roomname) != 1) {
        send(client_fd, "[Error] Usage: /createroom <name>\n", 33, 0);
    } else {
        pthread_mutex_lock(&rooms_mutex);
        if (room_count >= MAX_ROOMS) {
            pthread_mutex_unlock(&rooms_mutex);
            send(client_fd, "[Error] Max rooms reached\n", 25, 0);
        } else {
            int rid = room_count + 1;
            Chatroom *r = &rooms[room_count++];
            r->room_id = rid;
            strncpy(r->name, roomname, MAX_ROOM_NAME_LEN);
            r->member_count = 0;
            pthread_mutex_unlock(&rooms_mutex);
            char msg[64];
            snprintf(msg, sizeof(msg),
                     "[Info] Room '%s' created with ID %d\n",
                     roomname, rid);
            send(client_fd, msg, strlen(msg), 0);
        }
    }
}
        // List all chatrooms
        else if (strncmp(buffer, "/listrooms", 10) == 0) {
    pthread_mutex_lock(&rooms_mutex);
    int cnt = room_count;
    send(client_fd, &cnt, sizeof(int), 0);
    for (int i = 0; i < cnt; i++) {
        // send room_id + fixed‐length name
        send(client_fd, &rooms[i].room_id, sizeof(int), 0);
        send(client_fd, rooms[i].name, MAX_ROOM_NAME_LEN, 0);
    }
    pthread_mutex_unlock(&rooms_mutex);
}
        // Join a room
        else if (strncmp(buffer, "/joinroom", 9) == 0) {
    int rid;
    if (sscanf(buffer, "/joinroom %d", &rid) != 1) {
        send(client_fd, "[Error] Usage: /joinroom <room_id>\n", 33, 0);
    } else {
        pthread_mutex_lock(&rooms_mutex);
        Chatroom *r = NULL;
        for (int i = 0; i < room_count; i++)
            if (rooms[i].room_id == rid) { r = &rooms[i]; break; }
        if (!r) {
            pthread_mutex_unlock(&rooms_mutex);
            send(client_fd, "[Error] Room ID not found\n", 26, 0);
        } else if (r->member_count >= MAX_CLIENTS) {
            pthread_mutex_unlock(&rooms_mutex);
            send(client_fd, "[Error] Room full\n", 18, 0);
        } else {
            r->members[r->member_count++] = clients[idx].client_number;
            pthread_mutex_unlock(&rooms_mutex);
            // Notify the joiner:
            char msg[64];
            snprintf(msg, sizeof(msg),
                     "[Info] Joined room '%s'\n", r->name);
            send(client_fd, msg, strlen(msg), 0);
            // TODO: broadcast join notification via P2P if you like
        }
    }
}
       // Leave a room
        else if (strncmp(buffer, "/leaveroom", 10) == 0) {
    int rid;
    if (sscanf(buffer, "/leaveroom %d", &rid) != 1) {
        send(client_fd, "[Error] Usage: /leaveroom <room_id>\n", 34, 0);
    } else {
        pthread_mutex_lock(&rooms_mutex);
        Chatroom *r = NULL;
        for (int i = 0; i < room_count; i++)
            if (rooms[i].room_id == rid) { r = &rooms[i]; break; }
        if (!r) {
            pthread_mutex_unlock(&rooms_mutex);
            send(client_fd, "[Error] Room ID not found\n", 26, 0);
        } else {
            // remove this client_number from r->members[]
            int cn = clients[idx].client_number;
            int w = 0;
            for (int i = 0; i < r->member_count; i++) {
                if (r->members[i] != cn)
                    r->members[w++] = r->members[i];
            }
            r->member_count = w;
            pthread_mutex_unlock(&rooms_mutex);
            send(client_fd, "[Info] Left the room\n", 21, 0);
            // TODO: broadcast leave notification via P2P if desired
        }
    }
}
        // List members of a room
        else if (strncmp(buffer, "/listmembers", 12) == 0) {
    int rid;
    if (sscanf(buffer, "/listmembers %d", &rid) != 1) {
        send(client_fd, "[Error] Usage: /listmembers <room_id>\n", 37, 0);
    } else {
        pthread_mutex_lock(&rooms_mutex);
        Chatroom *r = NULL;
        for (int i = 0; i < room_count; i++)
            if (rooms[i].room_id == rid) { r = &rooms[i]; break; }
        if (!r) {
            pthread_mutex_unlock(&rooms_mutex);
            send(client_fd, "[Error] Room ID not found\n", 26, 0);
        } else {
            int mc = r->member_count;
            send(client_fd, &mc, sizeof(int), 0);
            for (int i = 0; i < mc; i++) {
                // lookup that member’s ClientInfo
                int cnum = r->members[i];
                for (int j = 0; j < client_count; j++) {
                    if (clients[j].client_number == cnum) {
                        send(client_fd, &clients[j], sizeof(ClientInfo), 0);
                        break;
                    }
                }
            }
            pthread_mutex_unlock(&rooms_mutex);
        }
    }
}
        if(!strncmp(buffer,"/getpeerinfo",12)) {
            int tgt; sscanf(buffer,"/getpeerinfo %d",&tgt);
            pthread_mutex_lock(&clients_mutex);
            for(int i=0;i<client_count;i++){
                if(clients[i].client_number==tgt){
                    send(client_fd,&clients[i],sizeof(ClientInfo),0);
                    break;
                }
            }
            pthread_mutex_unlock(&clients_mutex);
        }
        else if(!strncmp(buffer,"/listclients",12)) {
            pthread_mutex_lock(&clients_mutex);
            send(client_fd,&client_count,sizeof(int),0);
            for(int i=0;i<client_count;i++){
                send(client_fd,&clients[i],sizeof(ClientInfo),0);
            }
            pthread_mutex_unlock(&clients_mutex);
        }
    }

    close(client_fd);
    return NULL;
}

void start_server() {
    // Generate the ONE static AES key+IV for the entire chatroom
    generate_aes_key(static_aes_key, static_aes_iv);

    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    int opt=1;
    setsockopt(sfd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));

    struct sockaddr_in sa={0};
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons(SERVER_PORT);
    sa.sin_addr.s_addr = INADDR_ANY;

    bind(sfd,(struct sockaddr*)&sa,sizeof(sa));
    listen(sfd, MAX_CLIENTS);
    printf("Server started on port %d\n", SERVER_PORT);

    while(1) {
        struct sockaddr_in ca;
        socklen_t cl = sizeof(ca);
        int *cfd = malloc(sizeof(int));
        *cfd = accept(sfd,(struct sockaddr*)&ca,&cl);
        pthread_t tid;
        pthread_create(&tid,NULL,handle_client,cfd);
        pthread_detach(tid);
    }
}
