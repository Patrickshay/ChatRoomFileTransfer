#ifndef COMMON_H
#define COMMON_H

#include <netinet/in.h>

#define MAX_CLIENTS    10
#define MAX_MSG_LEN    2048
#define SERVER_PORT    8888
#define P2P_PORT_BASE  9000
#define MAX_ROOMS         10
#define MAX_ROOM_NAME_LEN 32

typedef struct {
    int    sockfd;
    int    client_number;
    char   ip[INET_ADDRSTRLEN];
    int    p2p_port;
    char*  public_key_pem;    // RSA pubkey PEM
    long   public_key_len;
} ClientInfo;

typedef struct {
    int  room_id;
    char name[MAX_ROOM_NAME_LEN];
    int  member_count;
    int  members[MAX_CLIENTS];   // store client_number of each member
} Chatroom;

#endif // COMMON_H
