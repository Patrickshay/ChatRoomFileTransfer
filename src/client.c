#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include "common.h"
#include "encryption.h"
#include "p2p.h"

unsigned char aes_key[16], aes_iv[16];
int           sockfd, client_number;

// ─── Peer Cache + Server Alive Flag + One-Time Warning ───
static ClientInfo cached_peers[MAX_CLIENTS];
static int        cached_count = 0;
static int        server_alive  = 1;
static int        warned        = 0;
static int current_room = 0;  // 0 = not in any room

#define WARN_ONCE(msg) do {            \
  if (!warned) {                       \
    fprintf(stderr, "%s\n", msg);      \
    warned = 1;                        \
  }                                     \
} while (0)

// ─── Fetch a single peer’s info, with fallback to cache ───
void fetch_peer_info(int target, ClientInfo* out) {
  char req[32];
  sprintf(req, "/getpeerinfo %d", target);

  if (server_alive) {
    if (send(sockfd, req, strlen(req), 0) <= 0) {
      WARN_ONCE("[Client] Server disconnected—entering P2P-only mode.");
      server_alive = 0;
    }
  }
  if (server_alive) {
    if (recv(sockfd, out, sizeof(ClientInfo), 0) <= 0) {
      WARN_ONCE("[Client] Server disconnected—entering P2P-only mode.");
      server_alive = 0;
    } else {
      // update cache
      for (int i = 0; i < cached_count; i++) {
        if (cached_peers[i].client_number == target) {
          cached_peers[i] = *out;
          break;
        }
      }
      return;
    }
  }
  // fallback: linear search in cache
  for (int i = 0; i < cached_count; i++) {
    if (cached_peers[i].client_number == target) {
      *out = cached_peers[i];
      break;
    }
  }
  if (!server_alive) {
    printf("[Client] Using cached info for client %d.\n", target);
  }
}

// ─── Fetch full peer list, with fallback to cache ───
int fetch_peer_list(ClientInfo** list) {
  if (server_alive) {
    if (send(sockfd, "/listclients", strlen("/listclients"), 0) <= 0) {
      WARN_ONCE("[Client] Server disconnected—entering P2P-only mode.");
      server_alive = 0;
    }
  }
  if (server_alive) {
    int cnt;
    if (recv(sockfd, &cnt, sizeof(int), 0) <= 0) {
      WARN_ONCE("[Client] Server disconnected—entering P2P-only mode.");
      server_alive = 0;
    } else {
      // got fresh list
      *list = malloc(cnt * sizeof(ClientInfo));
      for (int i = 0; i < cnt; i++) {
        recv(sockfd, &(*list)[i], sizeof(ClientInfo), 0);
      }
      // update cache
      memcpy(cached_peers, *list, cnt * sizeof(ClientInfo));
      cached_count = cnt;
      return cnt;
    }
  }
  // fallback to cache
  *list = cached_peers;
  if (!server_alive) {
    printf("[Client] Using cached peer list (%d entries).\n", cached_count);
  }
  return cached_count;
}

// ─── Main client logic ───
void start_client() {
  struct sockaddr_in sa = {0};
  char buf[MAX_MSG_LEN];

  // 1) connect to server
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  sa.sin_family      = AF_INET;
  sa.sin_port        = htons(SERVER_PORT);
  sa.sin_addr.s_addr = inet_addr("127.0.0.1");
  connect(sockfd, (struct sockaddr*)&sa, sizeof(sa));

  // 2) receive client number & send P2P port
  recv(sockfd, &client_number, sizeof(int), 0);
  int p2p_port = P2P_PORT_BASE + client_number;
  send(sockfd, &p2p_port, sizeof(int), 0);

  // 3) RSA keygen + send public key PEM
  generate_rsa_keys("pub.pem", "priv.pem");
  FILE* f = fopen("pub.pem", "rb");
  fseek(f, 0, SEEK_END);
  long sz = ftell(f);
  rewind(f);
  char* pem = malloc(sz);
  fread(pem, 1, sz, f);
  fclose(f);
  send(sockfd, &sz,  sizeof(long), 0);
  send(sockfd, pem, sz,        0);

  // 4) receive encrypted AES key
  int  ek;    unsigned char ekey[256];
  recv(sockfd, &ek,    sizeof(int), 0);
  recv(sockfd, ekey, ek,           0);
  rsa_decrypt_file("priv.pem", ekey, ek, aes_key);

  // 5) receive encrypted AES IV
  int  ei;    unsigned char eiv[256];
  recv(sockfd, &ei,    sizeof(int), 0);
  recv(sockfd, eiv, ei,           0);
  rsa_decrypt_file("priv.pem", eiv, ei, aes_iv);

  free(pem);

  // 6) seed cache from server
  cached_count = fetch_peer_list(&cached_peers);
  printf("[Client] Cached %d peers from server.\n", cached_count);

  // DEBUG: show AES key/IV on each client
  printf("[Client] AES Key = ");
  for (int i = 0; i < 16; i++) printf("%02X", aes_key[i]);
  printf("\n[Client] AES IV  = ");
  for (int i = 0; i < 16; i++) printf("%02X", aes_iv[i]);
  printf("\n");

  // 7) start P2P listener
  pthread_t tid; 
  int* pp = malloc(sizeof(int)); *pp = p2p_port;
  pthread_create(&tid, NULL, p2p_listener_thread, pp);
  pthread_detach(tid);

  // Ask server for the list of members in a given room
int fetch_member_list(int rid, ClientInfo** list) {
  char req[32];
  sprintf(req, "/listmembers %d", rid);
  send(sockfd, req, strlen(req), 0);

  int cnt;
  recv(sockfd, &cnt, sizeof(cnt), 0);
  *list = malloc(cnt * sizeof(ClientInfo));
  for (int i = 0; i < cnt; i++) {
      recv(sockfd, &(*list)[i], sizeof(ClientInfo), 0);
  }
  return cnt;
}

  // 8) CLI loop
  printf("Client %d ready> ", client_number);
  fflush(stdout);

  printf("Chatroom Commands:\n"
    "  /listrooms\n"
    "  /createroom <name>\n"
    "  /joinroom <room_id>\n"
    "  /leaveroom <room_id>\n"
    "  /listmembers <room_id>\n"
    "P2P in current room:\n"
    "  /msg <client#> <message>\n"
    "  /broadcast <message>\n"
    "  /sendfile <client#> <filename>\n"
    "  /sendfilegroup <filename>\n"
    "> ");
fflush(stdout);

while (fgets(buf, sizeof(buf), stdin)) {
 buf[strcspn(buf, "\n")] = '\0';

 // ─── Chatroom commands ───────────────────────────────────────
 if (!strncmp(buf, "/listrooms", 10)) {
     send(sockfd, "/listrooms", 10, 0);
     int rc; recv(sockfd, &rc, sizeof(rc), 0);
     printf("[Rooms] %d available\n", rc);
     for (int i = 0; i < rc; i++) {
         int  rid; char name[MAX_ROOM_NAME_LEN];
         recv(sockfd, &rid, sizeof(rid), 0);
         recv(sockfd, name, MAX_ROOM_NAME_LEN, 0);
         printf("  %2d: %s\n", rid, name);
     }

 } else if (!strncmp(buf, "/createroom", 11)) {
     send(sockfd, buf, strlen(buf), 0);
     recv(sockfd, buf, MAX_MSG_LEN, 0);
     printf("%s", buf);

 } else if (!strncmp(buf, "/joinroom", 9)) {
    int rid, got = sscanf(buf, "/joinroom %d", &rid);
    if (got != 1) {
      fprintf(stderr, "[Error] Usage: /joinroom <room_id>\n");
   } else {
      send(sockfd, buf, strlen(buf), 0);
      int n = recv(sockfd, buf, MAX_MSG_LEN-1, 0);
      if (n > 0) {
          buf[n] = '\0';
          printf("%s", buf);
          // Only on successful join do we set current_room
          if (strstr(buf, "[Info] Joined room") == buf) {
              current_room = rid;
          }
      }
  }
} else if (!strncmp(buf, "/leaveroom", 10)) {
  int rid, got = sscanf(buf, "/leaveroom %d", &rid);
  if (got != 1) {
      fprintf(stderr, "[Error] Usage: /leaveroom <room_id>\n");
  } else {
      send(sockfd, buf, strlen(buf), 0);
      int n = recv(sockfd, buf, MAX_MSG_LEN-1, 0);
      if (n > 0) {
          buf[n] = '\0';
          printf("%s", buf);
          // Only on successful leave do we clear current_room
          if (strstr(buf, "[Info] Left the room") == buf) {
              current_room = 0;
          }
      }
  }
}
else if (!strncmp(buf, "/listmembers", 12)) {
     int rid, got = sscanf(buf, "/listmembers %d", &rid);
     if (got != 1) {
         fprintf(stderr, "[Error] Usage: /listmembers <room_id>\n");
     } else {
         send(sockfd, buf, strlen(buf), 0);
         int mc; recv(sockfd, &mc, sizeof(mc), 0);
         printf("[Members] %d in this room\n", mc);
         for (int i = 0; i < mc; i++) {
             ClientInfo ci;
             recv(sockfd, &ci, sizeof(ci), 0);
             printf("  Client %2d @ %s (P2P port %d)\n",
                    ci.client_number, ci.ip, ci.p2p_port);
         }
     }

 // ─── P2P commands ────────────────────────────────────────────
 } else if (!strncmp(buf, "/msg", 4)) {
     int tgt; char msg[MAX_MSG_LEN];
     int got = sscanf(buf, "/msg %d %[^\n]", &tgt, msg);
     if (got < 2) {
         fprintf(stderr, "[Error] Usage: /msg <client#> <message>\n");
     } else {
         ClientInfo peer; fetch_peer_info(tgt, &peer);
         send_message_to_peer(peer.ip, peer.p2p_port, msg);
     }

 } else if (!strncmp(buf, "/broadcast", 10)) {
  if (current_room == 0) {
      fprintf(stderr, "[Error] Join a room first with /joinroom\n");
  } else {
      char message[MAX_MSG_LEN];
      int got = sscanf(buf, "/broadcast %[^\n]", message);
      if (got < 1) {
          fprintf(stderr, "[Error] Usage: /broadcast <message>\n");
      } else {
          // fetch only members of current_room
          ClientInfo *members;
          int cnt = fetch_member_list(current_room, &members);
          for (int i = 0; i < cnt; i++) {
              if (members[i].client_number != client_number) {
                  send_message_to_peer(
                    members[i].ip,
                    members[i].p2p_port,
                    message
                  );
              }
          }
          free(members);
      }
  }
} else if (!strncmp(buf, "/sendfilegroup", 14)) {
  if (current_room == 0) {
      fprintf(stderr, "[Error] Join a room first with /joinroom\n");
  } else {
      char filename[256];
      int got = sscanf(buf, "/sendfilegroup %255s", filename);
      if (got < 1) {
          fprintf(stderr, "[Error] Usage: /sendfilegroup <filename>\n");
      } else if (access(filename, R_OK) != 0) {
          fprintf(stderr, "[Error] File '%s' not found\n", filename);
      } else {
          ClientInfo *members;
          int cnt = fetch_member_list(current_room, &members);
          for (int i = 0; i < cnt; i++) {
              if (members[i].client_number != client_number) {
                  send_file_to_peer(
                    members[i].ip,
                    members[i].p2p_port,
                    filename
                  );
              }
          }
          free(members);
      }
  }
}

// ─── Unknown ──
else {
     fprintf(stderr,
       "[Error] Unknown command.\n"
       " Available: /listrooms, /createroom, /joinroom,\n"
       "            /leaveroom, /listmembers,\n"
       "            /msg, /broadcast, /sendfile\n");
 }

 // prompt again
 printf("> ");
 fflush(stdout);
}

  close(sockfd);
}
