#ifndef P2P_H
#define P2P_H

void* p2p_listener_thread(void* arg);
void  send_message_to_peer(const char* ip, int port, const char* message);
void  send_file_to_peer(const char* ip, int port, const char* filename);

#endif // P2P_H
