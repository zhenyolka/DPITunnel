#ifndef DPITUNNEL_SNI_H
#define DPITUNNEL_SNI_H

#include <tlse.h>
#include <string>

/*int recv_string_tls(SSL* client, int client_socket, std::string & message);
int send_string_tls(SSL* client, std::string & string_to_send);
SSL* init_tls_server(std::string &sni);
SSL* accept_tls_client(int client_socket, SSL* tls_serv_ctx);
int deinit_tls_server(SSL* tls_serv_ctx);*/
int recv_string_tls(int socket, TLSContext *context, std::string & message, bool is_server);
int send_string_tls(int client_socket, TLSContext *client_context, const std::string& string_to_send);
SSL* init_tls_server_server();
SSL* init_tls_server_client(int client_socket, SSL* server_context, std::string & sni);
SSL* init_tls_client(int client_socket, std::string & sni);

#endif //DPITUNNEL_SNI_H
