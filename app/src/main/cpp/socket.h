#ifndef DPITUNNEL_SOCKET_H
#define DPITUNNEL_SOCKET_H

int recv_string(int socket, std::string & message);
int recv_string(int socket, std::string & message, struct timeval timeout);
int send_string(int socket, std::string string_to_send);
int send_string(int socket, std::string string_to_send, unsigned int split_position);
int init_remote_server_socket(int & remote_server_socket, std::string & remote_server_host, int remote_server_port, bool is_https, bool hostlist_condition);

#endif //DPITUNNEL_SOCKET_H
