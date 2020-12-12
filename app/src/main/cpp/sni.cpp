#include "fileIO.h"
#include "sni.h"
#include "sni_cert_gen.h"
#include "socket.h"
#include "dpi-bypass.h"

extern struct Settings settings;

std::string root_cert_store;

/*int recv_string_tls(SSL* client, int client_socket, std::string & message)
{
    std::string log_tag = "CPP/recv_string_tls";

    std::string buffer(1024, ' ');
    ssize_t read_size = 0;
    size_t message_offset = 0;

    bool is_received = false;

    while(true)
    {
        read_size = SSL_read(client, &buffer[0], buffer.size());
        if(is_received && read_size <= 0)
            break;
        if(read_size < 0)
        {
            if(read_size == TLS_GENERIC_ERROR)
            {
                int err = 0;
                socklen_t size = sizeof (err);
                int check = getsockopt (client_socket, SOL_SOCKET, SO_ERROR, &err, &size);
                if (check != 0)
                {
                    log_error(log_tag.c_str(), "There is critical tls read error. Can't process client");
                    return -1;
                }
                break;
            } else
                continue;
        }

        if(message_offset + read_size >= message.size()) // If there isn't any space in message string - just increase it
        {
            message.resize(message_offset + read_size + 1024);
        }

        message.insert(message.begin() + message_offset, buffer.begin(), buffer.begin() + read_size);
        message_offset += read_size;

        is_received = true;
    }

    message.resize(message_offset);

    return 0;
}

int send_string_tls(SSL* client, std::string &string_to_send)
{
    std::string log_tag = "CPP/send_string_tls";

    if(string_to_send.empty())
        return 0;

    size_t offset = 0;

    while(string_to_send.size() - offset != 0)
    {
        ssize_t send_size = SSL_write(client, string_to_send.c_str() + offset, string_to_send.size() - offset);
        if(send_size < 0)
        {
            log_error(log_tag.c_str(), "There is critical tls send error. Can't process client");
            return -1;
        }
        offset += send_size;
    }

    return 0;
}

SSL* init_tls_server(std::string &sni)
{
    GeneratedCA certificate;
    generate_ssl_cert(sni, certificate);

    SSL *tls_serv_ctx;
    std::string log_tag = "CPP/init_tls_server";
    tls_serv_ctx = SSL_CTX_new(SSLv3_server_method());
    if (!tls_serv_ctx) {
        log_error(log_tag.c_str(), "Error creating server context");
        return NULL;
    }
    tls_load_certificates(tls_serv_ctx,
                          reinterpret_cast<const unsigned char *>(certificate.public_key_pem.c_str()),
                          certificate.public_key_pem.size());
    tls_load_private_key(tls_serv_ctx,
            reinterpret_cast<const unsigned char *>(certificate.private_key_pem.c_str()),
            certificate.private_key_pem.size());

    if (!SSL_CTX_check_private_key(tls_serv_ctx)) {
        log_error(log_tag.c_str(), "Private key not loaded");
        return NULL;
    }
    return tls_serv_ctx;
}

SSL* accept_tls_client(int client_socket, SSL* tls_serv_ctx)
{
    std::string log_tag = "CPP/accept_tls_client";
    SSL *client = SSL_new(tls_serv_ctx);
    if (!client) {
        log_error(log_tag.c_str(), "Error creating SSL client");
        return NULL;
    }
    SSL_set_fd(client, client_socket);
    if (!SSL_accept(client)){
        log_error(log_tag.c_str(), "Error in handshake");
        SSL_shutdown(client);
        SSL_free(client);
        return NULL;
    }
    return client;
}

int deinit_tls_server(SSL* tls_serv_ctx)
{
    SSL_CTX_free(tls_serv_ctx);
    return 0;
}*/
int verify_signature(struct TLSContext *context, struct TLSCertificate **certificate_chain, int len) {
    return no_error;
}

int verify_certificate(struct TLSContext *context, struct TLSCertificate **certificate_chain, int len) {
    int i;
    int err;

    if (certificate_chain) {
        for (i = 0; i < len; i++) {
            struct TLSCertificate *certificate = certificate_chain[i];
            // check validity date
            err = tls_certificate_is_valid(certificate);
            if (err)
                return err;
        }
    }
    // check if chain is valid
    err = tls_certificate_chain_is_valid(certificate_chain, len);
    if (err)
        return err;

    // check certificate subject
    // DON'T CHECK SUBJECT SINCE WE USE FAKE SNI
    /*if ((!context->is_server) && (context->sni) && (len > 0) && (certificate_chain)) {
        err = tls_certificate_valid_subject(certificate_chain[0], context->sni);
        if (err)
            return err;
    }*/

    err = tls_certificate_chain_is_valid_root(context, certificate_chain, len);
    if (err)
        return err;

    return no_error;
}

int send_pending(int client_sock, struct TLSContext *context) {
    std::string log_tag = "CPP/send_pending";
    unsigned int out_buffer_len = 0;
    const unsigned char *out_buffer = tls_get_write_buffer(context, &out_buffer_len);
    unsigned int out_buffer_index = 0;
    int send_res = 0;
    while ((out_buffer) && (out_buffer_len > 0)) {
        int res = send(client_sock, (char *)&out_buffer[out_buffer_index], out_buffer_len, 0);
        if (res == 0) {
            send_res = res;
            break;
        }
        if (res < 0) {
            log_error(log_tag.c_str(), "Error in send() function");
            return -1;
        }
        out_buffer_len -= res;
        out_buffer_index += res;
    }
    tls_buffer_clear(context);
    return send_res;
}

int recv_string_tls(int socket, TLSContext *context, std::string & message, bool is_server)
{
    std::string log_tag = "CPP/recv_string_tls";

    std::string buffer;
    ssize_t read_size;

    while (true)
    {
        if(recv_string(socket, buffer) == -1)
            return -1;
        if (buffer.empty())
        {
            message.resize(0);
            return 0;
        }

        if (tls_consume_stream(context, reinterpret_cast<const unsigned char *>(&buffer[0]),
                buffer.size(), verify_signature) < 0) {
            log_error(log_tag.c_str(), "Error in consume stream");
            return -1;
        }

        if (send_pending(socket, context) == -1)
        {
            log_error(log_tag.c_str(), "Error in send pending");
            return -1;
        }

        if (is_server ? tls_established(context) == 1 : tls_established(context))
            break;
    }

    size_t message_offset = 0;

    while(true)
    {
        if(message.size() - message_offset < 1024) // If there isn't any space in message string - just increase it
        {
            message.resize(message.size() + 1024);
        }

        read_size = tls_read(context, reinterpret_cast<unsigned char *>(&message[0] + message_offset), message.size() - message_offset);
        if (read_size < 0)
        {
            log_error(log_tag.c_str(), "Failed to read");
            return -1;
        }
        else if(read_size == 0) break;

        if(message_offset + read_size >= message.size()) // If there isn't any space in message string - just increase it
        {
            message.resize(message_offset + read_size + 1024);
        }

        message_offset += read_size;
    }

    message.resize(message_offset);

    return 0;
}

int send_string_tls(int client_socket, TLSContext *client_context, const std::string& string_to_send)
{
    if (string_to_send.empty())
        return 0;
    tls_write(client_context, reinterpret_cast<const unsigned char *>(&string_to_send[0]), string_to_send.size());
    if (send_pending(client_socket, client_context) == -1)
        return -1;
    return 0;
}

SSL* init_tls_server_server()
{
    struct TLSContext *server_context = tls_create_context(1, TLS_V12);

    return server_context;
}

SSL* init_tls_server_client(int client_socket, SSL* server_context, std::string & sni)
{
    std::string log_tag = "CPP/init_tls_server_client";

    struct TLSContext *client_context = tls_accept(server_context);

    // Process ClientHello
    std::string buffer(1024, ' ');

    // Generate certificates
    GeneratedCA certificate;
    generate_ssl_cert(sni, certificate);

    // Load certificates
    tls_load_certificates(client_context,
                          reinterpret_cast<const unsigned char *>(&certificate.public_key_pem[0]), certificate.public_key_pem.size());
    tls_load_private_key(client_context,
                         reinterpret_cast<const unsigned char *>(&certificate.private_key_pem[0]), certificate.private_key_pem.size());

    ssize_t read_size;

    while ((read_size = recv(client_socket, &buffer[0], buffer.size(), 0)) > 0)
    {
        if (tls_consume_stream(client_context,
                reinterpret_cast<const unsigned char *>(&buffer[0]),
                read_size, verify_signature) > 0)
            break;
    }

    if(read_size < 0)
    {
        log_error(log_tag.c_str(), "Failed to process ClientHello");
        return NULL;
    }

    if (send_pending(client_socket, client_context) == -1)
        return NULL;

    return client_context;
}

SSL* init_tls_client(int socket, std::string & sni)
{
    std::string log_tag = "CPP/init_tls_client";

    struct TLSContext *client_context = tls_create_context(0, TLS_V12);

    // Load root certificates
    // Read them from file if need
    if (root_cert_store.empty())
        if(read_file(settings.app_files_dir + "/root.pem", root_cert_store) != 0)
        {
            log_error(log_tag.c_str(), "Failed to read verified root CA certificates");
            return NULL;
        }
    // Load them to tlse
    tls_load_root_certificates(client_context,
                               reinterpret_cast<const unsigned char *>(root_cert_store.c_str()),
                               root_cert_store.size());

    // Set sni. It may contain fake SNI to bypass DPI
    tls_sni_set(client_context, sni.c_str());

    // Generate and send ClientHello
    tls_client_connect(client_context);
    send_pending(socket, client_context);

    // Process ServerHello
    std::string buffer(1024, ' ');

    ssize_t read_size;

    while ((read_size = recv(socket, &buffer[0], buffer.size(), 0)) > 0) {
        tls_consume_stream(client_context, reinterpret_cast<const unsigned char *>(&buffer[0]), read_size, verify_certificate);
        send_pending(socket, client_context);
        if (tls_established(client_context))
            break;
    }

    if(read_size < 0)
    {
        log_error(log_tag.c_str(), "Failed to process ServerHello");
        return NULL;
    }

    return client_context;
}