#include "fileIO.h"
#include "sni.h"
#include "sni_cert_gen.h"
#include "socket.h"
#include "dpi-bypass.h"

extern struct Settings settings;

std::string root_cert_store;

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

int recv_string_tls(int socket, SSL *context, std::string & message)
{
    std::string log_tag = "CPP/recv_string_tls";

    ssize_t read_size;
    size_t message_offset = 0;

    // Set receive timeout on socket
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 50;
    if(setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout)) < 0)
    {
        log_error(log_tag.c_str(), "Can't setsockopt on socket");
        return -1;
    }

    while(true)
    {
        if(message.size() - message_offset < 1024) // If there isn't any space in message string - just increase it
        {
            message.resize(message.size() + 1024);
        }

        read_size = SSL_read(context, &message[0] + message_offset, message.size() - message_offset);
        if(read_size < 0)
        {
            if(errno == EWOULDBLOCK || errno == EAGAIN)	break;
            if(errno == EINTR)      continue; // All is good. This is just interrrupt.
            else
            {
                log_error(log_tag.c_str(), "There is critical recv error. Can't process client. Errno: %s", std::strerror(errno));
                return -1;
            }
        }
        else if(read_size == 0)	return -1;

        message_offset += read_size;
    }

    message.resize(message_offset);

    return 0;
}

int send_string_tls(int socket, TLSContext *context, const std::string & string_to_send)
{
    std::string log_tag = "CPP/send_string_tls";

    if(string_to_send.empty())
        return 0;

    size_t offset = 0;

    // Set send timeout on socket
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 100;
    if(setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(timeout)) < 0)
    {
        log_error(log_tag.c_str(), "Can't setsockopt on socket");
        return -1;
    }

    while(string_to_send.size() - offset != 0)
    {
        ssize_t send_size = SSL_write(context, string_to_send.c_str() + offset, string_to_send.size() - offset);
        if(send_size < 0)
        {
            if(errno == EAGAIN) break;
            if(errno == EINTR)      continue; // All is good. This is just interrrupt.
            else {
                log_error(log_tag.c_str(), "There is critical send error. Can't process client. Errno: %s", std::strerror(errno));
                return -1;
            }
        }
        if(send_size == 0)
        {
            return -1;
        }
        offset += send_size;
    }

    return 0;
}

SSL* init_tls_server_server(std::string & sni)
{
    std::string log_tag = "CPP/init_tls_server_server";

    SSL *server_context = SSL_CTX_new(SSLv3_server_method());

    if (!server_context) {
        log_error(log_tag.c_str(), "Error creating server context");
        return NULL;
    }

    // Generate certificates
    GeneratedCA certificate;
    generate_ssl_cert(sni, certificate);

    // Load certificates
    tls_load_certificates(server_context,
                          reinterpret_cast<const unsigned char *>(&certificate.public_key_pem[0]), certificate.public_key_pem.size());
    tls_load_private_key(server_context,
                         reinterpret_cast<const unsigned char *>(&certificate.private_key_pem[0]), certificate.private_key_pem.size());

    if (!SSL_CTX_check_private_key(server_context)) {
        log_error(log_tag.c_str(), "Private key not loaded");
        return NULL;
    }

    return server_context;
}

SSL* init_tls_server_client(int client_socket, SSL* server_context)
{
    std::string log_tag = "CPP/init_tls_server_client";

    SSL *client = SSL_new(server_context);

    SSL_set_fd(client, client_socket);

    if (!SSL_accept(client))
    {
        log_error(log_tag.c_str(), "Error in handshake");
        return NULL;
    }

    return client;
}

SSL* init_tls_client(int socket, std::string & sni)
{
    std::string log_tag = "CPP/init_tls_client";

    SSL *client_context = SSL_CTX_new(SSLv3_client_method());

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

    // Set certificate validate function
    SSL_CTX_set_verify(client_context, SSL_VERIFY_PEER, verify_certificate);

    if (!client_context) {
        log_error(log_tag.c_str(), "Error initializing client context");
        return NULL;
    }

    SSL_set_fd(client_context, socket);

    tls_sni_set(client_context, sni.c_str());

    int ret;
    if ((ret = SSL_connect(client_context)) != 1) {
        log_error(log_tag.c_str(), "Handshake Error %i. Errno %s", ret, std::strerror(errno));
        return NULL;
    }

    return client_context;
}