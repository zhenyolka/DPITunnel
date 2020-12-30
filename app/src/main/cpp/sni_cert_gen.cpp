#include "dpi-bypass.h"
#include "fileIO.h"
#include "sni_cert_gen.h"
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

extern struct Settings settings;

const int RSA_KEY_BITS = 2048;
const std::string REQ_DN_C = "RU";
const std::string REQ_DN_ST = "The Great Russia";
const std::string REQ_DN_L = "Secret city";
const std::string REQ_DN_O = "DPI Tunnel inc. & Umbrella";
const std::string REQ_DN_OU = "Research";

std::string root_crt;
std::string root_key;

std::map<std::string, GeneratedCA> certCache;

int load_ca(EVP_PKEY **ca_key, X509 **ca_crt)
{
    BIO *bio = NULL;
    *ca_crt = NULL;
    *ca_key = NULL;

    /* Load CA public key. */
    bio = BIO_new(BIO_s_mem());
    BIO_puts(bio, root_crt.c_str());
    *ca_crt = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!*ca_crt)
    {
        BIO_free_all(bio);
        X509_free(*ca_crt);
        EVP_PKEY_free(*ca_key);
        return 0;
    }
    BIO_free_all(bio);

    /* Load CA private key. */
    bio = BIO_new(BIO_s_mem());
    BIO_puts(bio, root_key.c_str());
    *ca_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!*ca_key)
    {
        BIO_free_all(bio);
        X509_free(*ca_crt);
        EVP_PKEY_free(*ca_key);
        return 0;
    }
    BIO_free_all(bio);
    return 1;
}

int add_ext(STACK_OF(X509_EXTENSION) *sk, int nid, const char *value) {
    X509_EXTENSION *ex;
    ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
    if (!ex)
        return 0;
    sk_X509_EXTENSION_push(sk, ex);
    return 1;
}

int generate_key_csr(EVP_PKEY **key, X509_REQ **req, std::string & REQ_DN_CN)
{
    *key = NULL;
    *req = NULL;
    RSA *rsa = NULL;
    BIGNUM *e = NULL;

    *key = EVP_PKEY_new();
    if (!*key){
        EVP_PKEY_free(*key);
        X509_REQ_free(*req);
        RSA_free(rsa);
        BN_free(e);
        return 0;

    }
    *req = X509_REQ_new();
    if (!*req)
    {
        EVP_PKEY_free(*key);
        X509_REQ_free(*req);
        RSA_free(rsa);
        BN_free(e);
        return 0;
    }
    rsa = RSA_new();
    if (!rsa)
    {
        EVP_PKEY_free(*key);
        X509_REQ_free(*req);
        RSA_free(rsa);
        BN_free(e);
        return 0;
    }
    e = BN_new();
    if (!e)
    {
        EVP_PKEY_free(*key);
        X509_REQ_free(*req);
        RSA_free(rsa);
        BN_free(e);
        return 0;
    }

    BN_set_word(e, 65537);
    if (!RSA_generate_key_ex(rsa, RSA_KEY_BITS, e, NULL))
    {
        EVP_PKEY_free(*key);
        X509_REQ_free(*req);
        RSA_free(rsa);
        BN_free(e);
        return 0;
    }
    if (!EVP_PKEY_assign_RSA(*key, rsa))
    {
        EVP_PKEY_free(*key);
        X509_REQ_free(*req);
        RSA_free(rsa);
        BN_free(e);
        return 0;
    }

    X509_REQ_set_pubkey(*req, *key);

    /* Set the DN of the request. */
    X509_NAME *name = X509_REQ_get_subject_name(*req);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char *>(REQ_DN_C.c_str()), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char *>(REQ_DN_ST.c_str()), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char *>(REQ_DN_L.c_str()), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char *>(REQ_DN_O.c_str()), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char *>(REQ_DN_OU.c_str()), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char *>(REQ_DN_CN.c_str()), -1, -1, 0);

    /* Add alternative name
     * DON'T need. We add extensions, while sign certificate
    STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
    add_ext(exts, NID_subject_alt_name, ("DNS: " + REQ_DN_CN).c_str());

    X509_REQ_add_extensions(*req, exts);
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);*/

    /* Self-sign the request to prove that we posses the key. */
    if (!X509_REQ_sign(*req, *key, EVP_sha256()))
    {
        EVP_PKEY_free(*key);
        X509_REQ_free(*req);
        RSA_free(rsa);
        BN_free(e);
        return 0;
    }

    BN_free(e);

    return 1;
}

int generate_set_random_serial(X509 *crt)
{
    /* Generates a 20 byte random serial number and sets in certificate. */
    unsigned char serial_bytes[20];
    if (RAND_bytes(serial_bytes, sizeof(serial_bytes)) != 1) return 0;
    serial_bytes[0] &= 0x7f; /* Ensure positive serial! */
    BIGNUM *bn = BN_new();
    BN_bin2bn(serial_bytes, sizeof(serial_bytes), bn);
    ASN1_INTEGER *serial = ASN1_INTEGER_new();
    BN_to_ASN1_INTEGER(bn, serial);

    X509_set_serialNumber(crt, serial); // Set serial.

    ASN1_INTEGER_free(serial);
    BN_free(bn);
    return 1;
}

int add_ext(X509 *cert, int nid, const char *value)
{
    X509_EXTENSION *ex;
    X509V3_CTX ctx;
    /* This sets the 'context' of the extensions. */
    /* No configuration database */
    X509V3_set_ctx_nodb(&ctx);
    /* Issuer and subject certs: both the target since it is self signed,
     * no request and no CRL
     */
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ex)
        return 0;

    X509_add_ext(cert,ex,-1);
    X509_EXTENSION_free(ex);
    return 1;
}

int generate_signed_key_pair(EVP_PKEY *ca_key, X509 *ca_crt, EVP_PKEY **key, X509 **crt, std::string & REQ_DN_CN)
{
    /* Generate the private key and corresponding CSR. */
    X509_REQ *req = NULL;
    if (!generate_key_csr(key, &req, REQ_DN_CN)) {
        fprintf(stderr, "Failed to generate key and/or CSR!");
        return 0;
    }

    /* Sign with the CA. */
    *crt = X509_new();
    if (!*crt)
    {
        EVP_PKEY_free(*key);
        X509_REQ_free(req);
        X509_free(*crt);
        return 0;
    }
    X509_set_version(*crt, 2); /* Set version to X509v3 */

    /* Generate random 20 byte serial. */
    if (!generate_set_random_serial(*crt))
    {
        EVP_PKEY_free(*key);
        X509_REQ_free(req);
        X509_free(*crt);
        return 0;
    }

    /* Set issuer to CA's subject. */
    X509_set_issuer_name(*crt, X509_get_subject_name(ca_crt));

    /* Add alternative name extensions */
    add_ext(*crt, NID_subject_alt_name, ("DNS: " + REQ_DN_CN + ",DNS: *." + REQ_DN_CN).c_str());

    /* Set validity of certificate to 2 years. */
    X509_gmtime_adj(X509_get_notBefore(*crt), 0);
    X509_gmtime_adj(X509_get_notAfter(*crt), (long)2*365*24*3600);

    /* Get the request's subject and just use it (we don't bother checking it since we generated
     * it ourself). Also take the request's public key. */
    X509_set_subject_name(*crt, X509_REQ_get_subject_name(req));
    EVP_PKEY *req_pubkey = X509_REQ_get_pubkey(req);
    X509_set_pubkey(*crt, req_pubkey);
    EVP_PKEY_free(req_pubkey);

    /* Now perform the actual signing with the CA. */
    if (X509_sign(*crt, ca_key, EVP_sha256()) == 0)
    {
        EVP_PKEY_free(*key);
        X509_REQ_free(req);
        X509_free(*crt);
        return 0;
    }

    X509_REQ_free(req);
    return 1;
}

void crt_to_pem(X509 *crt, uint8_t **crt_bytes, size_t *crt_size)
{
    /* Convert signed certificate to PEM format. */
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, crt);
    *crt_size = BIO_pending(bio);
    *crt_bytes = (uint8_t *)malloc(*crt_size + 1);
    BIO_read(bio, *crt_bytes, *crt_size);
    BIO_free_all(bio);
}

void key_to_pem(EVP_PKEY *key, uint8_t **key_bytes, size_t *key_size)
{
    /* Convert private key to PEM format. */
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL);
    *key_size = BIO_pending(bio);
    *key_bytes = (uint8_t *)malloc(*key_size + 1);
    BIO_read(bio, *key_bytes, *key_size);
    BIO_free_all(bio);
}

int read_certs_from_file()
{
    std::string log_tag = "CPP/read_certs_from_file";
    read_file(settings.app_files_dir + "/rootCA.key", root_key);
    read_file(settings.app_files_dir + "/rootCA.crt", root_crt);
    if(root_key.empty() || root_crt.empty())
    {
        log_error(log_tag.c_str(), "Failed to read certificates from files");
        return -1;
    }

    return 0;
}

int generate_ssl_cert(std::string sni, struct GeneratedCA & generatedCa)
{
    std::string log_tag = "CPP/generate_ssl_cert";

    // First of all, try to find certificate in cache
    auto it = certCache.find(sni);
    if (it != certCache.end())
    {
        generatedCa = it->second;
        return 0;
    }

    // Load root CA key and cert.
    EVP_PKEY *ca_key = NULL;
    X509 *ca_crt = NULL;
    // Load certs from file
    if (root_crt.empty() || root_key.empty())
        if (read_certs_from_file() != 0)
            return -1;
    // Move them to openssl
    if (!load_ca(&ca_key, &ca_crt)) {
        log_error(log_tag.c_str(), "Failed to load CA certificate and/or key!");
        return -1;
    }

    // Generate keypair
    EVP_PKEY *key = NULL;
    X509 *crt = NULL;

    int ret = generate_signed_key_pair(ca_key, ca_crt, &key, &crt, sni);
    if (!ret) {
        EVP_PKEY_free(ca_key);
        X509_free(ca_crt);
        log_error(log_tag.c_str(), "Failed to generate key pair!");
        return -1;
    }

    // Convert key and certificate to PEM format.
    uint8_t *key_bytes = NULL;
    uint8_t *crt_bytes = NULL;
    size_t key_size = 0;
    size_t crt_size = 0;

    key_to_pem(key, &key_bytes, &key_size);
    crt_to_pem(crt, &crt_bytes, &crt_size);

    // Save certificates
    GeneratedCA cert{std::string(reinterpret_cast<char const*>(crt_bytes), crt_size),
                std::string(reinterpret_cast<char const*>(key_bytes), key_size)};
    generatedCa = cert;

    // Store cert in cache
    certCache[sni] = cert;

    // Free stuff.
    EVP_PKEY_free(ca_key);
    EVP_PKEY_free(key);
    X509_free(ca_crt);
    X509_free(crt);
    free(key_bytes);
    free(crt_bytes);

    return 0;
}