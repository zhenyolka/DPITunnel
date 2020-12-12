#ifndef DPITUNNEL_SNI_CERT_GEN_H
#define DPITUNNEL_SNI_CERT_GEN_H
struct GeneratedCA
{
    std::string       public_key_pem;
    std::string       private_key_pem;
};

int generate_ssl_cert(std::string sni, struct GeneratedCA & generatedCa);

#endif //DPITUNNEL_SNI_CERT_GEN_H
