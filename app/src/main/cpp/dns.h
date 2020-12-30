#ifndef DPITUNNEL_DNS_H
#define DPITUNNEL_DNS_H

int resolve_host(const std::string& host, std::string & ip);
int reverse_resolve_host(std::string & host);

#endif //DPITUNNEL_DNS_H
