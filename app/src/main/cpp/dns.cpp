#include "dpi-bypass.h"
#include "dns.h"
#include "hostlist.h"

extern struct Settings settings;
extern JavaVM* javaVm;
extern jclass utils_class;
extern jclass localdnsserver_class;

int resolve_host_over_doh(std::string host, std::string & ip)
{
    std::string log_tag = "CPP/resolve_host_over_doh";

    // Make request to DoH with Java code

    // Get JNIEnv
    JNIEnv* jni_env;
    javaVm->GetEnv((void**) &jni_env, JNI_VERSION_1_6);

    // Attach JNIEnv
    javaVm->AttachCurrentThread(&jni_env, NULL);

    // Find Java method
    jmethodID utils_make_doh_request = jni_env->GetStaticMethodID(utils_class, "makeDOHRequest", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
    if(utils_make_doh_request == NULL)
    {
        log_error(log_tag.c_str(), "Failed to find makeDOHRequest method");
        return -1;
    }

    // Since we have some doh servers, we need to use they by turns
    std::string response_string;

    char delimiter = '\n';
    std::string doh_server;
    std::istringstream stream(settings.dns.dns_doh_servers);
    bool isOK = false;
    while (std::getline(stream, doh_server, delimiter))
    {
        // Call method
        jstring response_string_object = (jstring) jni_env->CallStaticObjectMethod(utils_class, utils_make_doh_request, jni_env->NewStringUTF(doh_server.c_str()), jni_env->NewStringUTF(host.c_str()));
        response_string = jni_env->GetStringUTFChars(response_string_object, 0);
        if(response_string.empty())
        {
            log_error(log_tag.c_str(), "Failed to make request to DoH server. Trying again...");
        } else {
            isOK = true;
            break;
        }
    }

    // Detach thread
    javaVm->DetachCurrentThread();

    if(!isOK)
    {
        log_error(log_tag.c_str(), "No request to the DoH servers was successful. Can't process client");
        return -1;
    }

    ip = response_string;

    return 0;
}

int resolve_host_over_dns(std::string host, std::string & ip)
{
    std::string log_tag = "CPP/resolve_host_over_dns";

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if(getaddrinfo(host.c_str(), NULL, &hints, &res) != 0)
    {
        log_error(log_tag.c_str(), "Failed to get host address. Errno: %s", strerror(errno));
        return -1;
    }

    while(res)
    {
        char addrstr[100];
        inet_ntop(res->ai_family, res->ai_addr->sa_data, addrstr, sizeof(addrstr));
        if(res->ai_family == AF_INET) // If current address is ipv4 address
        {
            void *ptr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
            inet_ntop(res->ai_family, ptr, &ip[0], ip.size());

            size_t first_zero_char = ip.find(' ');
            ip = ip.substr(0, first_zero_char);
            return 0;
        }
        res = res->ai_next;
    }

    return -1;
}

int resolve_host(std::string host, std::string & ip)
{
    // Check if host is IP
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, host.c_str(), &sa.sin_addr);
    if(result != 0)
    {
        ip = host;
        return 0;
    }

    if(settings.dns.is_use_doh && (settings.hostlist.is_use_hostlist ? (settings.dns.is_use_doh_only_for_site_in_hostlist ? find_in_hostlist(host) : true) : true))
    {
        return resolve_host_over_doh(host, ip);
    }
    else
    {
        return resolve_host_over_dns(host, ip);
    }
}

int reverse_resolve_host(std::string & host)
{
    std::string log_tag = "CPP/reverse_resolve_host";

    // Check if host is IP
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, host.c_str(), &sa.sin_addr);
    if(settings.other.is_use_vpn && result != 0)
    {
        // Get JNIEnv
        JNIEnv* jni_env;
        javaVm->GetEnv((void**) &jni_env, JNI_VERSION_1_6);

        // Attach JNIEnv
        javaVm->AttachCurrentThread(&jni_env, NULL);

        // Find Java method
        jmethodID localdnsserver_get_hostname = jni_env->GetStaticMethodID(localdnsserver_class, "getHostname", "(Ljava/lang/String;)Ljava/lang/String;");
        if(localdnsserver_get_hostname == NULL)
        {
            log_error(log_tag.c_str(), "Failed to find getHostname method");
            return -1;
        }

        // Call Java method
        jstring response_string_object = (jstring) jni_env->CallStaticObjectMethod(localdnsserver_class, localdnsserver_get_hostname, jni_env->NewStringUTF(host.c_str()));
        host = jni_env->GetStringUTFChars(response_string_object, 0);
        if(host.empty())
        {
            log_error(log_tag.c_str(), "Failed to find hostname to ip");
            return -1;
        }

        // Detach thread
        javaVm->DetachCurrentThread();

        return 0;
    }
    else
        return 0;
}