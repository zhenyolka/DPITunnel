#include "dpi-bypass.h"
#include "hostlist.h"
#include "fileIO.h"
#include "dns.h"

extern struct Settings settings;

std::vector<std::string> hostlist_vector;

bool find_in_hostlist(std::string host) // string_host used to store domain of remote server, because host can contain IP in VPN mode
{
    std::string log_tag = "CPP/find_in_hostlist";

    for(const std::string& host_in_vector : hostlist_vector)
        if(host_in_vector == host)
        {
            log_debug(log_tag.c_str(), "Found host in hostlist. %s, %s", host_in_vector.c_str(), host.c_str());
            return 1;
        }

    return 0;
}

int parse_hostlist()
{
    std::string log_tag = "CPP/parse_hostlist";

    std::string hostlist_string;
    read_file(settings.hostlist.hostlist_path, hostlist_string);
    if (hostlist_string.empty())
    {
        log_error(log_tag.c_str(), "Failed to read hostlist file");
        return -1;
    }

    // Parse hostlist file
    if(settings.hostlist.hostlist_format == "json")
    {
        // Parse with rapidjson
        rapidjson::Document hostlist_document;

        if(hostlist_document.Parse(hostlist_string.c_str()).HasParseError())
        {
            log_error(log_tag.c_str(), "Failed to parse hostlist file");
            return -1;
        }

        // Convert rapidjson::Document to vector<string>
        hostlist_vector.reserve(hostlist_document.GetArray().Size());
        for(const auto & host_in_list : hostlist_document.GetArray())
            hostlist_vector.push_back(host_in_list.GetString());
    }
    else if(settings.hostlist.hostlist_format == "txt")
    {
        // Parse as text
        char delimiter = '\n';
        std::string host;
        std::istringstream stream(hostlist_string);
        while (std::getline(stream, host, delimiter))
            hostlist_vector.push_back(host);
    }

    return 0;
}