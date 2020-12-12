#include "dpi-bypass.h"
#include "fileIO.h"

int read_file(const std::string & path, std::string & destination)
{
    std::string log_tag = "CPP/read_cert_from_file";
    std::ifstream file;
    file.open(path);
    if(!file)
    {
        log_error(log_tag.c_str(), "Failed to open file");
        return -1;
    }

    // Create string object from file
    std::stringstream stream;
    stream << file.rdbuf();
    destination = stream.str();

    return 0;
}