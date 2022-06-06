#ifndef REMOTE_REPOSITORY_H_
#define REMOTE_REPOSITORY_H_

#include "repository.h"

class RemoteRepository : public Repository {
private:
    std::string url;

    long last_scripts_update;
    long last_tcp_update;
    long last_udp_update;

    json scripts_cache;
    json tcp_patterns_cache;
    json udp_patterns_cache;
public:
    RemoteRepository(const std::string& url);
    ~RemoteRepository();
    json get_http_scripts();
    std::vector<std::string> get_tcp_patterns();
    std::vector<std::string> get_udp_patterns();
};

#endif // REMOTE_REPOSITORY_H_