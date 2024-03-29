#ifndef LOCAL_REPOSITORY_H_
#define LOCAL_REPOSITORY_H_

#include "repository.h"

class LocalRepository : public Repository {
private:
    std::string path;
public:
    LocalRepository(std::string path);
    ~LocalRepository();
    json get_http_scripts();
    std::vector<std::string> get_tcp_patterns();
    std::vector<std::string> get_udp_patterns();
};

#endif // LOCAL_REPOSITORY_H_