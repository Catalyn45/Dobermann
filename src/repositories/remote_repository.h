#ifndef REMOTE_REPOSITORY_H_
#define REMOTE_REPOSITORY_H_

#include "repository.h"

class RemoteRepository : public Repository {
private:
    std::string url;
    long last_update;
    json scripts_cache;
public:
    RemoteRepository(const std::string& url);
    ~RemoteRepository();
    json get_http_scripts();
};

#endif // REMOTE_REPOSITORY_H_