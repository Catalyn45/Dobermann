#ifndef _LOGGING_H_
#define _LOGGING_H_

#include <memory>
#include <string>

enum class Level : int {
    DEBUG,
    INFO,
    WARNING,
    ERROR
};

class Logger {
private:
    static std::unique_ptr<Logger> logger;
    static Level log_level;

    Logger();

protected:
    virtual void log(Level level, const char* message);

public:
    static Logger* get_logger();
    static void config(Level level);

    void debug(const char* fmt, ...);
    void info(const char* fmt, ...);
    void warning(const char* fmt, ...);
    void error(const char* fmt, ...);
};

#endif  // _LOGGING_H_