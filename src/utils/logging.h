#ifndef _LOGGING_H_
#define _LOGGING_H_

#include <memory>
#include <string>

enum class Level : int {
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    DETECTION
};

class Logger {
private:
    static std::unique_ptr<Logger> logger;
    static Level log_level;
    static bool colors;

    Logger();

protected:
    virtual void log(Level level, const char* message);

public:
    static Logger* get_logger();
    static void config(Level level, bool colors=true);
    static Level level_name(const std::string level);

    void debug(const char* fmt, ...);
    void info(const char* fmt, ...);
    void warning(const char* fmt, ...);
    void error(const char* fmt, ...);
    void detection(const char* fmt, ...);

    virtual ~Logger();
};

#endif  // _LOGGING_H_