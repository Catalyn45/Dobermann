#include "logging.h"
#include <iostream>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>

Logger::Logger() {}

std::unique_ptr<Logger> Logger::logger = nullptr;

Level Logger::log_level = Level::ERROR;

static const char* levels[] = {
    "[DEBUG]",
    "[INFO] ",
    "[WARN] ",
    "[ERROR]"
};

void Logger::log(Level level, const char* message) {
    static char buffer[26];
    char color[10] = "\033[0;37m";

    if (level == Level::ERROR) {
        strcpy(color, "\033[0;31m");
    } else if (level == Level::WARNING) {
        strcpy(color, "\033[0;33m");
    } else if (level == Level::DEBUG) {
        strcpy(color, "\033[0;36m");
    }

    struct timeval now;
    gettimeofday(&now, NULL);
    struct tm* tm = localtime(&now.tv_sec);
    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm);

    printf("%s[%s:%ld] %s %s\n", color, buffer, now.tv_usec, levels[(int)level], message);
}

Logger* Logger::get_logger() {
    if (!Logger::logger.get()) {
        Logger::logger.reset(new Logger());
    }

    return Logger::logger.get();
}

void Logger::config(Level level) {
    Logger::log_level = level;
}

#define MAX_MESSAGE_LEN 300

#define LOG_MESSAGE(level)                          \
    if (level < log_level)                          \
        return;                                     \
    char message[MAX_MESSAGE_LEN];                  \
    va_list list;                                   \
    va_start(list, fmt);                            \
    vsnprintf(message, sizeof(message), fmt, list); \
    va_end(list);                                   \
    this->log(level, message)

void Logger::debug(const char* fmt, ...) {
    LOG_MESSAGE(Level::DEBUG);
}

void Logger::info(const char* fmt, ...) {
    LOG_MESSAGE(Level::INFO);
}

void Logger::warning(const char* fmt, ...) {
    LOG_MESSAGE(Level::WARNING);
}

void Logger::error(const char* fmt, ...) {
    LOG_MESSAGE(Level::ERROR);
}