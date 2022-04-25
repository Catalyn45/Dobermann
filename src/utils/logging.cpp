#include "logging.h"
#include <iostream>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <stdarg.h>

Logger::Logger() {}
Logger::~Logger() {}

std::unique_ptr<Logger> Logger::logger(nullptr);

Level Logger::log_level = Level::ERROR;
bool Logger::colors = true;

static const char* levels[] = {
    "[DEBUG]",
    "[INFO] ",
    "[WARN] ",
    "[ERROR]",
    "[DETEC]"
};

void Logger::log(Level level, const char* message) {
    static char buffer[26];
    char color[8] = "\033[0;37m";

    if (colors) {
        if (level == Level::ERROR) {
            strcpy(color, "\033[0;31m");
        } else if (level == Level::WARNING) {
            strcpy(color, "\033[0;33m");
        } else if (level == Level::DEBUG) {
            strcpy(color, "\033[0;36m");
        } else if (level == Level::DETECTION) {
            strcpy(color, "\033[0;35m");
        }
    }

    struct timeval now;
    gettimeofday(&now, NULL);
    struct tm* tm = localtime(&now.tv_sec);
    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm);

    printf("%s[%s:%06ld] %s %s\n", color, buffer, now.tv_usec, levels[(int)level], message);
}

Logger* Logger::get_logger() {
    if (!Logger::logger.get()) {
        Logger::logger = std::unique_ptr<Logger>(new Logger());
    }

    return Logger::logger.get();
}

void Logger::config(Level level, bool colors) {
    Logger::log_level = level;
    Logger::colors = colors;
}

Level Logger::level_name(const std::string level) {
    if (level == "DEBUG") {
        return Level::DEBUG;
    } else if (level == "INFO") {
        return Level::INFO;
    } else if (level == "WARNING") {
        return Level::WARNING;
    } else if (level == "DETECTION") {
        return Level::DETECTION;
    }

    return Level::ERROR;
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

void Logger::detection(const char* fmt, ...) {
    LOG_MESSAGE(Level::DETECTION);
}