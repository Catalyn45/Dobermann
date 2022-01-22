#include "logging.h"

#include <stdarg.h>

#include <iostream>

Logger::Logger() {}

std::unique_ptr<Logger> Logger::logger = nullptr;

Level Logger::log_level = Level::ERROR;

const char* levels[] = {
    "DEBUG",
    "INFO",
    "WARNING",
    "ERROR"

};

void Logger::log(Level level, const char* message) {
    std::cout << levels[(int)level] << " : " << message << std::endl;
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