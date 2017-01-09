/*
 log.h
 como
 
 BSD 2-Clause License
 
 Copyright (c) 2017, Zhou Chong <zhouchonghz AT gmail.com>
 All rights reserved.
 
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:
 
 * Redistributions of source code must retain the above copyright notice, this
 list of conditions and the following disclaimer.
 
 * Redistributions in binary form must reproduce the above copyright notice,
 this list of conditions and the following disclaimer in the documentation
 and/or other materials provided with the distribution.
 
 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef log_h
#define log_h

#include <stdio.h>
#include <stdarg.h>

#define LOG_LEV_DEBUG   1
#define LOG_LEV_INFO    2
#define LOG_LEV_WARN    3
#define LOG_LEV_ERROR   4
#define LOG_LEV_FATAL   5


static inline void log_vformat(int level, const char *fmt, va_list args)
{
    vprintf(fmt,args);
}

static inline void log_debug(const char *fmt, ...)
{
    va_list ap;
    va_start(ap,fmt);
    log_vformat(LOG_LEV_DEBUG, fmt, ap);
    va_end(ap);
}

static inline void log_info(const char *fmt, ...)
{
    va_list ap;
    va_start(ap,fmt);
    log_vformat(LOG_LEV_INFO, fmt, ap);
    va_end(ap);
}

static inline void log_warn(const char *fmt, ...)
{
    va_list ap;
    va_start(ap,fmt);
    log_vformat(LOG_LEV_WARN, fmt, ap);
    va_end(ap);
}

static inline void log_error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap,fmt);
    log_vformat(LOG_LEV_ERROR, fmt, ap);
    va_end(ap);
}

static inline void log_fatal(const char *fmt, ...)
{
    va_list ap;
    va_start(ap,fmt);
    log_vformat(LOG_LEV_FATAL, fmt, ap);
    va_end(ap);
}

#endif /* log_h */
