/*
* Copyright (c) 2012-2013 Fredrik Mellbin
*
* This file is part of VapourSynth.
*
* VapourSynth is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public
* License as published by the Free Software Foundation; either
* version 2.1 of the License, or (at your option) any later version.
*
* VapourSynth is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with VapourSynth; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
*/

#include "vslog.h"
#include <cassert>
#include <cstdlib>
#include <cstdio>
#include <cstdarg>
#include <mutex>
#include <vector>

static VSMessageHandler messageHandler = nullptr;
static void *messageUserData = nullptr;
static std::mutex logMutex;

void vsSetMessageHandler(VSMessageHandler handler, void *userData) {
    std::lock_guard<std::mutex> lock(logMutex);
    if (handler) {
        messageHandler = handler;
        messageUserData = userData;
    } else {
        messageHandler = nullptr;
        messageUserData = nullptr;
    }
}

void vsLog(const char *file, long line, VSMessageType type, const char *msg, ...) {
    std::lock_guard<std::mutex> lock(logMutex);
    if (messageHandler) {
        va_list alist;
        try {
            va_start(alist, msg);
            int size = vsnprintf(nullptr, 0, msg, alist);
            va_end(alist);
            std::vector<char> buf(size+1);
            va_start(alist, msg);
            vsnprintf(buf.data(), buf.size(), msg, alist);
            va_end(alist);
#ifdef __WINE__
            if (TEST_WINE_FLAG(messageHandler))
                ((VSMessageHandlerWine)CLEAR_WINE_FLAG(messageHandler))(type, buf.data(), messageUserData);
            else
#endif
            messageHandler(type, buf.data(), messageUserData);
        } catch (std::bad_alloc &) {
            fprintf(stderr, "Bad alloc exception in log handler\n");
            va_start(alist, msg);
            vfprintf(stderr, msg, alist);
            va_end(alist);
            fprintf(stderr, "\n");
        }
    } else {
        va_list alist;
        va_start(alist, msg);
        vfprintf(stderr, msg, alist);
        va_end(alist);
        fprintf(stderr, "\n");
    }

    if (type == mtFatal) {
        assert(false);
        abort();
    }
}
