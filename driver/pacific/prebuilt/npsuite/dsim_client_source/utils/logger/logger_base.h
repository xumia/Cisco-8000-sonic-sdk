// BEGIN_LEGAL
//
// Copyright (c) 2015-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
//
// This file and all technical concepts, proprietary knowledge, algorithms and
// intellectual property rights it contains (collectively the "Confidential Information"),
// are the sole propriety information of Cisco and shall remain at Cisco's ownership.
// You shall not disclose the Confidential Information to any third party and you
// shall use it solely in connection with operating and/or maintaining of Cisco's
// products and pursuant to the terms and conditions of the license agreement you
// entered into with Cisco.
//
// THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
// IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
// AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
// THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// END_LEGAL

#ifndef _LOGGER_BASE_H_
#define _LOGGER_BASE_H_

#include "utils/npsuite_logger.h"

namespace npsuite
{

struct nplLogInfo {
    // Location to relevant file
    std::string nplFileLocation;
    // Line number
    uint16_t nplLineNumber = 0;
    // Column number
    uint16_t nplColumnNumber = 0;

    nplLogInfo(const std::string fileLocation, const uint16_t lineNumber) : nplFileLocation(fileLocation), nplLineNumber(lineNumber)
    {
        ;
    }

    nplLogInfo(const std::string fileLocation, const uint16_t lineNumber, const uint16_t columnNumber)
        : nplLogInfo(fileLocation, lineNumber)
    {
        nplColumnNumber = columnNumber;
    }

    std::string to_string() const
    {
        return nplColumnNumber > 0
                   ? std::string(nplFileLocation + ":" + std::to_string(nplLineNumber) + ":" + std::to_string(nplColumnNumber))
                   : std::string(nplFileLocation + ":" + std::to_string(nplLineNumber));
    }
};

inline const char*
GetLogLevelName(npsuite::npsuite_log_level_e level)
{
    static const char* names[npsuite::NPSUITE_LOG_LEVEL_NUM_LEVELS]
        = {"TRACE", "DEBUG", "INFO", "PROGRESS", "WARNING", "ESSENTIAL", "ERROR", "FATAL"};

    if ((level >= npsuite::NPSUITE_LOG_LEVEL_NUM_LEVELS) || (level < 0)) {
        return "UNKNOWN";
    } else {
        return names[level];
    }
}
}

#endif //_LOGGER_BASE_H_
