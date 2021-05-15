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

#ifndef _LOG_FILE_WRITER_H_
#define _LOG_FILE_WRITER_H_

#include "../file_writer.h"
#include "logger_base.h"
#include <cstdarg>
#include <vector>
#include <chrono>

namespace npsuite
{

int string_format_size(const char* const format, ...);
const std::string string_format(const char* const format, ...);

class LogFileWriter : public FileWriter
{
public:
    LogFileWriter(std::string fileName, int flushEveryXLines, bool logPrefixEnabled, bool measureProgress, bool compress);
    LogFileWriter(std::string fileNameBase,
                  int flushEveryXLines,
                  bool logPrefixEnabled,
                  bool measureProgress,
                  size_t maxLogSizeBytes,
                  size_t maxRotationFiles,
                  bool compress);
    ~LogFileWriter();
    void Write(const std::string& moduleName,
               npsuite::npsuite_log_level_e level,
               const std::string& threadNamePrefix,
               const std::string& msgPrefix,
               const std::string& file,
               unsigned long int line,
               const std::string& msg,
               bool writeLineInfo); // write line to the file.
private:
    void about_to_write(size_t bytes_before_newline);

private:
    bool mLogPrefixEnabled;
    bool mMeasureProgress;
    std::chrono::time_point<std::chrono::system_clock> mCreationTime;
    size_t mMaxLogFileSizeBytes = 0;
    size_t mCurrLogFileSizeBytes = 0;
    size_t mMaxLogFiles = 0;
    bool mRotateLogs = false;
    uint64_t mNextLogFile = 0;
    std::string mBaseFileName;
    bool mCompressLogFiles;
};
}

extern size_t sdk_style_timestamp(char* buffer, size_t buffer_size);
extern std::string get_current_timestamp(void);

#endif //_LOG_FILE_WRITER_H_
