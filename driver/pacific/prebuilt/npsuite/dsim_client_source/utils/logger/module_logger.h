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

#ifndef _MODULE_LOGGER_H_
#define _MODULE_LOGGER_H_

#include "modules.h"
#include <string>
#include "logger_base.h"
#include "log_file_writer.h"

namespace npsuite
{

class ModuleLogger
{
public:
    ModuleLogger(eModules module, npsuite::npsuite_log_level_e fileLogLevel, npsuite::npsuite_log_level_e stdOutLogLevel);
    ~ModuleLogger();

    void SetFileLogLevel(npsuite::npsuite_log_level_e newLogLevel);
    void SetStdOutLogLevel(npsuite::npsuite_log_level_e newLogLevel);
    bool IsLogLevelEnabled(npsuite::npsuite_log_level_e level) const;
    void SetLogFileWriter(LogFileWriter* logFileWriter);

    bool Log(npsuite::npsuite_log_level_e level,
             const bool logPrefixEnabled,
             const std::string& threadNamePrefix,
             const std::string& msgPrefix,
             const std::string& file,
             unsigned long int line,
             const std::string& msg);

private:
    eModules mModule;
    std::string mModuleName;
    npsuite::npsuite_log_level_e mFileLogLevel;
    npsuite::npsuite_log_level_e mStdOutLogLevel;
    LogFileWriter* mLogFileWriter;
};
}

#endif //_MODULE_LOGGER_H_
