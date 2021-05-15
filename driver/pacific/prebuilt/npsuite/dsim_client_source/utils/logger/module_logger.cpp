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

#include <iostream>

#include "module_logger.h"

using namespace npsuite;
using namespace std;

ModuleLogger::ModuleLogger(eModules module, npsuite::npsuite_log_level_e fileLogLevel, npsuite::npsuite_log_level_e stdOutLogLevel)
{
    mModule = module;
    mLogFileWriter = NULL;
    mFileLogLevel = fileLogLevel;
    mStdOutLogLevel = stdOutLogLevel;
    mModuleName = string(getModuleName(mModule));
}

ModuleLogger::~ModuleLogger()
{
}

void
ModuleLogger::SetFileLogLevel(npsuite::npsuite_log_level_e newLogLevel)
{
    mFileLogLevel = newLogLevel;
}

void
ModuleLogger::SetStdOutLogLevel(npsuite::npsuite_log_level_e newLogLevel)
{
    mStdOutLogLevel = newLogLevel;
}

bool
ModuleLogger::IsLogLevelEnabled(npsuite::npsuite_log_level_e level) const
{
    return ((mLogFileWriter != nullptr && level >= mFileLogLevel) || (level >= mStdOutLogLevel));
}

void
ModuleLogger::SetLogFileWriter(LogFileWriter* logFileWriter)
{
    mLogFileWriter = logFileWriter;
}

bool
ModuleLogger::Log(npsuite::npsuite_log_level_e level,
                  const bool logPrefixEnabled,
                  const string& threadNamePrefix,
                  const std::string& msgPrefix,
                  const std::string& file,
                  unsigned long int line,
                  const std::string& msg)
{
    bool sentLogOut = false;
    std::string moduleName = mModuleName;
    std::string msg_out = msg;

    if (mModule == USER) {
        size_t pos = msg_out.find("@");
        assert(pos != std::string::npos && "Illegal user message format, expected '@' delimiter!");
        if (pos > 0) {
            moduleName = msg_out.substr(0, pos);
        }
        msg_out = msg_out.substr(pos + 1, std::string::npos);
    }

    if (level >= mFileLogLevel && mLogFileWriter != nullptr) {
        mLogFileWriter->Write(
            moduleName, level, threadNamePrefix, msgPrefix, file, line, msg_out, (mFileLogLevel < NPSUITE_LOG_LEVEL_INFO));
        sentLogOut = true;
    }

    if (level >= mStdOutLogLevel) {
        if (logPrefixEnabled) {
            cout << get_current_timestamp() << moduleName << " - [" << GetLogLevelName(level) << "] " << msg_out << endl;
        } else {
            cout << moduleName << " - [" << GetLogLevelName(level) << "] " << msg_out << endl;
        }
        sentLogOut = true;
    }

    return sentLogOut;
}
