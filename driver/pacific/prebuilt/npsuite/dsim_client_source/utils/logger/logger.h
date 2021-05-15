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

#ifndef _LOGGER_H_
#define _LOGGER_H_

#include <string>
#include <mutex>
#include <thread>
#include <deque>
#include <set>
#include <map>
#include <condition_variable>
#include "logger_base.h"
#include "modules.h"
#include "utils/npsuite_logger.h"
#include "log_file_writer.h"

#define DEFAULT_LOG_LEVEL_TO_FILE NPSUITE_LOG_LEVEL_TRACE
#define DEFAULT_LOG_LEVEL_TO_STDOUT NPSUITE_LOG_LEVEL_INFO

#define LOG_DIFF_IGNORE_STR "$DIFF_IGNORE$"

namespace npsuite
{

class ModuleLogger; // defined elsewhere

class Logger
{
public:
    ~Logger();

    Logger(std::string outputFolderPath,
           bool logPrefixEnabled,
           std::string logFileName,
           bool isSynchronous,
           size_t maxLogSize,
           size_t maxLogFiles,
           bool compress);
    Logger(std::string outputFolderPath,
           bool logPrefixEnabled,
           std::string logFileName,
           size_t maxLogSize,
           size_t maxLogFiles,
           bool compress);
    Logger(std::string outputFolderPath, bool logPrefixEnabled, std::string logFileName, bool isSynchronous, bool compress);
    Logger(std::string outputFolderPath, bool logPrefixEnabled, std::string logFileName, bool compress);

    static void setThreadPrefix(const std::string& tname);
    static const std::string& getThreadPrefix();
    static void InitDefaultLogger(std::string outputFolderPath, bool logPrefixEnabled, std::string logFileName);
    void SetLogFilePath(std::string outputFolderPath,
                        bool logPrefixEnabled,
                        std::string logFileName,
                        size_t maxLogSize,
                        size_t maxLogFiles,
                        bool compress);
    void SetModuleFileLogLevel(eModules module, enum npsuite::npsuite_log_level_e_ newLevel);
    void SetFileLogLevelForAll(enum npsuite::npsuite_log_level_e_ newLevel);
    void SetModuleStdOutLogLevel(eModules module, enum npsuite::npsuite_log_level_e_ newLevel);
    void SetStdOutLogLevelForAll(enum npsuite::npsuite_log_level_e_ newLevel);
    void SetIsSynchronousLogger(bool isSynchronous);
    void SetMsgPrefix(const std::string& msgPrefix);
    bool IsLogLevelEnabled(eModules module, enum npsuite::npsuite_log_level_e_ level) const;
    void Flush();
    void StopLoggingThread();
    void Log(eModules module,
             enum npsuite::npsuite_log_level_e_ level,
             const char* file,
             unsigned long int line,
             const std::string& msg);
    void Log(eModules module,
             enum npsuite::npsuite_log_level_e_ level,
             const std::string& file,
             unsigned long int line,
             const std::string& msg);
    void Log(eModules module,
             enum npsuite::npsuite_log_level_e_ level,
             const char* file,
             unsigned long int line,
             const std::string& msg,
             const nplLogInfo& nplInfo);
    unsigned long GetNumLogMessages(enum npsuite::npsuite_log_level_e_ level) const;
    static bool IsDefaultLoggerInitialized();
    static Logger* GetDefaultLogger();
    static void RedirectDefaultLogger(Logger* logger);
    static void RestoreDefualtLogger();
    static void FlushAndStopLoggingThreads();
    std::vector<std::string> GetErrorsVector();
    LogFileWriter* GetLogFileWriter();

    //
    // Register a callback to be invoked when the logger logs a message.
    //
    npsuite::register_log_message_client_handle_t register_log_message_callback(
        npsuite::npsuite_log_level_e level,
        npsuite::npsuite_logger_message_callback_t callback);

    //
    // Deregister a previous callback to be invoked when the logger logs a message.
    //
    void unregister_log_message_callback(const npsuite::register_log_message_client_handle_t& client_handle);

private:
    static std::set<Logger*>& GetActiveLoggers();
    void RegisterHandlers();
    void LogMessages();

private:
    struct LogInfo {
        LogInfo() = default;
        LogInfo(eModules module,
                enum npsuite::npsuite_log_level_e_ level,
                const std::string& threadNamePrefix,
                const std::string& file,
                unsigned long int line,
                const std::string& msg)
            : mModule(module), mLogLevel(level), mFileName(file), mLine(line), mThreadNamePrefix(threadNamePrefix), mMsg(msg)
        {
        }

        eModules mModule;
        enum npsuite::npsuite_log_level_e_ mLogLevel;
        std::string mFileName;
        unsigned long int mLine;
        std::string mThreadNamePrefix;
        std::string mMsg;
    };

    struct MessageBuffer {
        MessageBuffer() : mWriteInProgress(false)
        {
        }
        void wake();
        void flush();
        void notifyMessageWritten();
        void insert(eModules module,
                    enum npsuite::npsuite_log_level_e_ level,
                    const std::string& file,
                    unsigned long int line,
                    const std::string msg);
        void get(LogInfo& outLog);
        bool empty();
        size_t size();

        std::deque<LogInfo> mBuffer;
        std::mutex mBufferMutex;
        std::mutex mFlushMutex;
        std::condition_variable mBufferNotEmptyCond;
        std::condition_variable mBufferFlushedCond;
        bool mWriteInProgress;
    };

private:
    static Logger* mDefaultLogger;
    static Logger* mAlternateDefaultLogger;
    static std::mutex sActiveLoggersMutex;
    std::vector<std::string> mErrorsLoggingVector;
    void InsertErrorToVector(enum npsuite::npsuite_log_level_e_ level, const std::string& msg);
    std::mutex mErrorsVectorMutex;

    ModuleLogger* mModuleLoggers[NUM_MODULES];
    LogFileWriter* mLogFileWriter;
    unsigned long mNumLogsPerLevel[npsuite::NPSUITE_LOG_LEVEL_NUM_LEVELS];

    bool mLoggingThreadIsActive;
    bool mIsSynchronous;
    bool mLogPrefixEnabled{};
    std::thread* mLoggingThread;
    MessageBuffer mLoggingBuffer;
    std::string mMsgPrefix;

    using logger_api_lock = std::lock_guard<std::recursive_mutex>;
    std::recursive_mutex m_lock;

    //
    // This is a map of all currently registered listeners for NSIM logs.
    //
    std::map<register_log_message_client_handle_t,
             std::pair<npsuite::npsuite_log_level_e, npsuite::npsuite_logger_message_callback_t>>
        m_client_log_handlers;
    register_log_message_client_handle_t register_log_message_client_handle{};
};

#define T_LOGGING_ENABLED(logger, module) ((((logger) != nullptr)) && (logger)->IsLogLevelEnabled(module, NPSUITE_LOG_LEVEL_TRACE))
#define D_LOGGING_ENABLED(logger, module) ((((logger) != nullptr)) && (logger)->IsLogLevelEnabled(module, NPSUITE_LOG_LEVEL_DEBUG))
#define I_LOGGING_ENABLED(logger, module) ((((logger) != nullptr)) && (logger)->IsLogLevelEnabled(module, NPSUITE_LOG_LEVEL_INFO))
#define P_LOGGING_ENABLED(logger, module)                                                                                          \
    ((((logger) != nullptr)) && (logger)->IsLogLevelEnabled(module, NPSUITE_LOG_LEVEL_PROGRESS))
#define W_LOGGING_ENABLED(logger, module)                                                                                          \
    ((((logger) != nullptr)) && (logger)->IsLogLevelEnabled(module, NPSUITE_LOG_LEVEL_WARNING))
#define ES_LOGGING_ENABLED(logger, module)                                                                                         \
    ((((logger) != nullptr)) && (logger)->IsLogLevelEnabled(module, NPSUITE_LOG_LEVEL_ESSENTIAL))
#define E_LOGGING_ENABLED(logger, module) ((((logger) != nullptr)) && (logger)->IsLogLevelEnabled(module, NPSUITE_LOG_LEVEL_ERROR))
#define F_LOGGING_ENABLED(logger, module) ((((logger) != nullptr)) && (logger)->IsLogLevelEnabled(module, NPSUITE_LOG_LEVEL_FATAL))

#define TLOG_INSTANCE(logger, module, msg, ...)                                                                                    \
    if ((((logger) != nullptr)) && (logger)->IsLogLevelEnabled(module, NPSUITE_LOG_LEVEL_TRACE)) {                                 \
        (logger)->Log(module, NPSUITE_LOG_LEVEL_TRACE, __FILE__, __LINE__, msg, ##__VA_ARGS__);                                    \
    }
#define DLOG_INSTANCE(logger, module, msg, ...)                                                                                    \
    if (((logger) != nullptr) && (logger)->IsLogLevelEnabled(module, NPSUITE_LOG_LEVEL_DEBUG)) {                                   \
        (logger)->Log(module, NPSUITE_LOG_LEVEL_DEBUG, __FILE__, __LINE__, msg, ##__VA_ARGS__);                                    \
    }
#define ILOG_INSTANCE(logger, module, msg, ...)                                                                                    \
    if (((logger) != nullptr) && (logger)->IsLogLevelEnabled(module, NPSUITE_LOG_LEVEL_INFO)) {                                    \
        (logger)->Log(module, NPSUITE_LOG_LEVEL_INFO, __FILE__, __LINE__, msg, ##__VA_ARGS__);                                     \
    }
#define PLOG_INSTANCE(logger, module, msg, ...)                                                                                    \
    if (((logger) != nullptr) && (logger)->IsLogLevelEnabled(module, NPSUITE_LOG_LEVEL_PROGRESS)) {                                \
        (logger)->Log(module, NPSUITE_LOG_LEVEL_PROGRESS, __FILE__, __LINE__, msg, ##__VA_ARGS__);                                 \
    }
#define WLOG_INSTANCE(logger, module, msg, ...)                                                                                    \
    if (((logger) != nullptr) && (logger)->IsLogLevelEnabled(module, NPSUITE_LOG_LEVEL_WARNING)) {                                 \
        (logger)->Log(module, NPSUITE_LOG_LEVEL_WARNING, __FILE__, __LINE__, msg, ##__VA_ARGS__);                                  \
    }

#define ESLOG_INSTANCE(logger, module, msg, ...)                                                                                   \
    if (((logger) != nullptr) && (logger)->IsLogLevelEnabled(module, NPSUITE_LOG_LEVEL_ESSENTIAL)) {                               \
        (logger)->Log(module, NPSUITE_LOG_LEVEL_ESSENTIAL, __FILE__, __LINE__, msg, ##__VA_ARGS__);                                \
    }
#define ELOG_INSTANCE(logger, module, msg, ...)                                                                                    \
    if (((logger) != nullptr) && (logger)->IsLogLevelEnabled(module, NPSUITE_LOG_LEVEL_ERROR)) {                                   \
        (logger)->Log(module, NPSUITE_LOG_LEVEL_ERROR, __FILE__, __LINE__, msg, ##__VA_ARGS__);                                    \
    }
#define FLOG_INSTANCE(logger, module, msg, ...)                                                                                    \
    if (((logger) != nullptr) && (logger)->IsLogLevelEnabled(module, NPSUITE_LOG_LEVEL_FATAL)) {                                   \
        (logger)->Log(module, NPSUITE_LOG_LEVEL_FATAL, __FILE__, __LINE__, msg, ##__VA_ARGS__);                                    \
    }

#define ELOG_OR_THROW(failOnError, logger, module, msg, ...)                                                                       \
    do {                                                                                                                           \
        ELOG_INSTANCE(logger, module, msg, ##__VA_ARGS__);                                                                         \
        if (failOnError) {                                                                                                         \
            throw std::runtime_error(msg);                                                                                         \
        }                                                                                                                          \
    } while (false)

#define FLOG_OR_THROW(failOnError, logger, module, msg, ...)                                                                       \
    do {                                                                                                                           \
        FLOG_INSTANCE(logger, module, msg, ##__VA_ARGS__);                                                                         \
        if (failOnError) {                                                                                                         \
            throw std::runtime_error(msg);                                                                                         \
        }                                                                                                                          \
    } while (false)

#define TLOG(module, msg, ...) TLOG_INSTANCE(Logger::GetDefaultLogger(), module, msg, ##__VA_ARGS__)
#define DLOG(module, msg, ...) DLOG_INSTANCE(Logger::GetDefaultLogger(), module, msg, ##__VA_ARGS__)
#define ILOG(module, msg, ...) ILOG_INSTANCE(Logger::GetDefaultLogger(), module, msg, ##__VA_ARGS__)
#define PLOG(module, msg, ...) PLOG_INSTANCE(Logger::GetDefaultLogger(), module, msg, ##__VA_ARGS__)
#define WLOG(module, msg, ...) WLOG_INSTANCE(Logger::GetDefaultLogger(), module, msg, ##__VA_ARGS__)
#define ESLOG(module, msg, ...) ESLOG_INSTANCE(Logger::GetDefaultLogger(), module, msg, ##__VA_ARGS__)
#define ELOG(module, msg, ...) ELOG_INSTANCE(Logger::GetDefaultLogger(), module, msg, ##__VA_ARGS__)
#define FLOG(module, msg, ...) FLOG_INSTANCE(Logger::GetDefaultLogger(), module, msg, ##__VA_ARGS__)
}

#endif //_LOGGER_H_
