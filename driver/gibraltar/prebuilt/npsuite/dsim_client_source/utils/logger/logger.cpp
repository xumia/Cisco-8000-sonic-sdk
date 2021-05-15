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

#include "logger.h"
#include "module_logger.h"
#include "modules.h"
#include "utils/signal_handler.h"
#include <assert.h>
#include <iostream>
#include <sys/types.h>
#include <map>

using namespace npsuite;
using namespace std;

#define LOG_FILE_NAME "log.txt"
#define DEFAULT_MAX_LOG_FILES 10

/**************************************************************************************************************************
Note: it is assumed that no one will call the logger functions before init() was called. it is safer to check at each
function if already initialized, but it will create an unnecessary overhead. as we control the initialization and not the
application developer, we can live with this...
***************************************************************************************************************************/

Logger* Logger::mDefaultLogger = nullptr;
Logger* Logger::mAlternateDefaultLogger = nullptr;
std::mutex Logger::sActiveLoggersMutex;
static std::map<int, void (*)(int)> PrevHandlers;

void
LoggerAtexitHandler()
{
    Logger::FlushAndStopLoggingThreads();
}

void
LoggerSignalHandler(int signal)
{
    if (signal != SIGUSR2) {
        Logger::FlushAndStopLoggingThreads();
    }
}

static thread_local std::string threadPrefix = "";

void
Logger::setThreadPrefix(const std::string& tname)
{
    threadPrefix = tname;
    // Ensure our per-thread message prefix is not too large, to avoid overly long log entries
    if (threadPrefix.length() > 32) {
        threadPrefix.resize(32);
    }
    threadPrefix += ": ";
}

const std::string&
Logger::getThreadPrefix()
{
    return threadPrefix;
}

Logger::Logger(std::string outputFolderPath, bool logPrefixEnabled, std::string logFileName, bool isSynchronous, bool compress)
    : Logger(outputFolderPath, logPrefixEnabled, logFileName, isSynchronous, 0, 0, compress)
{
}

Logger::Logger(string outputFolderPath, bool logPrefixEnabled, string logFileName, bool compress)
    : Logger(outputFolderPath, logPrefixEnabled, logFileName, false, 0, 0, compress)
{
}

Logger::Logger(std::string outputFolderPath,
               bool logPrefixEnabled,
               std::string logFileName,
               size_t maxLogSize,
               size_t maxLogFiles,
               bool compress)
    : Logger(outputFolderPath, logPrefixEnabled, logFileName, false, maxLogSize, maxLogFiles, compress)
{
}

Logger::Logger(std::string outputFolderPath,
               bool logPrefixEnabled,
               std::string logFileName,
               bool isSynchronous,
               size_t maxLogSize,
               size_t maxLogFiles,
               bool compress)
    : mLogFileWriter(nullptr), mIsSynchronous(isSynchronous), mLogPrefixEnabled(logPrefixEnabled)
{
    // Get it and throw the value away to force it to be initialized
    (void)getThreadPrefix();

    // create the LogFileWriter that all modules will use to log their messages. (we may consider to use different for different
    // logs in the future)

    // create the moddule loggers
    for (int i = 0; i < NUM_MODULES; i++) {
        mModuleLoggers[i] = new ModuleLogger((eModules)i, DEFAULT_LOG_LEVEL_TO_FILE, DEFAULT_LOG_LEVEL_TO_STDOUT);
    }

    if (outputFolderPath != "") {
        SetLogFilePath(outputFolderPath, logPrefixEnabled, logFileName, maxLogSize, maxLogFiles, compress);
    }

    for (size_t i = 0; i < npsuite::NPSUITE_LOG_LEVEL_NUM_LEVELS; i++) {
        mNumLogsPerLevel[i] = 0;
    }

    mLoggingThreadIsActive = true;
    mLoggingThread = new std::thread(&Logger::LogMessages, this);

    std::lock_guard<std::mutex> lock(sActiveLoggersMutex);
    GetActiveLoggers().insert(this);
    RegisterHandlers();
}

std::set<Logger*>&
npsuite::Logger::GetActiveLoggers()
{
    static std::set<Logger*> activeLoggers;
    return activeLoggers;
}

void
Logger::RegisterHandlers()
{
    static bool exitHandlersRegistered = false;
    if (!exitHandlersRegistered) {
        SignalHandler::GetInstance().AddCallback(LoggerSignalHandler);
        std::atexit(LoggerAtexitHandler);
        exitHandlersRegistered = true;
    }
}

LogFileWriter*
Logger::GetLogFileWriter()
{
    return mLogFileWriter;
}

void
Logger::SetLogFilePath(string outputFolderPath,
                       bool logPrefixEnabled,
                       string logFileName,
                       size_t maxLogSize,
                       size_t maxLogFiles,
                       bool compress)
{
    if (mLogFileWriter) {
        delete mLogFileWriter;
        mLogFileWriter = nullptr;
    }

    string computedLogFileName = (logFileName != "") ? logFileName : LOG_FILE_NAME;

    if (maxLogSize == 0) {
        mLogFileWriter = new LogFileWriter(outputFolderPath + "/" + computedLogFileName, 1, logPrefixEnabled, true, compress);
    } else {
        mLogFileWriter = new LogFileWriter(outputFolderPath + "/" + computedLogFileName,
                                           1,
                                           logPrefixEnabled,
                                           true,
                                           maxLogSize,
                                           (maxLogFiles == 0) ? DEFAULT_MAX_LOG_FILES : maxLogFiles,
                                           compress);
    }
    // create the moddule loggers
    for (int i = 0; i < NUM_MODULES; i++) {
        mModuleLoggers[i]->SetLogFileWriter(mLogFileWriter);
    }
}

Logger::~Logger()
{
    std::lock_guard<std::mutex> lock(sActiveLoggersMutex);
    GetActiveLoggers().erase(this);

    StopLoggingThread();
    Flush();

    // Free the module loggers. Need to flush buffers to files.
    for (int i = 0; i < NUM_MODULES; i++) {
        delete mModuleLoggers[i];
        mModuleLoggers[i] = nullptr;
    }

    if (mLogFileWriter) {
        delete mLogFileWriter;
        mLogFileWriter = nullptr;
    }
}

void
Logger::InitDefaultLogger(string outputFolderPath, bool logPrefixEnabled, string logFileName)
{
    static Logger logger(outputFolderPath, logPrefixEnabled, logFileName, false);

    // create the singleton object
    if (nullptr == mDefaultLogger) {
        mDefaultLogger = &logger;
    }
    if (nullptr == mAlternateDefaultLogger) {
        mAlternateDefaultLogger = mDefaultLogger;
    }
}

void
Logger::SetModuleFileLogLevel(eModules module, npsuite_log_level_e newLevel)
{
    mModuleLoggers[module]->SetFileLogLevel(newLevel);
}

void
Logger::SetFileLogLevelForAll(enum npsuite::npsuite_log_level_e_ newLevel)
{
    for (int i = 0; i < NUM_MODULES; i++) {
        SetModuleFileLogLevel((eModules)i, newLevel);
    }
}

void
Logger::SetModuleStdOutLogLevel(eModules module, enum npsuite::npsuite_log_level_e_ newLevel)
{
    mModuleLoggers[module]->SetStdOutLogLevel(newLevel);
}

void
Logger::SetStdOutLogLevelForAll(enum npsuite::npsuite_log_level_e_ newLevel)
{
    for (int i = 0; i < NUM_MODULES; i++) {
        SetModuleStdOutLogLevel((eModules)i, newLevel);
    }
}

void
Logger::SetIsSynchronousLogger(bool isSynchronous)
{
    mIsSynchronous = isSynchronous;
}

void
Logger::SetMsgPrefix(const std::string& msgPrefix)
{
    if (msgPrefix.length() > 0) {
        mMsgPrefix = msgPrefix + ": ";
    } else {
        mMsgPrefix = "";
    }
}

bool
Logger::IsLogLevelEnabled(eModules module, enum npsuite::npsuite_log_level_e_ level) const
{
    return (mModuleLoggers[module] && mModuleLoggers[module]->IsLogLevelEnabled(level));
}

void
Logger::Flush()
{
    // Blocks untill the buffer is empty
    // and all messages are logged
    if (mLoggingThreadIsActive) {
        mLoggingBuffer.flush();
    } else {
        LogMessages();
    }
}

void
Logger::StopLoggingThread()
{
    if (mLoggingThread != nullptr) {
        if (mLoggingThread->joinable()) {
            mLoggingThreadIsActive = false;
            mLoggingBuffer.wake();
            mLoggingThread->join();
        }

        delete mLoggingThread;
        mLoggingThread = nullptr;
    }
}

void
Logger::LogMessages()
{
    LogInfo logInfo;
    while (mLoggingThreadIsActive || !mLoggingBuffer.empty()) {
        // Blocks untill there is a message to log
        {
            mLoggingBuffer.get(logInfo);

            if (mModuleLoggers[logInfo.mModule]->Log(logInfo.mLogLevel,
                                                     mLogPrefixEnabled,
                                                     logInfo.mThreadNamePrefix,
                                                     mMsgPrefix,
                                                     logInfo.mFileName,
                                                     logInfo.mLine,
                                                     logInfo.mMsg)) {
                ++mNumLogsPerLevel[logInfo.mLogLevel];
            }

            mLoggingBuffer.notifyMessageWritten();
        }

        //
        // If a callback has been specified, invoke it with "logInfo" which should be a safe copy of all logging information. Note
        // we are doing this intentionally outside of the
        // lock used by mLoggingBuffer.get() to try to avoid deadlocks; as there is no need for a lock now that we have a copy of
        // the log message.
        //
        logger_api_lock lock(m_lock);
        if (!m_client_log_handlers.empty()) {
            npsuite::npsuite_logger_message_callback_data_t data;

            data.level = logInfo.mLogLevel;
            data.thread_prefix = logInfo.mThreadNamePrefix;
            data.msg_prefix = mMsgPrefix;
            data.file = logInfo.mFileName;
            data.line = logInfo.mLine;
            data.msg = logInfo.mMsg;

            //
            // Send a copy of the log information to each registered client.
            //
            for (const auto& p : m_client_log_handlers) {
                //
                // Filter log messages for the client's level
                //
                const auto& value = p.second;
                auto client_log_level = value.first;
                if (client_log_level >= static_cast<int>(data.level)) {
                    (value.second)(data);
                }
            }
        }
    }
}

//
// Register a callback to be invoked when the logger logs a message.
//
npsuite::register_log_message_client_handle_t
Logger::register_log_message_callback(npsuite::npsuite_log_level_e level, npsuite::npsuite_logger_message_callback_t callback)
{
    logger_api_lock lock(m_lock);
    auto client_handle = ++register_log_message_client_handle;

    //
    // Keep track of/update this client
    //
    m_client_log_handlers[client_handle] = std::make_pair(level, callback);

    return client_handle;
}

//
// Deregister a previous callback to be invoked when the logger logs a message.
//
void
Logger::unregister_log_message_callback(const npsuite::register_log_message_client_handle_t& client_handle)
{
    logger_api_lock lock(m_lock);

    //
    // Forget this client
    //
    m_client_log_handlers.erase(client_handle);
}

void
Logger::InsertErrorToVector(enum npsuite::npsuite_log_level_e_ level, const std::string& msg)
{
    std::unique_lock<std::mutex> vectorLock(mErrorsVectorMutex);
    mErrorsLoggingVector.push_back(string(npsuite::GetLogLevelName(level)) + " " + msg);
}

void
Logger::Log(eModules module,
            enum npsuite::npsuite_log_level_e_ level,
            const std::string& file,
            unsigned long int line,
            const string& msg)
{
    mLoggingBuffer.insert(module, level, file, line, msg);
    if (level >= npsuite::NPSUITE_LOG_LEVEL_ERROR || level == npsuite::NPSUITE_LOG_LEVEL_WARNING) {
        InsertErrorToVector(level, msg);
    }
    if (mIsSynchronous) {
        Flush();
    }
}

void
Logger::Log(eModules module, enum npsuite::npsuite_log_level_e_ level, const char* file, unsigned long int line, const string& msg)
{
    Log(module, level, std::string(file), line, msg);
}

void
Logger::Log(eModules module,
            enum npsuite::npsuite_log_level_e_ level,
            const char* file,
            unsigned long int line,
            const std::string& msg,
            const nplLogInfo& nplInfo)
{
    Log(module, level, file, line, nplInfo.to_string() + ": " + msg);
}

bool
Logger::IsDefaultLoggerInitialized()
{
    return (mDefaultLogger != nullptr);
}

unsigned long
Logger::GetNumLogMessages(enum npsuite::npsuite_log_level_e_ level) const
{
    return mNumLogsPerLevel[level];
}

Logger*
Logger::GetDefaultLogger()
{
    return mAlternateDefaultLogger;
}

void
Logger::RedirectDefaultLogger(Logger* logger)
{
    mAlternateDefaultLogger = logger;
}

void
Logger::RestoreDefualtLogger()
{
    mAlternateDefaultLogger = mDefaultLogger;
}

void
Logger::FlushAndStopLoggingThreads()
{
    std::lock_guard<std::mutex> lock(sActiveLoggersMutex);
    for (auto logger : GetActiveLoggers()) {
        logger->StopLoggingThread();
        logger->Flush();
    }
}

std::vector<std::string>
Logger::GetErrorsVector()
{
    std::unique_lock<std::mutex> vectorLock(mErrorsVectorMutex);
    return mErrorsLoggingVector;
}

void
Logger::MessageBuffer::wake()
{
    // Inline a portion of the content of insert to prevent accessing thread local storage
    // during the std::atexit handler, which doesn't seem to reliably work and could
    // cause segmentation faults.
    std::unique_lock<std::mutex> flushLock(mFlushMutex, std::defer_lock);
    std::unique_lock<std::mutex> bufferLock(mBufferMutex, std::defer_lock);
    std::lock(flushLock, bufferLock);

    mBuffer.emplace_back(APP, NPSUITE_LOG_LEVEL_TRACE, "", "", 0, "");
    mBufferNotEmptyCond.notify_all();
}

void
Logger::MessageBuffer::flush()
{
    std::unique_lock<std::mutex> flushLock(mFlushMutex, std::defer_lock);
    std::unique_lock<std::mutex> bufferLock(mBufferMutex, std::defer_lock);
    std::lock(flushLock, bufferLock);

    mBufferFlushedCond.wait(bufferLock, [this]() { return mBuffer.size() == 0 && !mWriteInProgress; });
}

void
Logger::MessageBuffer::notifyMessageWritten()
{
    std::unique_lock<std::mutex> bufferLock(mBufferMutex);

    mWriteInProgress = false;
    mBufferFlushedCond.notify_one();
}

void
Logger::MessageBuffer::insert(eModules module,
                              enum npsuite::npsuite_log_level_e_ level,
                              const std::string& file,
                              unsigned long int line,
                              const std::string msg)
{
    std::unique_lock<std::mutex> flushLock(mFlushMutex, std::defer_lock);
    std::unique_lock<std::mutex> bufferLock(mBufferMutex, std::defer_lock);
    std::lock(flushLock, bufferLock);

    mBuffer.emplace_back(module, level, getThreadPrefix(), file, line, msg);
    mBufferNotEmptyCond.notify_one();
}

void
Logger::MessageBuffer::get(LogInfo& outLog)
{
    std::unique_lock<std::mutex> bufferLock(mBufferMutex);

    mBufferNotEmptyCond.wait(bufferLock, [this]() { return mBuffer.size() > 0; });
    mWriteInProgress = true;
    outLog = mBuffer.front();
    mBuffer.pop_front();
}

bool
Logger::MessageBuffer::empty()
{
    return mBuffer.size() == 0;
}

size_t
Logger::MessageBuffer::size()
{
    return mBuffer.size();
}
