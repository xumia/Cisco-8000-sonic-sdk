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

#include "log_file_writer.h"
#include <ctime>
#include <algorithm>
#include <assert.h>
#include <string.h>

using namespace npsuite;
using namespace std;

int
npsuite::string_format_size(const char* const format, ...)
{
    // initialize use of the variable argument array
    va_list vaArgs;
    va_start(vaArgs, format);

    // reliably acquire the size
    // and a functionally reliable call to mock the formatting
    const int iLen = std::vsnprintf(NULL, 0, format, vaArgs);
    va_end(vaArgs);

    return iLen;
}

const std::string
npsuite::string_format(const char* const format, ...)
{
    // initialize use of the variable argument array
    va_list vaArgs;
    va_start(vaArgs, format);

    // reliably acquire the size
    // from a copy of the variable argument array
    // and a functionally reliable call to mock the formatting
    va_list vaArgsCopy;
    va_copy(vaArgsCopy, vaArgs);
    const int iLen = std::vsnprintf(NULL, 0, format, vaArgsCopy);
    va_end(vaArgsCopy);

    // return a formatted string without risking memory mismanagement
    // and without assuming any compiler or platform specific behavior
    std::vector<char> zc(iLen + 1);
    std::vsnprintf(zc.data(), zc.size(), format, vaArgs);
    va_end(vaArgs);
    return std::string(zc.data(), iLen);
}

static string
get_filename(string baseFileName, uint64_t next)
{
    return string_format("%s.%lu", baseFileName.c_str(), next);
}

static string
add_z_extention_if_compressing(string baseFileName, bool compress)
{
#ifdef FILE_WRITER_SUPPORTS_COMPRESSION
    if (compress) {
        return baseFileName + ".Z";
    } else {
        return baseFileName;
    }
#else
    return baseFileName;
#endif
}

static bool
compress_if_you_can(bool compress)
{
#ifdef FILE_WRITER_SUPPORTS_COMPRESSION
    return compress;
#else
    return compress;
#endif
}

LogFileWriter::LogFileWriter(string fileName, int flushEveryXLines, bool logPrefixEnabled, bool measureProgress, bool compress)
    : FileWriter(add_z_extention_if_compressing(fileName, compress), flushEveryXLines, std::ios_base::out, compress),
      mLogPrefixEnabled(logPrefixEnabled),
      mMeasureProgress(measureProgress),
      mCompressLogFiles(compress_if_you_can(compress))
{
    mCreationTime = std::chrono::system_clock::now();
}

LogFileWriter::LogFileWriter(string fileNameBase,
                             int flushEveryXLines,
                             bool logPrefixEnabled,
                             bool measureProgress,
                             size_t maxLogSizeBytes,
                             size_t maxRotationFiles,
                             bool compress)
    : FileWriter(get_filename(add_z_extention_if_compressing(fileNameBase, compress), 0),
                 flushEveryXLines,
                 std::ios_base::out,
                 compress),
      mLogPrefixEnabled(logPrefixEnabled),
      mMeasureProgress(measureProgress),
      mMaxLogFileSizeBytes(maxRotationFiles > 0 ? maxLogSizeBytes / maxRotationFiles : 1),
      mMaxLogFiles(maxRotationFiles),
      mRotateLogs(true),
      mNextLogFile(1),
      mBaseFileName(add_z_extention_if_compressing(fileNameBase, compress)),
      mCompressLogFiles(compress_if_you_can(compress))
{
    mCreationTime = std::chrono::system_clock::now();
    assert((maxLogSizeBytes > 0) && (maxRotationFiles > 0) && "max log size and max rotation files must be > 0");
}

#define BUFFER_SIZE 256 * 1024

static FILE*
fopen_internal(const char* name, const char* mode)
{
    FILE* file = nullptr;
#if defined(_WIN32) || defined(_WIN64)
    (void)fopen_s(&file, name, mode);
#else
    file = fopen(name, mode);
#endif
    return file;
}

LogFileWriter::~LogFileWriter()
{
    // Do not coalesce log files when compressing them also
    if (mRotateLogs && mCompressLogFiles == false) {
        // Coalesce all of the remaining log files into a single file unless we compressed.
        uint64_t first_log_file;
        uint64_t last_log_file = mNextLogFile - 1;

        if (mNextLogFile >= mMaxLogFiles) {
            first_log_file = mNextLogFile - mMaxLogFiles;
        } else {
            first_log_file = 0;
        }

        if (FILE* ofile = fopen_internal(mBaseFileName.c_str(), "wb")) {
            size_t wresult = 0;
            size_t rresult = 0;
            unsigned char buffer[BUFFER_SIZE];
            uint64_t approximate_dropped_bytes = first_log_file * mMaxLogFileSizeBytes;

            // Add a header to the final log if any entries were dropped
            if (approximate_dropped_bytes != 0) {
                std::string output
                    = string_format("*** Dropped approximately %lu bytes of log entries because maximum log size is enabled\n",
                                    approximate_dropped_bytes);
                wresult = fwrite(output.c_str(), sizeof(unsigned char), output.length(), ofile);
                if (wresult == 0) {
                    fclose(ofile);
                    fprintf(stderr, "ERROR: Failed to write to %s\n", mBaseFileName.c_str());
                    return;
                }
            }

            for (uint64_t i = first_log_file; i <= last_log_file; i++) {
                std::string in_filename = get_filename(mBaseFileName, i);
                if (FILE* ifile = fopen_internal(in_filename.c_str(), "rb")) {
                    while (1) {
                        rresult = fread(buffer, sizeof(unsigned char), BUFFER_SIZE, ifile);
                        if (rresult != 0) {
                            wresult = fwrite(buffer, sizeof(unsigned char), rresult, ofile);
                            if (wresult == 0 && ferror(ofile)) {
                                fprintf(stderr, "ERROR: Failed to write %zu bytes to %s\n", rresult, mBaseFileName.c_str());
                                fclose(ofile);
                                fclose(ifile);
                                return;
                            }
                        } else if (ferror(ifile)) {
                            fprintf(stderr, "ERROR: Failed to read from %s\n", in_filename.c_str());
                            fclose(ofile);
                            fclose(ifile);
                            return;
                        }
                        // Handles EOF case
                        if (rresult != BUFFER_SIZE) {
                            fclose(ifile);
                            if (remove(in_filename.c_str()) != 0) {
                                fprintf(stderr, "WARNING: Failed to remove %s after copying its content\n", in_filename.c_str());
                            }
                            break;
                        }
                    }
                } else {
                    fprintf(stderr, "WARNING: Can't find %s, expected during coalescing\n", in_filename.c_str());
                }
            }

            fclose(ofile);
        } else {
            fprintf(stderr, "ERROR: Could not coalesce, unable to open %s for writing\n", mBaseFileName.c_str());
        }
    }
}

// I ran a single unit test with and without compression to come to this value.
//
// The real ratio is entirely dependent upon the source, so this is
// going to be wrong for every log, but it's a number and I needed one
//
// I ran a very huge test and got a ratio of 22.  I set it to 20 because
// a user concerned enough about disk space to enable compression and
// rotation is probably serious about not going over the specified limit.
//
// Since this is basically a guess, lets guess low (thus rotating more often)
//
// We could improve the guess by using gzoffset, with the caveat that it
// only updates when compressed bytes are written to disk.  We wouldn't
// be able to accurately know if a particular log entry would go over
// and then rotate, as we do without compression.  We could change the
// algorithm to rotate as soon as an entry goes over the max log file
// size instead.  This would prevent us from blowing over the max file limit,
// but then we could remove more than 1 file to compensate if required.
#define ARBITRARILY_OBTAINED_ZLIB_COMPRESSION_RATIO 20

void
LogFileWriter::about_to_write(size_t bytes_before_newline)
{
    // +1 for newline that will be added by FileWriter::Write, to keep
    // accounting accurate
    size_t len = bytes_before_newline + 1;

    size_t compression_ratio = 1;
    if (mCompressLogFiles) {
        // If we are compressing, then divide the number of bytes written by
        // our guess at how well ZLIB can compress NSIM logs to figure out
        // about how big the file is.  We have to guess because there's no
        // way to ask zlib how much will be written once the file is closed.
        compression_ratio = ARBITRARILY_OBTAINED_ZLIB_COMPRESSION_RATIO;
    }

    if ((len + mCurrLogFileSizeBytes) / compression_ratio > mMaxLogFileSizeBytes) {
        // Need to rotate files before write
        CloseFile();
        OpenFile(get_filename(mBaseFileName, mNextLogFile));

        if (mNextLogFile >= mMaxLogFiles) {
            uint64_t erase_file = mNextLogFile - mMaxLogFiles;
            string erase_name = get_filename(mBaseFileName, erase_file);

            if (remove(erase_name.c_str()) != 0) {
                fprintf(stderr, "WARNING: Failed to remove %s when switching to a new log output file\n", erase_name.c_str());
            }
        }

        mNextLogFile++;
        mCurrLogFileSizeBytes = len;
    } else {
        mCurrLogFileSizeBytes += len;
    }
}

#define PREFIX_LEN 100
#define FILE_LINE_LEN 512
#define TIME_ELAPSED_LEN 32

//
// Ripped off from the SDK. Please keep this identical to the SDK timestamp
// as it makes it easier to compare logs.
//
size_t
sdk_style_timestamp(char* buffer, size_t buffer_size)
{
    size_t chars_printed;
    auto now = std::chrono::system_clock::now();
    auto seconds = std::chrono::time_point_cast<std::chrono::seconds>(now);
    auto msec = std::chrono::duration_cast<std::chrono::milliseconds>(now - seconds);
    auto time_t_date = std::chrono::system_clock::to_time_t(now);
    struct tm result;

#if defined(_WIN32) || defined(_WIN64)
    localtime_s(&result, &time_t_date);
#else
    localtime_r(&time_t_date, &result);
#endif

    chars_printed = strftime(buffer, buffer_size, "%d-%m-%Y %H:%M:%S", &result);
    chars_printed += snprintf(buffer + chars_printed, buffer_size - chars_printed, ".%03d ", (int)msec.count());

    return chars_printed;
}

std::string
get_current_timestamp()
{
    char ts[64] = {};
    sdk_style_timestamp(ts, sizeof(ts));
    return std::string(ts);
}

void
LogFileWriter::Write(const std::string& moduleName,
                     npsuite::npsuite_log_level_e level,
                     const std::string& threadNamePrefix,
                     const std::string& msgPrefix,
                     const std::string& file,
                     unsigned long int line,
                     const std::string& msg,
                     bool writeLineInfo)
{
    static char sPrefix[PREFIX_LEN];
    int sPrefixLen = 0;
    static char sFileLine[FILE_LINE_LEN];
    int sFileLineLen = 0;
    static char sTimeElapsed[TIME_ELAPSED_LEN];
    int sTimeElapsedLen = 0;

    sPrefix[0] = '\0';
    sFileLine[0] = '\0';
    sTimeElapsed[0] = '\0';

    auto rawtime = std::chrono::system_clock::now();
    // prepare prefix, if needed
    if (mLogPrefixEnabled) {
        char ts[64]; // Matches the same buffer spaces as SDK
        auto chars_printed = sdk_style_timestamp(ts, sizeof(ts));
        if (chars_printed) {
            sPrefixLen = snprintf(sPrefix, sizeof(sPrefix), "%s- %-10s [%-8s] ", ts, moduleName.c_str(), GetLogLevelName(level));
        } else {
            sPrefixLen = snprintf(
                sPrefix, sizeof(sPrefix), "**-**-**** **:**:**.*** - %-10s [%-8s] ", moduleName.c_str(), GetLogLevelName(level));
        }
        if (sPrefixLen < 0 || sPrefixLen > PREFIX_LEN) {
            fprintf(stderr, "WARNING: Unable to format log prefix, return %d\n", sPrefixLen);
            sPrefixLen = 0;
        }
    }

    // prepare file-line
    if (writeLineInfo) {
        std::string file_out = file;
#if defined(_WIN32) || defined(_WIN64)
        // the following code meant for creating similar log file in windows/linux
        std::replace(file_out.begin(), file_out.end(), '\\', '/');
#endif
        sFileLineLen = snprintf(sFileLine, sizeof(sFileLine), " (line=> %s:%ld)", file_out.c_str(), line);

        if (sFileLineLen < 0 || sFileLineLen > FILE_LINE_LEN) {
            fprintf(stderr, "WARNING: Unable to format line info, return %d\n", sFileLineLen);
            sFileLineLen = 0;
        }
    }

    // prepare time measurement
    if (mMeasureProgress && (level == NPSUITE_LOG_LEVEL_PROGRESS)) {
        auto seconds = (int)std::chrono::duration_cast<std::chrono::seconds>(rawtime - mCreationTime).count();
        sTimeElapsedLen = snprintf(sTimeElapsed, sizeof(sTimeElapsed), " (%d seconds)", seconds);
        if (sTimeElapsedLen < 0 || sTimeElapsedLen > TIME_ELAPSED_LEN) {
            fprintf(stderr, "WARNING: Unable to format time elapsed, return %d\n", sTimeElapsedLen);
            sTimeElapsedLen = 0;
        }
    }

    if (mRotateLogs) {
        if (mLogPrefixEnabled) {
            about_to_write(sPrefixLen + msgPrefix.length() + threadNamePrefix.length() + msg.length() + sTimeElapsedLen
                           + sFileLineLen);
        } else {
            about_to_write(msg.length() + sTimeElapsedLen + sFileLineLen);
        }
    }

    if (mLogPrefixEnabled) {
        FileWriter::WritePartial(sPrefix);
        FileWriter::WritePartial(threadNamePrefix.c_str());
        FileWriter::WritePartial(msgPrefix.c_str());
    }
    FileWriter::WritePartial(msg.c_str());
    FileWriter::WritePartial(sTimeElapsed);
    FileWriter::Write(sFileLine);
}
