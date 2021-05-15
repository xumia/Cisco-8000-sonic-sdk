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

#ifndef _FILE_WRITER_H_
#define _FILE_WRITER_H_

#include <string>
#include <fstream>
#include <assert.h>

#if defined(__has_include)
#if __has_include(<zlib.h>)

#include <zlib.h>
// Not all ZLIBs are created equally.  Older implementations
// do not support gzclose_w or Transparent write mode.
#if ZLIB_VERNUM >= 0x1270
#define FILE_WRITER_SUPPORTS_COMPRESSION
#endif

#endif
#elif !defined(_WIN32) && !defined(_WIN64)
// Using not Windows as a proxy for "supports zlib" is not ideal, but since our VSCC doesn't support __has_include
// and our Windows build environment doesn't include zlib, it seems the best we can do
#define FILE_WRITER_SUPPORTS_COMPRESSION
#endif

#ifdef FILE_WRITER_SUPPORTS_COMPRESSION

typedef gzFile file_writer_file;
typedef const char* file_writer_mode;

static inline void
write_to_file(file_writer_file f, const char* msg)
{
    gzputs((gzFile)f, msg);
}

static inline file_writer_file
open_file(const char* filename, file_writer_mode m)
{
    gzFile ofile = gzopen(filename, (const char*)m);
    if (ofile) {
        return (file_writer_file)ofile;
    } else {
        fprintf(stderr, "Failed to open %s for writing with flags %s, err: %d", filename, m, errno);
        assert(0 && "Failed to open file");
        return (file_writer_file) nullptr;
    }
}

static inline void
close_file(file_writer_file f)
{
    if (f) {
        gzclose_w((gzFile)f);
    }
}

static inline void
flush(file_writer_file f)
{
    if (f) {
        gzflush((gzFile)f, 0);
    }
}

#else

typedef std::fstream* file_writer_file;
typedef std::ios_base::openmode file_writer_mode;

static inline void
write_to_file(file_writer_file f, const char* msg)
{
    (*((std::fstream*)f)) << msg;
}

static inline file_writer_file
open_file(const char* filename, file_writer_mode m)
{
    std::fstream* fstream = new std::fstream(filename, (std::ios_base::openmode)m);

    if (fstream && fstream->is_open()) {
        fstream->flush();
        return fstream;
    } else {
        fprintf(stderr, "Failed to open %s for writing with flags %d, err: %d", filename, m, errno);
        assert(0 && "Failed to open file");
        return (file_writer_file) nullptr;
    }
}

static inline void
close_file(file_writer_file f)
{
    std::fstream* fstream = (std::fstream*)f;

    if (fstream) {
        fstream->flush();
        delete fstream;
    }
}

static inline void
flush(file_writer_file f)
{
    std::fstream* fstream = (std::fstream*)f;
    if (fstream) {
        fstream->flush();
    }
}

#endif

namespace npsuite
{

class FileWriter
{
public:
    FileWriter(std::string fileName,
               int flushEveryXLines = 1,
               std::ios_base::openmode mode = std::ios_base::out,
               bool compress_output = false);
    ~FileWriter();
    void Write(const char* line);       // write line to the file.
    void Write(const std::string line); // write line to the file.
    std::string GetFileName() const
    {
        return mFileName;
    }

    void CloseFile();
    void OpenFile(const std::string& fileName);

protected:
    void WritePartial(const char* msg)
    {
        write_to_file(mFile, msg);
    }

private:
    int mFlushEveryXLines;
    int mLinesSinceLastFlush;
    std::string mFileName;
    file_writer_file mFile;
    file_writer_mode mMode;
};
}

#endif //_FILE_WRITER_H_
