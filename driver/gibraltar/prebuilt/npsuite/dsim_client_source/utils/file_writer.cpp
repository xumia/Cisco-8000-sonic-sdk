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

#include "file_writer.h"
#include <assert.h>
#include <iostream>

using namespace npsuite;
using namespace std;

#define TRANSPARENT_WRITE "Tw";
#define COMPRESS_WRITE "w"
#define TRANSPARENT_APPEND "Ta";

static file_writer_mode
get_mode(std::ios_base::open_mode mode, bool compress)
{
#ifdef FILE_WRITER_SUPPORTS_COMPRESSION
    const char* m;

    if (mode & ios_base::app) {
        m = TRANSPARENT_APPEND;
    } else if (mode & ios_base::out) {
        if (compress) {
            m = COMPRESS_WRITE;
        } else {
            m = TRANSPARENT_WRITE;
        }
    } else {
        m = "";
    }
    return (file_writer_mode)m;
#else
    return (file_writer_mode)mode;
#endif
}

FileWriter::FileWriter(string fileName, int flushEveryXLines, std::ios_base::openmode mode, bool compress)
    : mFlushEveryXLines(flushEveryXLines), mLinesSinceLastFlush(0), mFileName(fileName)
{
    mMode = get_mode(mode, compress);
    mFile = open_file(fileName.c_str(), mMode);
}

FileWriter::~FileWriter()
{
    close_file(mFile);
}

void
FileWriter::CloseFile()
{

    close_file(mFile);
    mFile = nullptr;
    mFileName = "";
}

void
FileWriter::OpenFile(const std::string& fileName)
{
    close_file(mFile);
    mFile = open_file(fileName.c_str(), mMode);
    mFileName = fileName;
}

void
FileWriter::Write(const char* line)
{
    if (mFile != nullptr) {
        write_to_file(mFile, line);
        write_to_file(mFile, "\n");

        mLinesSinceLastFlush++;
        if (mLinesSinceLastFlush == mFlushEveryXLines) {
            flush(mFile);
            mLinesSinceLastFlush = 0;
        }
    }
}

void
FileWriter::Write(const std::string line)
{
    Write(line.c_str());
}
