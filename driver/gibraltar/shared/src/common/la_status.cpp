// BEGIN_LEGAL
//
// Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "common/la_status.h"

class la_status_category : public std::error_category
{
public:
    const char* name() const noexcept override;
    std::string message(int ev) const override;
};

const char*
la_status_category::name() const noexcept
{
    return "Leaba";
}

std::string
la_status_category::message(int ev) const
{
    switch (static_cast<la_status_e>(ev)) {
    case la_status_e::SUCCESS:
        return "Success";

    case la_status_e::E_AGAIN:
        return "Resource temporarily unavailable";

    case la_status_e::E_OUTOFMEMORY:
        return "Out of memory";

    case la_status_e::E_ACCES:
        return "Attempt to read from a read-protected or to write to a write-protected resource";

    case la_status_e::E_BUSY:
        return "Resource needed for operation is busy";

    case la_status_e::E_EXIST:
        return "Key already exists in table";

    case la_status_e::E_NODEV:
        return "Device is not present";

    case la_status_e::E_INVAL:
        return "Invalid parameter was supplied";

    case la_status_e::E_DIFFERENT_DEVS:
        return "Parameters supplied belong to different devices";

    case la_status_e::E_RESOURCE:
        return "Out of resources";

    case la_status_e::E_NOTFOUND:
        return "Entry requested not found";

    case la_status_e::E_NOTIMPLEMENTED:
        return "API is not implemented";

    case la_status_e::E_UNKNOWN:
        return "Unknown error occurred while attempting to perform requested operation";

    case la_status_e::E_SIZE:
        return "Wrong buffer size";

    case la_status_e::E_NOTINITIALIZED:
        return "Object is not initialized";

    case la_status_e::E_DOUBLE_FAULT:
        return "A fault occured while trying to recover from a previous error - usually fatal";

    case la_status_e::E_OUTOFRANGE:
        return "Index is out of range";

    default:
        return "(Unknown status)";
    }
}

la_status_category la_status_category_inst;

const std::error_category&
la_status_get_category()
{
    return la_status_category_inst;
}

std::string
la_status::message() const
{
    std::string msg = "Leaba_Err: " + m_ec.category().message(m_ec.value());

    if (m_func) {
        msg += ": ";
        msg += m_func;
        msg += ":";
        msg += m_file;
        msg += ":";
        msg += std::to_string(m_line);
    }

    return (msg);
}

la_status_e
la_status::set_info(const std::shared_ptr<la_status_info>& info)
{
    if (m_info == nullptr) {
        m_info = info;
        return la_status_e::SUCCESS;
    }
    return la_status_e::E_EXIST;
}

std::string
la_status2str(la_status status)
{
    return (status.message());
}
