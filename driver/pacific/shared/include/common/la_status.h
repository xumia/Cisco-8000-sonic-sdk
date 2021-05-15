// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_STATUS_H__
#define __LA_STATUS_H__

/// @file
/// @brief Leaba status error code.
///
/// Defines API-s for managing leaba status error code.
///

#include <errno.h>
#include <memory>
#include <string>
#include <system_error>

/// @addtogroup SYSTEM
/// @{

/// @brief Leaba status error code enum.
enum class la_status_e {
    /*  0 */ SUCCESS = 0,            ///< Operation completed successfully.
    /* 11 */ E_AGAIN = EAGAIN,       ///< Resource temporarily unavailable.
    /* 12 */ E_OUTOFMEMORY = ENOMEM, ///< Out of memory.
    /* 13 */ E_ACCES = EACCES,       ///< Attempt to read from a read-protected or to write to a write-protected resource.
    /* 16 */ E_BUSY = EBUSY,         ///< Resource needed for operation is busy.
    /* 17 */ E_EXIST = EEXIST,       ///< Key already exists in table.
    /* 19 */ E_NODEV = ENODEV,       ///< Device is not present.
    /* 22 */ E_INVAL = EINVAL,       ///< Invalid parameter was supplied.
    /* 23 */ E_DIFFERENT_DEVS,       ///< Parameters supplied belong to different devices.
    /* 24 */ E_RESOURCE,             ///< Out of resources.
    /* 25 */ E_NOTFOUND,             ///< Entry requested not found.
    /* 26 */ E_NOTIMPLEMENTED,       ///< API is not implemented.
    /* 27 */ E_UNKNOWN,              ///< Unknown error occurred while attempting to perform requested operation.
    /* 28 */ E_SIZE,                 ///< Wrong buffer size
    /* 29 */ E_NOTINITIALIZED,       ///< Object is not initialized
    /* 30 */ E_DOUBLE_FAULT,         ///< A fault occured while trying to recover from a previous error - usually fatal.
    /* 34 */ E_OUTOFRANGE = ERANGE,  ///< Index is out of range
};

#ifndef SWIG
namespace std
{
/// @brief      Register la_status_e as a error code enum. Mandatory requirement.
template <>
struct is_error_code_enum<la_status_e> : public true_type {
};
}
#endif

/// @brief      Returns the error category for la_status. Currently category is only "leaba"
///
/// @retval     Returns error_category instance
const std::error_category& la_status_get_category();

/// @brief      Function overload used by std::error_code to create error_code object using error enum
///
/// @param[in]  val               error enum for status of the operation.
///
/// @returns    Returns error_code object
inline std::error_code
make_error_code(la_status_e val) noexcept
{
    return std::error_code(static_cast<int>(val), la_status_get_category());
}

struct la_status_info;

/// @brief      La status class stores status of the operation.
///
/// @details    A la status class is defined to store error code, function name
///             and line number of the file where operation status is created.
class la_status
{

public:
    /// @brief      Default constructor with success error enum.
    la_status() = default;

    /// @brief      Constructor with error enum
    ///
    /// @param[in]  val               error enum for status of the operation.
    la_status(la_status_e val) : m_ec(val)
    {
    }

    /// @brief      Constructor with error enum, function name and line number
    ///
    /// @param[in]  func              pointer to function name
    /// @param[in]  file              pointer to file name
    /// @param[in]  line              line number
    /// @param[in]  val               error enum for status of the operation.

    la_status(const char* func, const char* file, int line, la_status_e val) : m_ec(val), m_func(func), m_file(file), m_line(line)
    {
    }

    /// @brief      Constructor with error enum, function name, line number and error info
    ///
    /// @param[in]  func              pointer to function name
    /// @param[in]  file              pointer to file name
    /// @param[in]  line              line number
    /// @param[in]  val               error enum for status of the operation.
    /// @param[in]  info              error extra info
    la_status(const char* func, const char* file, int line, la_status_e val, const std::shared_ptr<la_status_info>& info)
        : m_ec(val), m_func(func), m_file(file), m_line(line), m_info(info)

    {
    }

    /// @brief      Get verbose information about error
    ///
    /// @returns    A string with verbose information about error, and if
    ///             available also includes function name and line number.
    std::string message() const;

    /// @brief      Get error enum value associated with la_status.
    ///
    /// @returns    Returns error enum value.
    int value() const noexcept
    {
        return (m_ec.value());
    }

    /// @brief      Get the error extra info
    ///
    /// @returns    Returns shared_ptr of the error info
    std::shared_ptr<const la_status_info> get_info() const
    {
        return m_info;
    }

    /// @brief      Set the error extra info
    ///
    /// @param[in]  info            the error extra info
    /// @returns    Returns la_status_e::E_EXIST if info already exist or la_status_e::SUCCESS otherwise.
    la_status_e set_info(const std::shared_ptr<la_status_info>& info);

    /// @brief      Checks if the error value is valid, i.e. non-zero.
    ///
    /// @retval     true          Non-zero error value i.e. failure
    /// @retval     false         Success
    explicit operator bool() const noexcept
    {
        return (bool(m_ec));
    }

    /// @brief      Compare if la_status is equal to another la_status object.
    bool operator==(const la_status& rhs) const noexcept
    {
        return (this->value() == rhs.value());
    }

    /// @brief      Compare if la_status is not equal to another la_status object.
    bool operator!=(const la_status& rhs) const noexcept
    {
        return (this->value() != rhs.value());
    }

private:
    /// @brief error code object
    std::error_code m_ec = la_status_e::SUCCESS;

    /// @brief function name where la_status was created.
    const char* m_func = nullptr;

    /// @brief file name where la_status was created.
    const char* m_file = nullptr;

    /// @brief line number in file where la_status was created.
    size_t m_line = 0;

    /// @brief error extra info according to the specific error type
    std::shared_ptr<la_status_info> m_info;
};

/// @brief make a new la_status object with error enum, caller's function name
///        and caller's line number
///
#define make_status(err) (la_status(__PRETTY_FUNCTION__, __FILE__, __LINE__, err))

/// @brief macros call make_status for the respective error's to create
//         la_status object with caller's function name and line number in file.
#define LA_STATUS_SUCCESS make_status(la_status_e::SUCCESS)
#define LA_STATUS_EAGAIN make_status(la_status_e::E_AGAIN)
#define LA_STATUS_EOUTOFMEMORY make_status(la_status_e::E_OUTOFMEMORY)
#define LA_STATUS_EACCES make_status(la_status_e::E_ACCES)
#define LA_STATUS_EBUSY make_status(la_status_e::E_BUSY)
#define LA_STATUS_EEXIST make_status(la_status_e::E_EXIST)
#define LA_STATUS_ENODEV make_status(la_status_e::E_NODEV)
#define LA_STATUS_EINVAL make_status(la_status_e::E_INVAL)
#define LA_STATUS_EDIFFERENT_DEVS make_status(la_status_e::E_DIFFERENT_DEVS)
#define LA_STATUS_ERESOURCE make_status(la_status_e::E_RESOURCE)
#define LA_STATUS_ENOTFOUND make_status(la_status_e::E_NOTFOUND)
#define LA_STATUS_ENOTIMPLEMENTED make_status(la_status_e::E_NOTIMPLEMENTED)
#define LA_STATUS_EUNKNOWN make_status(la_status_e::E_UNKNOWN)
#define LA_STATUS_ESIZE make_status(la_status_e::E_SIZE)
#define LA_STATUS_ENOTINITIALIZED make_status(la_status_e::E_NOTINITIALIZED)
#define LA_STATUS_EDOUBLE_FAULT make_status(la_status_e::E_DOUBLE_FAULT)
#define LA_STATUS_EOUTOFRANGE make_status(la_status_e::E_OUTOFRANGE)

#define LA_STATUS_ERESOURCE_INFO(info) (la_status(__PRETTY_FUNCTION__, __FILE__, __LINE__, la_status_e::E_RESOURCE, info))

/// @brief      return status of the operation as string
///
/// @param[in]  status            status of the operation.
///
/// @returns    verbose status string
std::string la_status2str(la_status status);

/// @}

#endif
