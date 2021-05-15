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

#ifndef __LA_STATUS_INFO_TYPES_H__
#define __LA_STATUS_INFO_TYPES_H__

/// @file
/// @brief Leaba status error extra information code.
///
/// Defines API-s for managing leaba status error extra information code.
///

#include "api/npu/la_counter_set.h"
#include "api/types/la_system_types.h"
#include "common/common_strings.h"
#include <string.h>

/// @addtogroup SYSTEM
/// @{

/// @brief      La status info struct stores status extra information of the la status.
///
/// @details    A la status info abstract struct is defined to store error extra information according to the error type,
///             and  where the error was created.
struct la_status_info {
    /// @brief La_status extra info type
    enum class type_e {
        /// ERESOURCE on table resource
        E_RESOURCE_TABLE,
        /// ERESOURCE on counter resource
        E_RESOURCE_COUNTER
    } type;

    /// @brief      Get verbose string about the error extra information
    ///
    /// @returns    A string with verbose information about the error
    virtual std::string message() = 0;

protected:
    virtual ~la_status_info()
    {
    }

    /// @brief      Constructor with info type
    ///
    /// @param[in]  _type              the info type
    explicit la_status_info(type_e _type) : type(_type)
    {
    }
};

/// @brief      La status info e_resource table struct stores status extra information for an E_RESOURCE error type of a table
/// resource.
///
/// @details    A la status info e_resource table struct is defined to store the resource type, the table name and the resoure
/// instance index
struct la_status_info_e_resource_table : la_status_info {

    /// @brief      Constructor with resource type, table name and instance index
    ///
    /// @param[in]  _resource              the resource type
    /// @param[in]  _name              the table name
    /// @param[in]  _id              the table instance index
    explicit la_status_info_e_resource_table(silicon_one::la_resource_descriptor::type_e _resource,
                                             std::string _name,
                                             silicon_one::la_resource_instance_index_t _id)
        : la_status_info(la_status_info::type_e::E_RESOURCE_TABLE), resource(_resource), name(_name), instance_id(_id)
    {
    }

    ~la_status_info_e_resource_table() override
    {
    }

    /// @brief resource type enum for which the out-of-resource error occurred.
    silicon_one::la_resource_descriptor::type_e resource;

    /// @brief table name for which the out-of-resource error occurred.
    std::string name;

    /// @brief table instance index for which the out-of-resource error occurred. according to the resource granularity.
    silicon_one::la_resource_instance_index_t instance_id;

    /// @brief      Get verbose string about the error extra information
    ///
    /// @returns    A string with verbose information about the error, includes the resource name, the info type, the table name and
    /// the table instance index.
    std::string message() override
    {
        std::string msg = "Leaba_Err_Info:";

        msg += "E_RESOURCE: ";
        msg += "resource: ";
        msg += silicon_one::to_string(resource);
        msg += ", type: ";
        msg += "E_RESOURCE_TABLE";
        msg += ", table name: ";
        msg += name;
        msg += ", instance_id: ";
        msg += std::to_string(instance_id);

        return msg;
    }
};

/// @brief      La status info e_resource counter struct stores status extra info for an E_RESOURCE error type of a counter
///
/// @details    A la status info e_resource counter struct is defined to store the resource type, the user type, slice id and ifg
/// id.
struct la_status_info_e_resource_counter : la_status_info {

    /// @brief      Constructor with resource type, user type, slice id and ifg
    ///
    /// @param[in]  _resource              the resource type
    /// @param[in]  _user              the counter user type
    /// @param[in]  _slice              the slice id
    /// @param[in]  _ifg             the ifg id
    explicit la_status_info_e_resource_counter(silicon_one::la_resource_descriptor::type_e _resource,
                                               std::string _user,
                                               la_slice_id_t _slice,
                                               la_ifg_id_t _ifg)
        : la_status_info(la_status_info::type_e::E_RESOURCE_COUNTER), resource(_resource), user(_user), slice(_slice), ifg(_ifg)
    {
    }

    ~la_status_info_e_resource_counter() override
    {
    }

    /// @brief resource type enum for which the out-of-resource error occurred.
    silicon_one::la_resource_descriptor::type_e resource;

    /// @brief the counter user type.
    std::string user;

    /// @brief the counter slice id
    la_slice_id_t slice;

    /// @brief the counter ifg id
    la_ifg_id_t ifg;

    /// @brief      Get verbose string about the error extra information
    ///
    /// @returns    A string with verbose information about the error, includes the resource name, the info type, the counter user
    /// name, the slice id and the ifg id.
    std::string message() override
    {
        std::string msg = "Leaba_Err_Info:";

        msg += "E_RESOURCE: ";
        msg += "resource: ";
        msg += silicon_one::to_string(resource);
        msg += ", type: ";
        msg += "E_RESOURCE_COUNTER";
        msg += ", user: ";
        msg += user;
        msg += ", slice: ";
        msg += std::to_string(slice);
        msg += ", ifg: ";
        msg += std::to_string(ifg);

        return msg;
    }
};

/// @}

#endif // __LA_STATUS_INFO_TYPES_H__
