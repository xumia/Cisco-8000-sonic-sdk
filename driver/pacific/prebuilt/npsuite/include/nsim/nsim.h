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

#ifndef __NSIM_H__
#define __NSIM_H__

#include <string>

#include "utils/nsim_bv.h"
#include "nsim/nsim_config_interface.h"
#include "nsim/nsim_control_interface.h"
#include "nsim/nsim_data_interface.h"
#include "nsim/nsim_log_interface.h"

/// @file
/// @brief NSIM API-s.
///
/// Defines API-s for creating and controlling an nsim_core NPL simulator.

namespace nsim
{

class nsim_core;

class nsim_holder;

/// @brief Create an nsim_core instance and initialize it.
///
/// @param[in]  source_path     NPL code path.
/// @param[in]  leaba_defined_path   leaba defined folder path.
/// @param[in]  additional_params   additional parameters map[feature_type, feature_value]
///
/// @return nsim_core instance if creation and initialization completed successfully.
///         NULL if NPL code in source path cannot be found/compiled, or Tables shared library cannot be loaded.
nsim_core* nsim_create_and_init(const std::string& source_path,
                                const std::string& leaba_defined_path,
                                const std::map<std::string, std::string> additional_params);

/// @brief Create an nsim_core instance.
///
/// @param[in]  source_path     NPL code path.
/// @param[in]  leaba_defined_path   leaba defined folder path.
///
/// @return nsim_core instance if creation completed successfully.
///         NULL if NPL code in source path cannot be found/compiled, or Tables shared library cannot be loaded.
nsim_core* nsim_create(const std::string& source_path, const std::string& leaba_defined_path);

/// @brief Log message function. Should be used as callback in modules which do not have direct access to nsim.
///
/// @param[in] opaque                   NSIM object pointer
/// @param[in] nsim_log_level           Integer version of the npsuite::npsuite_log_level_e
/// @param[in] user_prefix_identifier   User prefix identifier for custom print of the logger module name
/// @param[in] message                  User string message
void nsim_log_message(void* opaque, int nsim_log_level, std::string user_prefix_identifier, std::string message);

class nsim_core : public nsim_log_interface, public nsim_config_interface, public nsim_control_interface, public nsim_data_interface
{
public:
    virtual ~nsim_core()
    {
    }

    /// @brief Initialize nsim params - parse npl code, prepare internal structs.
    ///
    /// @return true if initialization was successful
    virtual bool initialize() = 0;

    /// @brief Registers nsim holder
    ///
    /// @param[in]  holder   pointer to nsim holder
    virtual void register_nsim_holder(nsim_holder* holder) = 0;
    /// @brief Unregisters nsim holder
    ///
    /// @param[in]  holder   pointer to nsim holder
    virtual void unregister_nsim_holder(nsim_holder* holder) = 0;
    /// @brief set slice_Id context
    ///
    /// @param[in]  slice_id  slice id
    ///
    /// @param[in]  context_name context string name
    ///
    /// @return true if set was successful
    virtual bool set_slice_context(size_t slice_id, size_t context_id) = 0;
    /// @brief get npsuite release version
    ///
    /// @return release version string
    virtual std::string get_release_version() const = 0;
    /// @brief get num of threads
    ///
    /// @return num of threads in nsim
    virtual size_t get_num_of_packet_processing_threads() const = 0;
};
class nsim_holder
{
public:
    nsim_holder(nsim_core* nsim);
    ~nsim_holder();
    void remove_pointer_to_nsim();
    nsim_core* get_nsim();

protected:
    nsim_core* m_nsim;
};
} // namespace nsim

#endif
