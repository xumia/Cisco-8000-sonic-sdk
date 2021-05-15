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

#ifndef __AAPL_IMPL_H__
#define __AAPL_IMPL_H__

#include "aapl/aapl.h"

#include "api/types/la_common_types.h"
#include "api/types/la_system_types.h"
#include "common/weak_ptr_unsafe.h"
#include "lld/lld_register.h"
#include <list>
#include <string>

namespace silicon_one
{

// Struct to share AAPL's built in void pointer: aapl-> client_data
// Referenced from aapl_core.h and aapl_core.c
// If needed, can add more pointers to struct
template <typename T>
struct aapl_client_data_struct {
    std::shared_ptr<T> default_ptr;                        // default pointer to use
    std::shared_ptr<std::vector<std::string> > log_buffer; // pointer for buffer storage
};

// Enum representing default_ptr and log_buffer of aapl_client_data_struct
enum client_data_label { CLIENT_DATA_DEFAULT_PTR = 0, CLIENT_DATA_LOG_BUFFER = 1 };

std::shared_ptr<void> aapl_bind_get_wrapper(Aapl_t* aapl, client_data_label label);

class la_device_impl;
}

using la_device_impl_wptr = silicon_one::weak_ptr_unsafe<silicon_one::la_device_impl>;

// In order to enable Avago AAPL API on top of Leaba Low-Level Driver,
// we utilize Avago AAPL option to register user supplied SBus communication functions.
// This Avago AAPL contain also capability to store user data inside Aapl_t handler and use
// it in the user supplied functions.
//
// This file contains: registered functions, user data definition and initialization function.

// Leaba "private" data stored in the Aapl_t handle and used by the registered functions.
class la_aapl_user
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief C'tor.
    la_aapl_user(const la_device_impl_wptr& device);

    /// @brief Translate logical receiver address to physical receiver address.
    ///
    /// @param[in]  addr                Logical receiver address.
    ///
    /// @return Physical receiver address.
    virtual uint32_t receiver_address_translate(uint32_t addr) const = 0;

    virtual void delay_before_exec() const;
    virtual void delay_before_poll() const;
    virtual void delay_in_poll() const;
    virtual int get_poll_timeout() const;

    la_device_impl_wptr m_device_impl;

    silicon_one::lld_register_scptr m_request_reg;
    silicon_one::lld_register_scptr m_request_data_reg;
    silicon_one::lld_register_scptr m_request_exec_reg;
    silicon_one::lld_register_scptr m_response_result_reg;
    silicon_one::lld_register_scptr m_response_data_reg;

    std::string m_name;

protected:
    virtual ~la_aapl_user() = default;
    la_aapl_user() = default;
    int m_delay_before_exec_cycles; ///< Delay this amount of core cycles before writing to m_request_exec_reg
    int m_delay_before_poll_cycles; ///< Delay this amount of core cycles before checking for 1->0 transition of exec.
    int m_delay_in_poll_cycles;     ///< Delay this amount of core cycles while polling for response (to debug sbus ifg).
    int m_poll_timeout;             ///< Number of times to poll response register
};

// Leaba "private" data and methods stored in the Aapl_t and used for IFG SerDes access without mapping.
class la_aapl_user_ifg_native : public la_aapl_user
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_aapl_user_ifg_native() = default;
    //////////////////////////////
public:
    // Disallow default and copy c'tors
    la_aapl_user_ifg_native(la_aapl_user_ifg_native&) = delete;

    la_aapl_user_ifg_native(const la_device_impl_wptr& device_impl, la_slice_id_t slice_id, la_ifg_id_t ifg_id);

    ~la_aapl_user_ifg_native() override = default;

    uint32_t receiver_address_translate(uint32_t addr) const override;

    std::list<uint32_t> get_all_serdes_address_list();

    la_slice_id_t m_slice_id;
    la_ifg_id_t m_ifg_id;
};

// Leaba "private" data and methods stored in the Aapl_t and used for IFG SerDes access.
class la_aapl_user_ifg : public la_aapl_user
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_aapl_user_ifg() = default;
    //////////////////////////////
public:
    // Disallow default and copy c'tors
    la_aapl_user_ifg(la_aapl_user_ifg&) = delete;

    la_aapl_user_ifg(const la_device_impl_wptr& device_impl, la_slice_id_t slice_id, la_ifg_id_t ifg_id);

    ~la_aapl_user_ifg() override = default;

    uint32_t receiver_address_translate(uint32_t addr) const override;

    la_slice_id_t m_slice_id;
    la_ifg_id_t m_ifg_id;
    uint m_base_addr;
};

// Leaba "private" data and methods stored in the Aapl_t and used for PCI SerDes access.
class la_aapl_user_pci : public la_aapl_user
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_aapl_user_pci() = default;
    //////////////////////////////
public:
    // Disallow default and copy c'tors
    la_aapl_user_pci(la_aapl_user_pci&) = delete;

    la_aapl_user_pci(const la_device_impl_wptr& device_impl);

    ~la_aapl_user_pci() override = default;

    uint32_t receiver_address_translate(uint32_t addr) const override;
};

// Leaba "private" data and methods stored in the Aapl_t and used for HBM channel access.
class la_aapl_user_hbm : public la_aapl_user
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_aapl_user_hbm() = default;
    //////////////////////////////
public:
    // Disallow default and copy c'tors
    la_aapl_user_hbm(la_aapl_user_hbm&) = delete;

    la_aapl_user_hbm(const la_device_impl_wptr& device_impl, size_t hbm_interface);

    ~la_aapl_user_hbm() override = default;

    uint32_t receiver_address_translate(uint32_t addr) const override;

    size_t m_hbm_interface;
};

// Function to communicate with SBus through Leaba LLD and to be registered to AAPL
// Register using aapl_register_sbus_fn which defined in aapl_core.h and aapl_core.c.
// Following is from aapl_core.c:
/**          The arguments for the registered SBus function are: */
/**             return: TRUE or FALSE to indicate if the command succeeded. */
/**             addr: SBus address to operate on. Corresponds to the *_sbus_receiver_address ports of the SBus master. */
/**             reg_addr: Data address within the given SBus address to operate on. Corresponds to the *_sbus_data_address ports on
 * the SBus master. */
/**             command: SBus command to send. Corresponds to the *_sbus_command ports on the SBus master. */
/**                 Required commands are: 1: write, 2: read, 0: reset */
/**             sbus_data: Pointer to the SBus data to write. Results of SBus read operations will be placed here. */
uint la_aapl_user_sbus_fn(::Aapl_t* aapl, uint addr, unsigned char reg_addr, unsigned char command, uint* sbus_data);

// Callback function to be used by AAPL
// Interface defined in aapl_core.h and aapl_core.c
int la_aapl_comm_open_fn(::Aapl_t* aapl);

// Callback function to be used by AAPL
// Interface defined in aapl_core.h and aapl_core.c
int la_aapl_comm_close_fn(::Aapl_t* aapl);

// Callback function to be used by AAPL
void la_aapl_log_fn(Aapl_t*, Aapl_log_type_t log_sel, const char* buf, size_t new_item_length);
// Callback function to be used by AAPL
int la_aapl_log_open_fn(Aapl_t*);
// Callback function to be used by AAPL
int la_aapl_log_close_fn(Aapl_t*);

#endif // __AAPL_IMPL_H__
