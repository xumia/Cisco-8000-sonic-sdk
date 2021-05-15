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

#ifndef __LEABA_LL_TRANSACTION_H__
#define __LEABA_LL_TRANSACTION_H__

#include <stdint.h>

#include "api/types/la_common_types.h"
#include "lld/ll_device.h"
#include "lld/lld_fwd.h"
#include "lld/lld_memory.h"
#include "lld/lld_register.h"

#include <functional>

namespace silicon_one
{

class ll_transaction
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @name Typedefs
    /// @{

    /// @brief Rollback action, runs in #silicon_one::ll_transaction::abort context.
    using rollback_desc = std::function<void()>;

    /// @}
    /// @name Special member functions
    /// @{

    /// @brief  Non-default c'tor - create a transaction and bind to a low-level device.
    ///
    /// @note   Assume that the low-level device object is already initialized.
    ///
    /// @param[in] ldev Pointer to a low-level device.
    ll_transaction(ll_device_wptr ldev);

    /// @brief  Move c'tor
    ///
    /// @param[in] other    Source object to move from
    ll_transaction(ll_transaction&& other);

    /// @brief  Copy c'tor - explicitly disallowed
    ll_transaction(const ll_transaction&) = delete;

    /// @}
    /// @name General API
    /// @{

    /// @brief  Commit the transaction to the device.
    ///
    /// @note   After commit(), the transaction becomes empty and new actions can be added to it.
    ///
    /// @retval Status code.
    la_status commit();

    /// @brief  Abort a transaction and run rollback actions.
    ///
    /// @note   Block till all rollback actions complete.
    ///
    /// @retval None.
    void abort();

    /// @brief  Add a rollback to a transaction.
    ///
    /// @note   Rollbacks are executed in LIFO (stack) order.
    ///
    /// @retval None.
    void push_rollback(rollback_desc rollback);

    /// @brief  Return the number of access descriptors queued for HW execution.
    ///
    /// @retval Number of queued actions.
    size_t access_count() const
    {
        return m_access.size();
    }

    /// @brief  Return the number of rollbacks.
    ///
    /// @retval Number of queued rollbacks.
    size_t rollback_count() const
    {
        return m_rollback.size();
    }

    /// @}
    /// @name Read/Write API
    /// @{

    /// @brief Read from a non-volatile register instance.
    ///
    /// @param[in]  reg                    Register to be queried.
    /// @param[out] out_bv                 Return value destination bit vector.
    ///
    /// @retval     Status code.
    la_status read_register(const lld_register& reg, bit_vector& out_bv);

    /// @brief Read register instance.
    ///
    /// Read HW register into auto-generated SW register struct.
    ///
    /// @param[in]  reg                 Register to be queried.
    /// @param[out] out_register_struct Register struct to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    template <class _StructType>
    inline la_status read_register(const lld_register& reg, _StructType& out_register_struct)
    {
        uint64_t* struct_ptr = (uint64_t*)&out_register_struct;
        bit_vector bv(struct_ptr, _StructType::SIZE_IN_BITS);
        return read_register(reg, bv);
    }

    /// @brief Read from a volatile register instance.
    ///
    /// @param[in]  reg     Register to be queried.
    /// @param[in]  peek    Peek at value without performing side effects.
    /// @param[out] out_bv  Return value destination bit vector.
    ///
    /// @retval     Status code.
    la_status read_register_volatile(const lld_register& reg, bool peek, bit_vector& out_bv);

    /// @brief Write to a register instance.
    ///
    /// @param[in]  reg                    Register to be manipulated.
    /// @param[in]  in_bv                  Data bit_vector.
    ///
    /// @retval     Status code.
    la_status write_register(const lld_register& reg, const bit_vector& in_bv);

    /// @brief Write to a register array instance.
    ///
    /// @param[in]  reg                    Register array to be manipulated.
    /// @param[in]  first                  First register to be manipulated.
    /// @param[in]  count                  Number of registers in register array to be manipulated.
    /// @param[in]  in_bv                  Data bit_vector.
    ///
    /// @retval     Status code.
    la_status write_register_array(const lld_register_array_container& reg, size_t first, size_t count, const bit_vector& in_bv);

    /// @brief Update a subfield of a register instance.
    ///
    /// @param[in]  reg                 Register to be manipulated.
    /// @param[in]  msb                 Subfield's MSB index.
    /// @param[in]  lsb                 Subfield's LSB index.
    /// @param[in]  value               Value to update.
    ///
    /// @retval     LA_STATUS_SUCCESS     Command completed successfully.
    /// @retval     LA_STATUS_EINVAL      One of the parameters is invalid.
    /// @retval     LA_STATUS_EOUTOFRANGE Value bit vector does not fit into target register.
    la_status read_modify_write_register(const lld_register& reg, size_t msb, size_t lsb, const bit_vector& value);

    /// @brief Wait for value to become equal or not equal.
    ///
    /// @note This operation is only meaningful for a volatile resource.
    ///
    /// @param[in]  reg                   Register to be manipulated.
    /// @param[in]  equal                 Wait for value to become equal or not.
    /// @param[in]  val                   Value to compare with.
    /// @param[in]  mask                  Comparison mask.
    ///
    /// @retval     LA_STATUS_SUCCESS     Command completed successfully.
    /// @retval     LA_STATUS_EINVAL      One of the parameters is invalid.
    /// @retval     LA_STATUS_EOUTOFRANGE Line index is out of range.
    la_status wait_for_value(const lld_register& reg, bool equal, uint16_t val, uint16_t mask);

    /// @brief Delay for a specified amount of core cycles.
    ///
    /// @param[in]  cycles  Delay cycles.
    ///
    /// @retval     LA_STATUS_SUCCESS     Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN    An unknown error occurred.
    la_status delay(uint64_t cycles);

    /// @brief Read one or more entries from non-volatile memory.
    ///
    /// @param[in]  mem                 Memory to access.
    /// @param[in]  first_entry         First entry to read from.
    /// @param[in]  count               Number of entries to read.
    /// @param[out] out_bv              Return value destination bit_vector.
    ///
    /// @retval     LA_STATUS_SUCCESS      Command completed successfully.
    /// @retval     LA_STATUS_EINVAL       One of the parameters is invalid.
    /// @retval     LA_STATUS_EOUTOFRANGE  Memory entry or count out of range.
    la_status read_memory(const lld_memory& mem, size_t first_entry, size_t count, bit_vector& out_bv);

    /// @brief Read one or more entries from volatile memory.
    ///
    /// @param[in]  mem                 Memory to access.
    /// @param[in]  first_entry         First entry to read from.
    /// @param[in]  count               Number of entries to read.
    /// @param[out] out_bv              Return value destination bit_vector.
    ///
    /// @retval     LA_STATUS_SUCCESS      Command completed successfully.
    /// @retval     LA_STATUS_EINVAL       One of the parameters is invalid.
    /// @retval     LA_STATUS_EOUTOFRANGE  Memory entry or count out of range.
    la_status read_memory_volatile(const lld_memory& mem, size_t first_entry, size_t count, bit_vector& out_bv);

    /// @brief Write one or more entries to memory.
    ///
    /// @param[in]  mem                 Memory to access.
    /// @param[in]  first_entry         First entry to write to.
    /// @param[in]  count               Number of entries to write.
    /// @param[out] in_bv               Input value.
    ///
    /// @retval     LA_STATUS_SUCCESS      Command completed successfully.
    /// @retval     LA_STATUS_EINVAL       One of the parameters is invalid.
    /// @retval     LA_STATUS_EOUTOFRANGE  Memory entry or count out of range.
    la_status write_memory(const lld_memory& mem, size_t first_entry, size_t count, const bit_vector& in_bv);

    /// @brief Update a subfield of a memory entry.
    ///
    /// @param[in]  mem                 Memory to be manipulated.
    /// @param[in]  line                Memory line.
    /// @param[in]  msb                 Subfield's MSB index.
    /// @param[in]  lsb                 Subfield's LSB index.
    /// @param[in]  value               Value to update.
    ///
    /// @retval     LA_STATUS_SUCCESS     Command completed successfully.
    /// @retval     LA_STATUS_EINVAL      One of the parameters is invalid.
    /// @retval     LA_STATUS_EOUTOFRANGE Value bit vector does not fit into target memory or line index is out of range.
    la_status read_modify_write_memory(const lld_memory& mem, size_t line, size_t msb, size_t lsb, const bit_vector& value);

    /// @brief Wait for value to become equal o not equal.
    ///
    /// @note This operation is only meaningful for a volatile resource.
    ///
    /// @param[in]  mem                   Memory to be manipulated.
    /// @param[in]  line                  Memory line.
    /// @param[in]  equal                 Wait for value to become equal or not.
    /// @param[in]  val                   Value to compare with.
    /// @param[in]  mask                  Comparison mask.
    ///
    /// @retval     LA_STATUS_SUCCESS     Command completed successfully.
    /// @retval     LA_STATUS_EINVAL      One of the parameters is invalid.
    /// @retval     LA_STATUS_EOUTOFRANGE Line index is out of range.
    la_status wait_for_value(const lld_memory& mem, size_t line, bool equal, uint16_t val, uint16_t mask);

    /// @brief Read TCAM entry.
    ///
    /// @param[in]  tcam                   TCAM to access.
    /// @param[in]  tcam_line              TCAM line to access.
    /// @param[out] out_key_bv             Return bit_vector for key.
    /// @param[out] out_mask_bv            Return bit_vector for mask.
    /// @param[out] out_valid              Return entry valid bit.
    ///
    /// @retval     LA_STATUS_SUCCESS       Command completed successfully.
    /// @retval     LA_STATUS_EINVAL        One of the parameters is invalid.
    /// @retval     LA_STATUS_EOUTOFRANGE   Line number is out of range.
    la_status read_tcam(lld_memory const& tcam, size_t tcam_line, bit_vector& out_key_bv, bit_vector& out_mask_bv, bool& out_valid);

    /// @brief Write TCAM entry and make it valid.
    ///
    /// @param[in]  tcam                   TCAM to access.
    /// @param[in]  tcam_line              TCAM line to access.
    /// @param[out] in_key_bv              Key bit_vector.
    /// @param[out] in_mask_bv             Mask bit_vector.
    ///
    /// @retval     LA_STATUS_SUCCESS       Command completed successfully.
    /// @retval     LA_STATUS_EINVAL        One of the parameters is invalid.
    /// @retval     LA_STATUS_EOUTOFRANGE   Line number is out of range.
    la_status write_tcam(const lld_memory& tcam, size_t tcam_line, const bit_vector& in_key_bv, const bit_vector& in_mask_bv);

    /// @brief Invalidate TCAM entry.
    ///
    /// @param[in]  tcam                   TCAM to access.
    /// @param[in]  tcam_line              The line number in the TCAM to access.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     LA_STATUS_EOUTOFRANGE   Line number is out of range.
    la_status invalidate_tcam(const lld_memory& tcam, size_t tcam_line);

    /// @}

private:
    // Low-level device
    ll_device_wptr m_ll_device;

    // HW access descriptors, executed in FIFO order
    vector_alloc<ll_device::access_desc> m_access;

    // Transaction rollback descriptors, executed in LIFO order
    std::vector<rollback_desc> m_rollback;

    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    ll_transaction() = default;

    // helpers
    la_status do_read_register(const lld_register& reg, bool peek, bit_vector& out_bv);
    la_status do_write_register(const lld_register& reg, const bit_vector& in_bv);

    la_status do_read_memory(const lld_memory& reg, size_t first_entry, size_t count, bit_vector& out_bv);
    la_status do_write_memory(const lld_memory& mem, size_t first_entry, size_t count, const bit_vector& in_bv);
    la_status do_write_register_array(const lld_register_array_container& reg, size_t first, size_t count, const bit_vector& in_bv);
};

} // namespace silicon_one
#endif
