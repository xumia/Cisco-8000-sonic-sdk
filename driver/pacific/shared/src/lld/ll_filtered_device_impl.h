// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LEABA_LLD_LL_FILTERED_DEVICE_IMPL_H__
#define __LEABA_LLD_LL_FILTERED_DEVICE_IMPL_H__

#include "common/bit_vector.h"
#include "ll_device_impl.h"
#include "lld/ll_device.h"

#include <string>

namespace silicon_one
{
/// @brief Leaba device - SBIF part implementation.
class ll_filtered_device_impl : public ll_device_impl
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    // @brief C'tor, the actual initialization of leaba module device is done in init().
    ///
    /// [in] device_id -            the designated Id for the current device
    /// [in] explicitly_allow -     if this is false, will only check if the block is forbiden
    /// [in] allowed_config_file -  a config file containing the ids of every allowed block,
    ///                              will only be used if explicitly_allow ==true
    explicit ll_filtered_device_impl(la_device_id_t device_id, bool explicitly_allow, const std::string allowed_config_file);

    /// @brief Copy c'tor - disallowed.
    ll_filtered_device_impl(const ll_filtered_device_impl&) = delete;

    bool initialize(const char* device_path, device_simulator* sim, const la_platform_cbs& platform_cbs) override;

    // Registers API
    la_status read_register(const lld_register& reg, bit_vector& out_bv) override;
    la_status read_register(const lld_register_scptr& reg, bit_vector& out_bv) override;
    la_status peek_register(const lld_register& reg, bit_vector& out_bv) override;
    la_status peek_register(const lld_register_scptr& reg, bit_vector& out_bv) override;
    la_status read_register(const lld_register& reg, size_t out_val_sz, void* out_val) override;
    la_status peek_register(const lld_register& reg, size_t out_val_sz, void* out_val) override;
    la_status read_register_raw(la_block_id_t block_id, la_entry_addr_t addr, uint32_t width_bits, bit_vector& out_bv) override;
    la_status peek_register_raw(la_block_id_t block_id, la_entry_addr_t addr, uint32_t width_bits, bit_vector& out_bv) override;

    la_status write_register(const lld_register& reg, const bit_vector& in_bv) override;
    la_status write_register(const lld_register_scptr& reg, const bit_vector& in_bv) override;
    la_status write_register(const lld_register& reg, size_t in_val_sz, const void* in_val) override;
    la_status write_register_raw(la_block_id_t block_id,
                                 la_entry_addr_t addr,
                                 uint32_t width_bits,
                                 const bit_vector& in_bv) override;

    la_status read_modify_write_register(const lld_register& reg, size_t msb, size_t lsb, const bit_vector& value) override;
    la_status wait_for_value(const lld_register& reg, bool equal, uint16_t val, uint16_t mask) override;

    // Memory API
    la_status read_memory(const lld_memory& mem, size_t line, bit_vector& out_bv) override;
    la_status read_memory(const lld_memory_scptr& mem, size_t line, bit_vector& out_bv) override;
    la_status read_memory(const lld_memory& mem, size_t first_line, size_t count, size_t out_val_sz, void* out_val) override;
    la_status read_memory(const lld_memory& mem, size_t first_line, size_t count, bit_vector& out_bv) override;
    la_status read_memory_raw(la_block_id_t block_id, la_entry_addr_t addr, uint32_t width_bits, bit_vector& out_bv) override;

    la_status write_memory(const lld_memory& mem, size_t line, const bit_vector& in_bv) override;
    la_status write_memory(const lld_memory_scptr& mem, size_t line, const bit_vector& in_bv) override;
    la_status write_memory(const lld_memory& mem, size_t first_line, size_t count, size_t in_val_sz, const void* in_val) override;
    la_status fill_memory(const lld_memory& mem, size_t mem_first_entry, size_t count, const bit_vector& in_bv) override;
    la_status write_memory_raw(la_block_id_t block_id, la_entry_addr_t addr, uint32_t width_bits, const bit_vector& in_bv) override;

    la_status read_modify_write_memory(const lld_memory& mem,
                                       size_t line,
                                       size_t msb,
                                       size_t lsb,
                                       const bit_vector& value) override;

    la_status refresh_memory(const lld_memory& mem, size_t line) override;

    la_status wait_for_value(const lld_memory& mem, size_t line, bool equal, uint16_t val, uint16_t mask) override;

    // TCAM API
    la_status read_tcam(lld_memory const& tcam,
                        size_t tcam_line,
                        bit_vector& out_key_bv,
                        bit_vector& out_mask_bv,
                        bool& out_valid) override;
    la_status read_tcam(lld_memory const& tcam,
                        size_t tcam_line,
                        size_t key_mask_sz,
                        void*& out_key,
                        void*& out_mask,
                        bool& out_valid) override;

    la_status write_tcam(const lld_memory& tcam,
                         size_t tcam_line,
                         const bit_vector& in_key_bv,
                         const bit_vector& in_mask_bv) override;
    la_status write_tcam(const lld_memory& tcam,
                         size_t tcam_line,
                         size_t key_mask_sz,
                         const void* in_key,
                         const void* in_mask) override;

    la_status invalidate_tcam(const lld_memory& tcam, size_t tcam_line) override;

    // Transaction API - create HW access descriptors
    access_desc make_read_register(const lld_register& reg, bool peek, bit_vector& out_bv) override;
    access_desc make_write_register(const lld_register& reg, const bit_vector& in_val) override;
    access_desc make_read_modify_write_register(const lld_register& reg, size_t msb, size_t lsb, const bit_vector& in_val) override;

    access_desc make_read_memory(const lld_memory& mem, size_t first_entry, size_t count, bit_vector& out_bv) override;
    access_desc make_write_memory(const lld_memory& mem, size_t first_entry, size_t count, const bit_vector& in_val) override;
    access_desc make_read_modify_write_memory(const lld_memory& mem,
                                              size_t line,
                                              size_t msb,
                                              size_t lsb,
                                              const bit_vector& in_val) override;
    access_desc make_read_tcam(lld_memory const& tcam,
                               size_t tcam_line,
                               bit_vector& out_key_bv,
                               bit_vector& out_mask_bv,
                               bool& out_valid) override;
    access_desc make_write_tcam(const lld_memory& tcam,
                                size_t tcam_line,
                                const bit_vector& in_key_bv,
                                const bit_vector& in_mask_bv) override;
    access_desc make_invalidate_tcam(const lld_memory& tcam, size_t tcam_line) override;
    access_desc make_wait_for_value(const lld_register& reg, bool equal, uint16_t val, uint16_t mask) override;
    access_desc make_wait_for_value(const lld_memory& mem, size_t line, bool equal, uint16_t val, uint16_t mask) override;

    bool is_block_available(la_block_id_t block_id) override;

    la_status disable_block(la_block_id_t block_id);
    la_status enable_block(la_block_id_t block_id);

    bool is_block_allowed(const lld_block_scptr& b) const override;

private:
    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    ll_filtered_device_impl() = default;

    /// @brief if (m_use_filtered), lld will only access block that are in m_filtered_block;
    std::set<la_block_id_t> m_filtered_block_ids;
    std::set<std::string> m_filtered_block_names;
    /// @brief lld will never access blocks that are in m_forbiden_blocks - weather or not they are in m_filtered_blocks;
    std::set<la_block_id_t> m_forbiden_blocks;

    bool m_use_filtered;

    std::string m_allowed_config_file;

    void validate_blocks();

    template <typename Command, typename Storage>
    la_status read_filtered(const Storage& storage, Command&& command)
    {
        if (is_block_allowed(storage.get_block())) {
            return command();
        } else {
            return LA_STATUS_SUCCESS;
        }
    }

    template <typename Command, typename Storage>
    la_status write_filtered(const Storage& storage, Command&& command)
    {
        if (is_block_allowed(storage.get_block())) {
            return command();
        } else {
            return LA_STATUS_SUCCESS;
        }
    }

    template <typename Command, typename Storage>
    ll_device::access_desc make_command(const Storage& storage, Command&& command)
    {
        if (is_block_allowed(storage.get_block())) {
            return command();
        } else {
            return make_delay(0);
        }
    }
};
}

#endif
