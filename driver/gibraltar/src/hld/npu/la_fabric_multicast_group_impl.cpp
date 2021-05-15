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

#include "la_fabric_multicast_group_impl.h"
#include "api/types/la_system_types.h"
#include "nplapi/device_tables.h"
#include "nplapi/nplapi_tables.h"
#include "npu/la_multicast_group_common_base.h"
#include "system/la_device_impl.h"
#include <sstream>

#include "api_tracer.h"
#include "common/bit_utils.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/transaction.h"
#include "la_strings.h"

namespace silicon_one
{

la_fabric_multicast_group_impl::la_fabric_multicast_group_impl(const la_device_impl_wptr& device)
    : m_device(device), m_gid((la_multicast_group_gid_t)-1), m_is_scale_mode_smcid(false)
{
}

la_fabric_multicast_group_impl::~la_fabric_multicast_group_impl()
{
}

la_status
la_fabric_multicast_group_impl::initialize(la_object_id_t oid,
                                           la_multicast_group_gid_t multicast_gid,
                                           la_replication_paradigm_e rep_paradigm)
{
    m_oid = oid;
    m_gid = multicast_gid;
    m_local_mcid = multicast_gid;
    m_rep_paradigm = rep_paradigm;
    m_links_bitmap = 0;

    m_is_scale_mode_smcid = m_device->is_scale_mode_smcid(multicast_gid);

    if (m_is_scale_mode_smcid) {
        // The local_mcid will be updated when devices are set on this multicast group.
        // Initialize it to an invalid value.
        // If this group create is called as part of replay after RPFO,
        // the smcid to local_mcid will be populated in configure_local_mcid
        m_local_mcid = NPL_MULTICAST_RESERVED_MCID_TO_FABRIC_SLICE;
    }

    log_debug(HLD, "fab mcast group create: mgid = %d scaled_mode = %d", m_gid, m_is_scale_mode_smcid);

    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_multicast_group_impl::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    if (m_is_scale_mode_smcid) {
        bool is_deleted = false;
        la_status status;
        status = erase_global_to_local_mcid_mapping(m_gid);
        return_on_error(status);

        if (m_local_mcid != NPL_MULTICAST_RESERVED_MCID_TO_FABRIC_SLICE) {
            // erase the system MCID to local MCID mapping for this m_gid
            m_device->m_mc_smcid_to_local_mcid.erase(m_gid);

            status = release_local_mcid(m_local_mcid, is_deleted);
            return_on_error(status);

            if (is_deleted) {
                uint64_t zero[2] = {0};
                status = set_mc_bitmap(m_local_mcid, zero);
                return_on_error(status);
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_fabric_multicast_group_impl::type() const
{
    return la_object::object_type_e::FABRIC_MULTICAST_GROUP;
}

std::string
la_fabric_multicast_group_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_fabric_multicast_group_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_fabric_multicast_group_impl::oid() const
{
    return m_oid;
}

const la_device*
la_fabric_multicast_group_impl::get_device() const
{
    return m_device.get();
}

la_multicast_group_gid_t
la_fabric_multicast_group_impl::get_gid() const
{
    return m_gid;
}

la_multicast_group_gid_t
la_fabric_multicast_group_impl::get_local_mcid() const
{
    return m_local_mcid;
}

la_status
la_fabric_multicast_group_impl::get_replication_paradigm(la_replication_paradigm_e& out_replication_paradigm) const
{
    start_api_getter_call("");
    out_replication_paradigm = m_rep_paradigm;
    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_multicast_group_impl::get_devices(la_device_id_vec_t& out_device_id_vec) const
{
    start_api_getter_call("");
    out_device_id_vec = m_devices;
    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_multicast_group_impl::set_devices(const la_device_id_vec_t& device_id_vec)
{
    start_api_call("device_id_vec=", device_id_vec);
    la_device_id_vec_t current_devices = m_devices;
    m_devices = device_id_vec;
    la_status status = configure_mc_bitmap();
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD,
                "%s - configure_mc_bitmap failed mcids available %d",
                __func__,
                m_device->m_index_generators.local_mcids.available());
        m_devices = current_devices;
        return status;
    }

    return LA_STATUS_SUCCESS;
}

la_status
populate_fe_smcid_to_mcid_key(la_multicast_group_gid_t global_mcid,
                              npl_fe_smcid_to_mcid_table_t::key_type& key,
                              uint32_t& entry_idx)
{
    // the key to the table is bits 17:3
    key.system_mcid_17_3 = bit_utils::get_bits(global_mcid, 17 /*msb*/, 3 /*lsb*/);

    // the 3 LSBits index into the entry
    entry_idx = bit_utils::get_bits(global_mcid, 2 /*msb*/, 0 /*lsb*/);

    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_multicast_group_impl::set_global_to_local_mcid_mapping(la_multicast_group_gid_t global_mcid,
                                                                 la_multicast_group_gid_t local_mcid)
{
    transaction txn;

    // update the slice pair tables for this global to local MCID mapping
    for (la_slice_pair_id_t slice_pair : m_device->get_used_slice_pairs()) {
        const auto& table(m_device->m_tables.fe_smcid_to_mcid_table[slice_pair]);
        npl_fe_smcid_to_mcid_table_t::key_type key;
        npl_fe_smcid_to_mcid_table_t::value_type value;
        npl_fe_smcid_to_mcid_table_t::entry_wptr_type entry_ptr;
        uint32_t entry_idx;

        txn.status = populate_fe_smcid_to_mcid_key(global_mcid, key, entry_idx);
        return_on_error(txn.status);

        // check if this entry already exists
        la_status status = table->lookup(key, entry_ptr);
        if (entry_ptr) {
            npl_fe_smcid_to_mcid_table_t::value_type prev_value;
            return_on_error(status);

            // found an entry, update it
            value = entry_ptr->value();
            prev_value = value;
            value.payloads.mcid_array.mcid[entry_idx].id = local_mcid;
            txn.status = entry_ptr->update(value);
            return_on_error(txn.status);
            txn.on_fail([=]() { (void)entry_ptr->update(prev_value); });
        } else if (status == LA_STATUS_ENOTFOUND) {
            // initialize all the entries to invalid
            for (int i = 0; i < NPL_MULTICAST_NUM_MCIDS_PER_ENTRY; i++) {
                value.payloads.mcid_array.mcid[i].id = NPL_MULTICAST_RESERVED_MCID_TO_FABRIC_SLICE;
            }

            // set the value and update the table
            value.payloads.mcid_array.mcid[entry_idx].id = local_mcid;
            txn.status = table->insert(key, value, entry_ptr);
            return_on_error(txn.status);
            txn.on_fail([=]() { erase_global_to_local_mcid_mapping(global_mcid); });
        } else {
            return status;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_multicast_group_impl::erase_global_to_local_mcid_mapping(la_multicast_group_gid_t global_mcid)
{
    // update the slice pair tables to remove this global to local MCID mapping
    for (la_slice_pair_id_t slice_pair : m_device->get_used_slice_pairs()) {
        const auto& table(m_device->m_tables.fe_smcid_to_mcid_table[slice_pair]);
        npl_fe_smcid_to_mcid_table_t::key_type key;
        npl_fe_smcid_to_mcid_table_t::value_type value;
        npl_fe_smcid_to_mcid_table_t::entry_wptr_type entry_ptr;
        uint32_t entry_idx;

        la_status status = populate_fe_smcid_to_mcid_key(global_mcid, key, entry_idx);
        return_on_error(status);

        // check if this entry already exists
        status = table->lookup(key, entry_ptr);
        if (status == LA_STATUS_SUCCESS) {
            // found an entry, update it
            value = entry_ptr->value();
            // the resevered MCID is used as invalid
            value.payloads.mcid_array.mcid[entry_idx].id = NPL_MULTICAST_RESERVED_MCID_TO_FABRIC_SLICE;
            status = entry_ptr->update(value);
            return_on_error(status);
        } else if (status != LA_STATUS_ENOTFOUND) {
            // the entry to be erased should always be found
            return status;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_multicast_group_impl::release_local_mcid(la_multicast_group_gid_t local_mcid, bool& out_is_deleted)
{
    out_is_deleted = false;

    // find the devices bitmap for this local mcid
    auto links_bitmap_iter = m_device->m_mcid_to_links_bitmap.find(local_mcid);
    if (links_bitmap_iter == m_device->m_mcid_to_links_bitmap.end()) {
        log_err(HLD, "release failed to find bitmap for local_mcid %d", local_mcid);
        return LA_STATUS_ENOTFOUND;
    }
    mc_links_key_t links_key = links_bitmap_iter->second;

    // find the allocated MCID for this devices bitmap
    auto allocated_iter = m_device->m_links_bitmap_to_allocated_mcid.find(links_key);
    if (allocated_iter == m_device->m_links_bitmap_to_allocated_mcid.end()) {
        log_err(HLD, "release failed to find alocated_mcid for local_mcid %d", local_mcid);
        return LA_STATUS_ENOTFOUND;
    }

    // decrement the in_use
    const auto& allocated_mcid = allocated_iter->second;

    if (allocated_mcid->in_use == 0) {
        log_err(HLD, "release_local_mcid: mcid in use cannot be 0 before releasing local_mcid %d, m_gid %d", local_mcid, m_gid);
        return LA_STATUS_EINVAL;
    }

    log_debug(
        HLD, "release_local_mcid: allocated mcid = %d for m_gid = %d local_mcid %d", allocated_mcid->in_use, m_gid, local_mcid);
    allocated_mcid->in_use--;

    if (allocated_mcid->in_use == 0) {
        // this local MCID is no longer needed, free it
        out_is_deleted = true;
        m_device->m_index_generators.local_mcids.release(local_mcid);
        m_device->m_mcid_to_links_bitmap.erase(local_mcid);
        m_device->m_links_bitmap_to_allocated_mcid.erase(links_key);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_multicast_group_impl::allocate_local_mcid(uint64_t* links_bitmap,
                                                    la_multicast_group_gid_t& out_mcid,
                                                    bool& out_is_new_allocation)
{
    out_is_new_allocation = false;

    // create a tuple with the 128b bitmap to use as a key to the mapping table
    auto links_key = mc_links_key_t(links_bitmap[0], links_bitmap[1]);

    // initialize the out_mcid in case of failures
    out_mcid = NPL_MULTICAST_RESERVED_MCID_TO_FABRIC_SLICE;

    // search the mapping for an existing MCID using this bitmap
    const auto& allocated_iter = m_device->m_links_bitmap_to_allocated_mcid.find(links_key);
    if (allocated_iter != m_device->m_links_bitmap_to_allocated_mcid.end()) {
        // found an existing allocated MCID
        const auto& allocated_mcid = allocated_iter->second;
        allocated_mcid->in_use++;
        out_mcid = allocated_mcid->mcid;
        log_debug(HLD, "Already allocated local MCID %d in_use %d", out_mcid, allocated_mcid->in_use);
    } else {
        uint64_t local_mcid;

        out_is_new_allocation = true;

        // no allocated MCID found, allocate a new local MCID
        if (!m_device->m_index_generators.local_mcids.allocate(local_mcid)) {
            log_err(HLD, "Unable to allocate a local MCID");
            return LA_STATUS_ERESOURCE;
        }
        out_mcid = local_mcid;

        // create a new allocated MCID for this set of devices
        auto allocated_mcid = std::make_shared<la_device_impl::mc_allocated_mcid>();
        if (allocated_mcid == NULL) {
            m_device->m_index_generators.local_mcids.release(local_mcid);
            log_err(HLD, "Unable to allocate an allocated MCID structure");
            return LA_STATUS_ERESOURCE;
        }
        allocated_mcid->in_use = 1;
        allocated_mcid->mcid = local_mcid;

        // create the mappings for this allocated MCID
        m_device->m_links_bitmap_to_allocated_mcid[links_key] = allocated_mcid;
        m_device->m_mcid_to_links_bitmap[local_mcid] = links_key;
        log_debug(HLD, "New local MCID %d iallocated in_use %d", out_mcid, allocated_mcid->in_use);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_multicast_group_impl::configure_local_mcid(uint64_t* link_bits)
{
    transaction txn;
    la_multicast_group_gid_t prev_local_mcid = m_local_mcid;
    bool is_new_allocation = false;
    bool is_deleted = false;

    // Note, this processing is doing make-before-break such that an
    // old mapping remains valid until the new one is programmed.

    if (m_local_mcid != NPL_MULTICAST_RESERVED_MCID_TO_FABRIC_SLICE) {
        // there was an existing local MCID allocated, release it
        txn.status = release_local_mcid(m_local_mcid, is_deleted);
        log_debug(HLD,
                  "released local_mcid %d m_gid %d is_del = %d lb[0] = 0x%lx lb [1] = 0x%lx",
                  m_local_mcid,
                  m_gid,
                  is_deleted,
                  link_bits[0],
                  link_bits[1]);
        return_on_error(txn.status);
        txn.on_fail([=]() {
            uint64_t* prev_link_bits = (uint64_t*)m_links_bitmap.byte_array();
            bool is_new_allocation = false;
            (void)allocate_local_mcid(prev_link_bits, m_local_mcid, is_new_allocation);
            log_debug(HLD,
                      "Rollback release for local_mcid %d m_gid %d is_del = %d lb[0] = 0x%lx lb [1] = 0x%lx",
                      m_local_mcid,
                      m_gid,
                      is_deleted,
                      link_bits[0],
                      link_bits[1]);
            m_device->m_mc_smcid_to_local_mcid[m_gid] = m_local_mcid;
        });
        m_local_mcid = NPL_MULTICAST_RESERVED_MCID_TO_FABRIC_SLICE;
        m_device->m_mc_smcid_to_local_mcid.erase(m_gid);
    }

    // only allocate a new MCID if there are links to send to
    if (link_bits[0] || link_bits[1]) {

        // allocate a new local MCID based on the links bitmap
        la_multicast_group_gid_t new_local_mcid;
        txn.status = allocate_local_mcid(link_bits, new_local_mcid, is_new_allocation);
        log_debug(HLD,
                  " Allocated mcid, prev_mcid = %d local_mcid %d m_gid %d is_alloc = %d lb[0] = 0x%lx lb [1] = 0x%lx",
                  prev_local_mcid,
                  new_local_mcid,
                  m_gid,
                  is_new_allocation,
                  link_bits[0],
                  link_bits[1]);
        return_on_error(txn.status);
        txn.on_fail([=]() {
            bool is_deleted = false;
            (void)release_local_mcid(new_local_mcid, is_deleted);
            m_local_mcid = prev_local_mcid;
        });
        m_local_mcid = new_local_mcid;

        if (is_new_allocation) {
            // for new allocations of local MCIDs update the bitmap
            txn.status = set_mc_bitmap(m_local_mcid, link_bits);
            return_on_error(txn.status);
            txn.on_fail([=]() {
                // this is a new allocation so the undo should set to zero
                uint64_t zero[2] = {0};
                (void)set_mc_bitmap(m_local_mcid, zero);
            });
        }

        // update the system to local MCID mapping
        m_device->m_mc_smcid_to_local_mcid[m_gid] = m_local_mcid;
    }

    // update the global to local MCID mapping for this new local MCID
    txn.status = set_global_to_local_mcid_mapping(m_gid, m_local_mcid);
    return_on_error(txn.status);
    txn.on_fail([=]() { (void)set_global_to_local_mcid_mapping(m_gid, prev_local_mcid); });

    // zero the bitmap for the old entry if a new one was allocated
    if (is_deleted && (prev_local_mcid != m_local_mcid)) {
        uint64_t zero[2] = {0};
        // if the old MCID was deleted then invalidate the old bitmap
        txn.status = set_mc_bitmap(prev_local_mcid, zero);
        return_on_error(txn.status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_multicast_group_impl::configure_mc_bitmap()
{
    la_status status;
    bit_vector128_t links_bitmap(0, NUM_FABRIC_PORTS_IN_DEVICE);

    // Set 1's in the indices that match ports which are connected to LCs included in this MC group.
    for (auto device_id : m_devices) {
        for (auto link : m_device->m_device_to_links[device_id]) {
            links_bitmap.set_bit(link, 1);
        }
    }

    if (m_links_bitmap == links_bitmap) {
        uint64_t* link_bits = (uint64_t*)links_bitmap.byte_array();
        log_debug(HLD, "mgid %d link bitmaps are same [%lx %lx]", m_gid, link_bits[0], link_bits[1]);
        // return success if this is the same bitmap to be programmed
        return LA_STATUS_SUCCESS;
    }

    uint64_t* link_bits = (uint64_t*)links_bitmap.byte_array();

    if (m_is_scale_mode_smcid) {
        // multicast scale mode requires configuring a local MCID
        status = configure_local_mcid(link_bits);
        return_on_error(status);
    } else {
        // for 1:1 mapped MCIDs only update the bitmap
        status = set_mc_bitmap(m_local_mcid, link_bits);
        return_on_error(status);
    }
    m_links_bitmap = links_bitmap;

    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_multicast_group_impl::set_mc_bitmap(la_multicast_group_gid_t mcid, uint64_t* link_bits)
{
    const auto& table(m_device->m_tables.mc_fe_links_bmp);
    npl_mc_fe_links_bmp_entry_t* dummy;
    npl_mc_fe_links_bmp_key_t key;
    npl_mc_fe_links_bmp_value_t value;

    value.action = NPL_MC_FE_LINKS_BMP_ACTION_WRITE;

    key.rxpp_pd_fwd_destination_15_0_ = mcid;
    value.payloads.mc_fe_links_bmp_db_result.fe_links_bmp[0] = link_bits[0];
    value.payloads.mc_fe_links_bmp_db_result.fe_links_bmp[1] = link_bits[1];

    la_status status = table->set(key, value, dummy);
    return_on_error(status);

    status = flush_mcid_cache();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_multicast_group_impl::flush_mcid_cache() const
{
    la_status status;
    for (la_slice_id_t sid : m_device->get_used_slices()) {
        status = m_device->flush_rxpdr_mcid_cache(sid);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
