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

#ifndef __SLICE_ID_MANAGER_H__
#define __SLICE_ID_MANAGER_H__

#include "../device_context/la_slice_mapper_base.h"
#include "api/types/la_common_types.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "system/slice_manager_smart_ptr_base.h"
#include <memory>
#include <vector>

namespace silicon_one
{

class la_slice_mapper_base;

enum class fabric_slices_type_e {
    // Slices that are usualy used for fabric in linecard mode
    LINECARD_FABRIC,
    LINECARD_NON_FABRIC,
    // Slices with specific hardware changes for enhanced preformance in fabric mode
    HW_FABRIC,
    HW_NON_FABRIC
};

class la_device;
/// This class is responsible for managing the valid (enabled) slice Ids
/// It implements all slice_id, slice_pair_id, and ifg_id related functionality.
/// Any related function should be called directly from it, or from la_device, hld_utils, or ifg_use_count -
/// all of which should simply call functions of this class.
/// This class has one instance per device, and you can get it from the la_device.
class slice_id_manager_base
{
    // FOR SERIALIZATION PURPOSES//
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    //////////////////////////////
public:
    slice_id_manager_base();
    virtual ~slice_id_manager_base();

    /// @brief sets all the lists and data of enabled slices. Based on the device properties. must be called.
    /// @param[in]    dev            the device of this slice_id_manager, should be the same one used in get_instance
    virtual void initialize(const la_device_impl_base_wptr& dev);

    /// @brief the total number of slices that are physicly found on device
    virtual size_t num_slices_per_device() const;

    /// @brief the total number of slice pairs that are physicly found on device
    virtual size_t num_slice_pairs_per_device() const;

    /// @brief the total number of slices that are physicly found on device
    virtual size_t maximal_num_ifg_per_slice() const;

    /// @brief the first slice used as fabric in Linecard Mode
    la_slice_id_t first_possible_fabric_slice_in_lc() const;

    /// @brief the total number of slices that are not disabled
    size_t num_enabled_slices() const;

    /// @brief a vector of indices of all the slices that are not diabled.
    /// each index is <num_slices_per_device()
    const la_slice_id_vec_t& get_used_slices_internal() const;

    /// @brief a vector of indices of all the slices in that pair that are not diabled.
    la_slice_id_vec_t get_active_slices_in_pair(la_slice_pair_id_t pair) const;

    /// @brief a vector of logical indices of all the slice_pirs that has at least on slice that is not diabled.
    /// each index is smaller than num_slices_per_device()/2
    const la_slice_pair_id_vec_t& get_used_slice_pairs_internal() const;

    /// @brief a vector of indices of all the slices that are not diabled.
    /// bascily, each index is <num_enabled_slices()/2
    const la_slice_id_vec_t& get_used_logical_slices() const;

    /// @brief a vector of logical indices of all the slice_pirs that has at least on slice that is not diabled.
    /// bascily, each index is <num_enabled_slice_pairs()/2
    const la_slice_pair_id_vec_t& get_used_logical_slice_pairs() const;

    /// @brief a vector of slice_ifg of all the IFGs found on slices that are not diabled.
    const slice_ifg_vec_t& get_used_ifgs() const;

    /// @brief a vector of slice_ifg of all the ifgs found on slices that are not diabled.
    slice_ifg_vec_t get_ifgs_by_mode(la_device_impl_base_wcptr device, la_slice_mode_e mode) const;

    /// @brief a vector of indices of all the ifgs found on the given slice, that are not diabled.
    /// the indices start from i=0 for ifg=0, i=1 to ifg=1...
    ifg_index_vec_t get_slice_used_ifgs(la_slice_id_t slice) const;

    /// @brief a vector of all the physical slices that are on the device, even if some of them are diabled.
    /// can be called before initialization
    /// should only be used if accessing all slices before the slice_id_manager is initialized
    la_slice_id_vec_t get_all_possible_slices() const;

    /// @brief a vector of all the physical slice_pairs that are on the device, even if some of them are diabled.
    /// can be called before initialization
    /// should only be used if accessing all slice_pairs before the slice_id_manager is initialized
    la_slice_pair_id_vec_t get_all_possible_slice_pairs() const;

    /// @brief a vector of slice_ifg of all the IFGs that may be found on the device, even if some of them are diabled.
    /// can be called before initialization
    /// should only be used if accessing all IFGs before the slice_id_manager is initialized
    slice_ifg_vec_t get_all_possible_ifgs() const;

    /// @brief a vector of array indices of all the IFGs found on slices that are not diabled.
    /// the indices start from i=0 for slice=0 ifg=0, i=1 to slice=0 ifg=1... running on alll slices, including disabled slices.
    ifg_index_vec_t get_used_ifgs_gifg_id() const;

    /// @brief given an IFG by slice_id and ifg number, gives its position in an all IFGs array
    /// arry structure as described for get_used_ifgs_gifg_id()
    virtual size_t slice_ifg_2_global_ifg(la_slice_id_t slice, la_ifg_id_t ifg) const;

    /// @brief given an IFG by slice_id and ifg number, gives its position in an all IFGs array
    /// arry structure as described for get_used_ifgs_gifg_id()
    virtual size_t slice_ifg_2_global_ifg(la_slice_ifg ifg) const;

    /// @brief given an IFG by position in array (as described by get_used_ifgs_gifg_id)
    /// @brief return slice_id and ifg number on that slice
    virtual la_slice_ifg global_ifg_2_slice_ifg(size_t gifg) const;

    /// @brief is slice id points to a valid slice
    ///
    /// @retval     LA_STATUS_SUCCESS   slice is valid
    /// @retval     LA_STATUS_EOUTOFRANGE  slice id is out-of-range
    /// @retval     LA_STATUS_EINVAL slice id exists, but slice is disabled
    /// @retval     false       if slice is disabled, or not existing
    la_status is_slice_valid(la_slice_id_t sid) const;

    /// @brief is slice_pair id points to a slice_pair with at least one valid slice
    ///
    /// @retval     LA_STATUS_SUCCESS   slice_pair is valid
    /// @retval     LA_STATUS_EOUTOFRANGE  slice_pair id is out-of-range
    /// @retval     LA_STATUS_EINVAL slice_pair id exists, but pair is disabled (i.e. both slices disabled)
    la_status is_slice_pair_valid(la_slice_pair_id_t sid) const;

    /// @brief is la_slice_ifg points to an enabled IFG
    ///
    /// @retval     LA_STATUS_SUCCESS       ifg is enabled
    /// @retval     LA_STATUS_EOUTOFRANGE   ifg.slice id is out-of-range
    /// @retval     LA_STATUS_EINVAL        ifg.slice id exists, but slice is disabled
    la_status is_slice_ifg_valid(la_slice_ifg ifg) const;

    /// @brief is_slice_ifg_valid( la_slice_ifg ifg) overload
    la_status is_slice_ifg_valid(la_slice_id_t slice, size_t ifg_id) const;

    /// @brief checks for an array of IFGs which are valid.
    ///
    /// @param[in]    ifg_vect            a vector of IFG ids to be tested.
    ///
    /// @retval     a sub-vector of ifg_vect, contaning all IFG ids in ifg_vect for which is_slice_ifg_valid() returns success
    slice_ifg_vec_t get_all_valid_ifgs(const slice_ifg_vec_t& ifg_vect) const;

    /// @brief a vector of indices of all the slices that has the specified fabric charestaristic (and are not disabled).
    /// @param[in]    fabric_slices_type_e            which slices to return, fubric or non-fabric.
    const la_slice_id_vec_t& get_slices_by_fabric_type(fabric_slices_type_e type) const;

    bool is_fabric_type_slice(la_slice_id_t sid, fabric_slices_type_e type) const;

    la_slice_id_t get_an_active_slice_id(la_slice_id_t def_sid) const;

    /// mapping functions
    virtual la_slice_pair_id_t map_slice_pair(la_slice_pair_id_t id) const;
    virtual la_slice_pair_id_t map_back_slice_pair(la_slice_pair_id_t id) const;

    virtual la_slice_id_t map_slice(la_slice_id_t id) const;
    virtual la_slice_id_t map_back_slice(la_slice_id_t id) const;

    virtual la_status map_slice_ifg(la_slice_ifg& ifg) const;
    virtual la_status map_back_slice_ifg(la_slice_ifg& ifg) const;

    virtual la_status map_serdices(la_slice_serdices& map_this) const;
    virtual la_status map_back_serdices(la_slice_serdices& map_this) const;

    virtual la_status map_pif(la_slice_pif& map_this) const;
    virtual la_status map_back_pif(la_slice_pif& map_this) const;

    const std::shared_ptr<la_slice_mapper_base>& get_slice_mapper() const;

    // la_status read_mapping_file(std::string file_name);
    virtual la_slice_ifg get_npu_host_port_ifg() const;

protected:
    la_slice_id_t m_FIRST_HW_FABRIC_SLICE;
    la_slice_id_t m_first_possible_fabric_slice;

    la_slice_id_vec_t m_enabled_slices;
    la_slice_pair_id_vec_t m_enabled_slice_pairs;
    la_slice_id_vec_t m_enabled_slices_logical;
    la_slice_pair_id_vec_t m_enabled_slice_pairs_logical;

    slice_ifg_vec_t m_enabled_ifgs;
    std::vector<bool> m_is_gifg_enabled;
    bool m_initialized;

    la_slice_id_vec_t m_designated_fabric_slices;
    la_slice_id_vec_t m_designated_nonfabric_slices;
    la_slice_id_vec_t m_fabric_hw_slices;
    la_slice_id_vec_t m_nonfabric_hw_slices;

    std::shared_ptr<la_slice_mapper_base> m_slice_mapper;
};

} // namespace silicon_one

#endif // __SLICE_ID_MANAGER_H__
