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

#ifndef __LA_INTERFACE_SCHEDULER_IMPL_H__
#define __LA_INTERFACE_SCHEDULER_IMPL_H__

#include "api/system/la_mac_port.h"
#include "api/tm/la_interface_scheduler.h"
#include "hld_types.h"
#include "hld_types_fwd.h"

namespace silicon_one
{

class la_device_impl;
class lld_register;
class lld_register_array_container;

class la_interface_scheduler_impl : public la_interface_scheduler
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    la_interface_scheduler_impl();
    explicit la_interface_scheduler_impl(const la_device_impl_wptr& device,
                                         la_slice_id_t slice_id,
                                         la_ifg_id_t ifg_id,
                                         la_uint_t pif_base,
                                         la_mac_port::port_speed_e speed,
                                         bool is_fabric);
    ~la_interface_scheduler_impl() override;

    // la_interface_scheduler API-s
    la_status get_transmit_cir(la_rate_t& out_rate) const override;
    la_status set_transmit_cir(la_rate_t rate) override;

    la_status get_credit_cir(la_rate_t& out_rate) const override;
    la_status set_credit_cir(la_rate_t rate) override;

    la_status get_transmit_eir_or_pir(la_rate_t& out_rate, bool& out_is_eir) const override;
    la_status set_transmit_eir_or_pir(la_rate_t rate, bool is_eir) override;

    la_status get_credit_eir_or_pir(la_rate_t& out_rate, bool& out_is_eir) const override;
    la_status set_credit_eir_or_pir(la_rate_t rate, bool is_eir) override;

    la_status get_cir_weight(la_wfq_weight_t& out_weight) const override;
    la_status set_cir_weight(la_wfq_weight_t weight) override;
    la_status get_eir_weight(la_wfq_weight_t& out_weight) const override;
    la_status set_eir_weight(la_wfq_weight_t weight) override;

    la_mac_port::port_speed_e get_port_speed() const;

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // la_interface_scheduler_impl API-s
    la_status initialize(la_object_id_t oid);
    la_status destroy();

    la_status configure_rx_congestion();

    la_status set_oqs_enabled(bool enabled);

    // Configure seperate OQs for PFC-enabled TC-s
    la_status set_pfc_oq_profiles(la_uint8_t tc_bitmap);
    la_status get_pfc_oq_profiles(la_uint8_t& out_tc_bitmap);

    // TX CGM profile, depends on port speed: 10G, 25G, 40, 50, 100, 200, 400, 800
    static const std::map<la_mac_port::port_speed_e, la_uint_t> TX_CGM_PROFILE_MAP;
    static const std::map<la_mac_port::port_speed_e, la_uint_t> TX_CGM_PROFILE_MAP_PFC;

    la_status set_pfc(bool pfc_on);

    la_status reset_fdoq_credits();

private:
    la_status initialize_reorder();
    la_status initialize_pfc_mapping();
    la_status initialize_txcgm();

    enum {
        IFSE_EIR_SHAPE_MODE_BASE = 124, // Base of field IfseEirShaperMode of register IfseGeneralConfiguration
    };

    // Information for TpseOqpgMappingConfigutration register
    enum {
        TM_PORT_COUNT = 20,    ///< Number of TM ports.
        BITS_PER_PORT = 17,    ///< Number of bits for each port.
        REG_SIZE_IN_BITS = 340 ///< Number of bits in element.
    };

    enum {
        MANTISSA_SIZE = 5, ///< Mantissa size in bits
    };

    // Device this transmit scheduler belongs to
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    // Scheduler slice ID
    la_slice_id_t m_slice_id;

    // Scheduler interface group ID
    la_ifg_id_t m_ifg_id;

    // SCH or SCH_FAB registers and memories
    lld_register_scptr m_sch_ifse_general_configuration;
    lld_register_array_sptr m_sch_ifse_wfq_cir_weights;
    lld_register_array_sptr m_sch_ifse_wfq_eir_weights;
    lld_register_array_sptr m_sch_ifse_cir_shaper_rate_configuration;
    lld_register_array_sptr m_sch_ifse_pir_shaper_configuration;

    template <class _sch>
    void initialize_sch_references(_sch& sch)
    {
        m_sch_ifse_general_configuration = sch->ifse_general_configuration;
        m_sch_ifse_wfq_cir_weights = sch->ifse_wfq_cir_weights;
        m_sch_ifse_wfq_eir_weights = sch->ifse_wfq_eir_weights;
        m_sch_ifse_cir_shaper_rate_configuration = sch->ifse_cir_shaper_rate_configuration;
        m_sch_ifse_pir_shaper_configuration = sch->ifse_pir_shaper_configuration;
    }

    // Scheduler first PIF (within the IFG)
    la_uint_t m_pif_base;

    // Scheduler first PIF (within the slice)
    la_uint_t m_slice_pif_base;

    // Scheduler TM port ID (within the IFG)
    la_uint_t m_tm_port_id;

    // Scheduler slice interface ID (unique interface ID within the slice)
    la_uint_t m_slice_tm_port_id;

    // Interface speed
    la_mac_port::port_speed_e m_speed;

    bool m_is_fabric;

    bool m_pfc;

    // TC-s that should use PFC specific OQ profile
    la_uint8_t m_pfc_tc_bitmap;

}; // class la_interface_scheduler_impl

} // namespace silicon_one

#endif // __LA_INTERFACE_SCHEDULER_IMPL_H__
