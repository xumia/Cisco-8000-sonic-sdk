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

#ifndef __HLD_TYPES_H__
#define __HLD_TYPES_H__

#include <bitset>
#include <chrono>
#include <functional>
#include <map>
#include <set>
#include <tuple>

#include "api/system/la_mac_port.h"
#include "api/types/la_acl_types.h"
#include "api/types/la_common_types.h"
#include "api/types/la_ethernet_types.h"
#include "api/types/la_ip_types.h"
#include "api/types/la_system_types.h"
#include "api/types/la_tm_types.h"
#include "nplapi/npl_enums.h"

/// @file
/// @brief HLD Type definitions.
///
/// Defines types and enumerations used by the HLD.

namespace silicon_one
{
class la_object;

/// @brief Device global constants.
enum {
    ASIC_MAX_SLICES_PER_DEVICE_NUM = 6,
    NUM_SLICES_WITH_NPUH_PER_DEVICE = ASIC_MAX_SLICES_PER_DEVICE_NUM + 1,
    NUM_NP_ENGINES_PER_SLICE = 8,
    NUM_SLICE_PAIRS_PER_DEVICE = ASIC_MAX_SLICES_PER_DEVICE_NUM / 2,
    NUM_IFGS_PER_SLICE = 2,
    NUM_IFGS_PER_DEVICE = ASIC_MAX_SLICES_PER_DEVICE_NUM * NUM_IFGS_PER_SLICE,
    NUM_IFGS_PER_SYNCE_GROUP = 3,
    NUM_SERDES_PER_IFG = 18,
    NUM_PIF_PER_IFG = 18,
    MAX_NUM_SERDES_PER_IFG = 24, ///< Maximum SerDes's per IFG in all Devices
    MAX_NUM_PIF_PER_IFG = 24,
    NUM_INTERNAL_IFCS_PER_IFG = 2, ///< Number of internal interfaces per IFG: recycle and internal host
    HOST_SERDES_ID = 24,
    RECYCLE_SERDES_ID = 25,
    HOST_PIF_ID = 24,
    RECYCLE_PIF_ID = 25,
    NUM_OQ_PER_PIF = 8,
    NUM_OQ_PER_IFG = NUM_OQ_PER_PIF * MAX_NUM_PIF_PER_IFG + NUM_OQ_PER_PIF /* Rcy */ + NUM_OQ_PER_PIF /* host */,
    TXPDR_NUM_OQS = 2, ///< TXPDR has 2 OQs: HP and LP.
    FIRST_LP_QUEUING_OQSE = NUM_OQ_PER_IFG + TXPDR_NUM_OQS,
    ENHANCED_FABRIC_IFG_SERDES_ID = 20,
    NUM_ENHANCED_FABRIC_IFG_SERDES = 2, ///< In an "enhanced" IFG, this is the number of borrowed serdeses
    NUM_TC_CLASSES = 8,
    NUM_CGM_HBM_POOLS = 2,                                        ///< Num of HBM partitions.
    MAX_PORT_EXTENDER_VID = 255,                                  ///< Maximal VLAN ID in port-extented tag.
    MAX_PORT_EXTENDER_VIDS_PER_SLICE = MAX_PORT_EXTENDER_VID + 1, ///< Maximum number of extended vids inside a slice.
    MAX_PORT_EXTENDER_VIDS_PER_PIF = 4,

    NUM_RESOLUTION_STAGES = 4,
    NUM_PBTS_LEVELS = 4,

    NUM_HBM_INTERFACES = 2, ///< Number of HBM interfaces.
    NUM_HBM_CHANNELS = 8,   ///< Number of HBM channels.
    HBM_MODEL_B_DIE = 0x21,
    HBM_MODEL_X_DIE = 0x40,
    NUM_HBM_DRAM_BUFFER_CELLS = 32, ///< Number of cells in HBM DRAM buffer

    NUM_VOQ_SLICE_COUNTER_REGIONS = 4, ///< Number of VOQ slice counters regions - single counter for the whole VOQ region in slice
    NUM_SERDES_PER_FABRIC_PORT = 2,
    NUM_OQ_PER_EXTENDED_PORT = 2,

    NUM_STATISTICAL_METER_BANKS = 4,

    NUM_ACL_TCAM_POOLS = 2,         ///< Number of ACL TCAM pools
    NUM_RTF_CONF_SETS = 256,        ///< Number of RTF configuration sets
    NUM_ACL_COMMAND_PROFILES = 4,   ///  Number of ACL command profiles
    NUM_ACL_GROUP_ACLS = 4,         ///  Number of ACLs in acl group
    NUM_UDK_TABLES_PER_DEVICE = 18, /// Number of UDK tables

    /// Serdes ID number of the lended serdes on the lender IFG in LC_56_FABRIC_PORT_MODE
    IFG_LENDED_SERDES_ID = NUM_SERDES_PER_IFG - NUM_ENHANCED_FABRIC_IFG_SERDES, // = 16

    /// Serdes ID number of the borrowed serdes on the borrower IFG in LC_56_FABRIC_PORT_MODE
    IFG_BORROWED_SERDES_ID = 19,

    /// Number of fabric ports in "normal" IFG, i.e., in LC_56_FABRIC_PORT_MODE this IFG does not get an extra fabric port
    NUM_FABRIC_PORTS_IN_NORMAL_IFG = NUM_SERDES_PER_IFG / NUM_SERDES_PER_FABRIC_PORT,

    /// Number of fabric ports in "enhanced" IFG, i.e., in LC_56_FABRIC_PORT_MODE this IFG gets an extra fabric port.
    NUM_FABRIC_PORTS_IN_ENHANCED_IFG = (NUM_SERDES_PER_IFG + NUM_ENHANCED_FABRIC_IFG_SERDES) / NUM_SERDES_PER_FABRIC_PORT,

    /// Number of fabric ports in Slice
    NUM_FABRIC_PORTS_IN_SLICE = 18,

    /// The in-IFG fabric port number of the borrowed port
    IFG_BORROWED_FABRIC_PORT_NUM = NUM_FABRIC_PORTS_IN_ENHANCED_IFG - 1, // = 9

    /// Maximum number of supported fabric ports in device. It is reached only in FE device
    NUM_FABRIC_PORTS_IN_DEVICE = ASIC_MAX_SLICES_PER_DEVICE_NUM * NUM_FABRIC_PORTS_IN_SLICE,

    /// The maximal number of fabric ports in a slice. Normally it would be NUM_FABRIC_PORTS_IN_NORMAL_IFG*2, but in
    /// LC_56_FABRIC_PORT_MODE some slices have an "enhanced" IFG.
    MAX_FABRIC_PORTS_IN_SLICE = NUM_FABRIC_PORTS_IN_NORMAL_IFG + NUM_FABRIC_PORTS_IN_ENHANCED_IFG,

    /// The maximum number of fabric ports in a Linecard device. There is one "normal" slice and two "enhanced" slices.
    MAX_FABRIC_PORTS_IN_LINECARD_DEVICE = (NUM_FABRIC_PORTS_IN_NORMAL_IFG + NUM_FABRIC_PORTS_IN_NORMAL_IFG)
                                          + (NUM_FABRIC_PORTS_IN_NORMAL_IFG + NUM_FABRIC_PORTS_IN_ENHANCED_IFG) * 2, // = 56

    // Maximum number of link bundles in FE device. Each bundle maintains at least two links.
    MAX_LINK_BUNDLES_IN_FE_DEVICE = NUM_FABRIC_PORTS_IN_DEVICE / 2,

    // Maximum number of links in one bundle.
    MAX_LINKS_IN_BUNDLE = 4,

    ///< In Pacfic, on the HW level, slices 0..3 have different resources than slices 4..5, and are regarded as network-type.
    LAST_NETWORK_TYPE_SLICE = 4,

    ///< There are three PLB fabric contexts, UC_H, UC_L, MC. Assume that MC is the highest.
    NUM_PLB_FABRIC_CONTEXTS = NPL_FABRIC_CONTEXT_PLB_MC + 1,

    ///< On an RX-Fabric slice, per PLB fabric context, there's a MS-VOQ per RX-Fabric port * TX-Slice
    MAX_NUM_OF_MSVOQS_PER_FABRIC_CONTEXT_PER_SLICE = MAX_FABRIC_PORTS_IN_SLICE * ASIC_MAX_SLICES_PER_DEVICE_NUM,

    ///< On an RX-Fabric slice, there's a MS-VOQ per RX-Fabric port * TX-Slice * PLB fabric context
    MAX_NUM_OF_MSVOQS_PER_SLICE = MAX_NUM_OF_MSVOQS_PER_FABRIC_CONTEXT_PER_SLICE * NUM_PLB_FABRIC_CONTEXTS,

    DEFAULT_DEVICE_FREQUENCY = 1200000,
    /// Frequency used for time_offset register value calculation.
    MAX_DEVICE_FREQUENCY = 1400000,
    MIN_DEVICE_FREQUENCY = 900000,

    DEFAULT_TCK_FREQUENCY = 5,
    MAX_TCK_FREQUENCY = 10,
    MIN_TCK_FREQUENCY = 1,

    DEFAULT_MAX_COUNTER_THRESHOLD = 1 << 30,

    NUM_OF_OOBI_SHAPERS = (NUM_SERDES_PER_IFG / 2),
    LENDED_IFG_LAST_SHAPER_ID = (IFG_LENDED_SERDES_ID / 2), // = 8
    DEFAULT_OOB_SHAPER_BURST_SIZE = 6,

    DEFAULT_RESET_INTERRUPT_COUNTERS_INTERVAL_SECONDS = 24 * 60 * 60,

    // VOQ range reserved for multicast.
    // All the VSCs of all destination slices must be in the given range.
    // @see silicon_one::la_device::set_egress_multicast_slice_replication_voq_set.
    SA_MC_VSC_RANGE_START = 0,
    SA_MC_VSC_RANGE_END = NATIVE_VOQ_SET_SIZE * ASIC_MAX_SLICES_PER_DEVICE_NUM - 1, // 95
    // In linecard mode, the network slices each get a VSC range in order to
    // multicast to other network slices as needed by multicast scale.
    LC_NETWORK_VSC_RANGE_START = 0,
    LC_NETWORK_VSC_RANGE_END = NATIVE_VOQ_SET_SIZE * 3 - 1, // 47
    // In linecard mode, the fabric slice uses a single VSC range.
    FABRIC_MC_VSC_RANGE_START = LC_NETWORK_VSC_RANGE_END + 1,                          // 48
    FABRIC_MC_VSC_RANGE_END = FABRIC_MC_VSC_RANGE_START + NATIVE_VOQ_SET_SIZE * 3 - 1, // 97

    // The MC VSC ranges of SA and fabric must not overlap, this will cause an undefined behavior of the device.
    SA_MC_VSC_IN_LC = FABRIC_MC_VSC_RANGE_END + 1,
    FABRIC_MC_VSC_IN_SA = SA_MC_VSC_RANGE_END + 1,

    LC_LAST_RESERVED_VSC = FABRIC_MC_VSC_RANGE_END, // 47
    SA_LAST_RESERVED_VSC = SA_MC_VSC_RANGE_END,     // 95

    // IFG buffer allocation constants
    TX_FIFO_LINES_MAIN_PIF = (1584 / 24),

    SYNCE_REF_CLOCK_PER_GROUP = 2,
    SYNCE_REF_CLOCK_MAX_PIN = 4,

    // MC-COPY-ID prefixes
    L2_AC_MC_COPY_ID_PREFIX_6b = 0x0, // 0b000000
    L2_AC_MC_COPY_ID_MASK_6b = 0x20,  // 0b100000

    L3_AC_MC_COPY_ID_PREFIX_6b = 0x30, // 0b110000
    L3_AC_MC_COPY_ID_MASK_6b = 0x30,   // 0b110000

    CUD_MAP_PREFIX_6b = 0x20, // 0b100000
    CUD_MAP_MASK_6b = 0x38,   // 0b111000

    MCG_COUNTER_MC_COPY_ID_PREFIX_6b = 0x28, // 0b101000
    MCG_COUNTER_MC_COPY_ID_MASK_6b = 0x38,   // 0b111000
};

/// @brief Vector of ifgs.
using slice_ifg_vec_t = std::vector<la_slice_ifg>;
using ifg_index_vec_t = std::vector<size_t>;

/// Protection monitor ID.
typedef la_uint_t la_protection_monitor_gid_t;
static const la_protection_monitor_gid_t LA_PROTECTION_MONITOR_GID_INVALID = (la_protection_monitor_gid_t)(-1);

/// @brief Invalid GID definitions
static const la_spa_port_gid_t LA_SPA_PORT_GID_INVALID = (la_spa_port_gid_t)(-1);

/// @brief Invalid CLOS direction
static constexpr la_clos_direction_e CLOS_DIRECTION_INVALID = (la_clos_direction_e)(-1);

/// @brief ACL ID type.
typedef size_t la_acl_id_t;

/// @BVN PROFILE 4 bits
typedef size_t la_bvn_profile_t;

/// @brief Maps VSC_ID and VSC-attached ingress VOQ details.
using la_vsc_voq_map_t = std::map<la_vsc_gid_t, la_vsc_oq>;

/// @brief Resolution steps type.
enum resolution_step_e {
    RESOLUTION_STEP_FIRST = 0,
    RESOLUTION_STEP_FORWARD_L2 = RESOLUTION_STEP_FIRST,
    RESOLUTION_STEP_FORWARD_L3,
    RESOLUTION_STEP_FORWARD_MPLS,
    /* GB STEPS */
    RESOLUTION_STEP_STAGE0_PBTS_GROUP,
    RESOLUTION_STEP_FEC,
    RESOLUTION_STEP_STAGE0_ECMP,
    RESOLUTION_STEP_STAGE0_CE_PTR,
    RESOLUTION_STEP_STAGE0_L2_LP,
    RESOLUTION_STEP_STAGE0_PROTECTION,

    RESOLUTION_STEP_STAGE1_ECMP,
    RESOLUTION_STEP_STAGE1_L2_DLPA,
    RESOLUTION_STEP_STAGE1_PROTECTION,

    RESOLUTION_STEP_STAGE2_ECMP,
    RESOLUTION_STEP_STAGE2_NH,

    RESOLUTION_STEP_STAGE3_ECMP,
    RESOLUTION_STEP_STAGE3_DSPA,

    RESOLUTION_STEP_RETURN,
    RESOLUTION_STEP_LAST = RESOLUTION_STEP_RETURN,
    RESOLUTION_STEP_INVALID,

    /* Legacy pacific */
    RESOLUTION_STEP_NATIVE_L3_LP,
    RESOLUTION_STEP_NATIVE_FRR,
    RESOLUTION_STEP_PORT_NPP_PROTECTION
};

static constexpr unsigned RESOLUTION_INVALID_STAGE = 0xff;

struct destination_id {
    destination_id() : val((1 << 20) - 1)
    {
    }

    explicit destination_id(uint64_t init_val)
    {
        val = init_val;
    }

    bool operator==(const destination_id& other) const
    {
        return (val == other.val);
    }

    la_uint32_t val : 20;
};
static const destination_id DESTINATION_ID_INVALID = (const destination_id)-1;

struct lpm_destination_id {
    lpm_destination_id() : val((1 << 20) - 1)
    {
    }

    explicit lpm_destination_id(uint64_t init_val)
    {
        val = init_val;
    }

    bool operator==(const lpm_destination_id& other) const
    {
        return (val == other.val);
    }

    la_uint32_t val : 20;
};
static const lpm_destination_id LPM_DESTINATION_ID_INVALID = (const lpm_destination_id)-1;

struct resolution_table_index {
    resolution_table_index() : val(-1)
    {
    }

    explicit resolution_table_index(uint64_t init_val)
    {
        val = init_val;
    }

    bool operator==(const resolution_table_index& other) const
    {
        return (val == other.val);
    }

    uint64_t val;
};
static const resolution_table_index RESOLUTION_TABLE_INDEX_INVALID = (const resolution_table_index)-1;

/// @brief object attributes that dependent objects need to be notified about
enum class attribute_management_op : la_uint64_t {
    VRF_FALLBACK_CHANGED = (1 << 0),
    EGRESS_VLAN_TAG_CHANGED = (1 << 1),
    SPA_MEMBERSHIP_CHANGED = (1 << 2),
    ASBR_LSP_PROPERTY_CHANGED = (1 << 3),
    TE_TUNNEL_DESTINATION_CHANGED = (1 << 4),
    MAC_PORT_LINK_STATE_CHANGED = (1 << 5),
    VOQ_CHANGED = (1 << 6),
    MAC_MOVED = (1 << 7),
    L3_AC_PORT_MAC_CHANGED = (1 << 8),
    L3_PROT_GROUP_DESTINATION_CHANGED = (1 << 9),
    PORT_SPEED_CHANGED = (1 << 10),
    MIRROR_COMMAND_ATTR_UPDATE = (1 << 11),
    EGRESS_SFLOW_CHANGED = (1 << 12),
    L3_PORT_ATTR_CHANGED = (1 << 13),
    L2_DLP_ATTRIB_CHANGED = (1 << 14),
    MULTICAST_PROTECTION_GROUP_CHANGED = (1 << 15),
    SERVICE_MAPPING_TYPE_CHANGED = (1 << 16),
    PWE_L3_DESTINATION_ATTRIB_CHANGED = (1 << 17),
    REMOTE_VOQ_CHANGED = (1 << 18),
    ACL_GROUP_CHANGED = (1 << 19),
    MCG_MEMBER_LIST_CHANGED = (1 << 20),
};

enum class ifg_management_op { IFG_ADD, IFG_REMOVE };

// Details of a SPA membership change
struct spa_membership_change_details {
    const la_l2_service_port* l2_ac_port;
    const la_l3_ac_port* l3_ac_port;
    const la_system_port* sys_port;
    bool is_added; // True if the system port is added, false if it is removed
};

// Details of a multicast protection group update
struct multicast_protection_group_change_details {
    const la_next_hop* primary_dest;
    const la_system_port* primary_sys_port;
    const la_next_hop* backup_dest;
    const la_system_port* backup_sys_port;
    const la_multicast_protection_monitor* monitor;
};

// Details of mcg member list change event
struct mcg_member_list_change_details {
    bool slice_added;
    la_slice_id_t slice;
    const la_l3_port* l3_port;
};

// Details of attribute-changes notifications
struct attribute_management_details {
    attribute_management_op op;
    union {
        spa_membership_change_details spa;
        const la_meter_profile* meter_profile;
        const la_l3_destination* l3_dest;
        const la_l3_port* l3_port;
        bool is_mac_port_link_state_up;
        bool txcgm_oqs_enable; // True if oqs to be enabled, false if oqs to be disabled
        la_mac_addr_t mac_addr;
        la_mac_port::port_speed_e mac_port_speed;
        la_acl_packet_format_e packet_format;
        multicast_protection_group_change_details mcg_change;
        mcg_member_list_change_details mcg_slice_update;
    };
};

using la_amd_undo_callback_funct_t = std::function<attribute_management_details(attribute_management_details)>;
/// @brief Manage all dependency operations
struct dependency_management_op {
    enum class management_type_e { IFG_MANAGEMENT = 0, ATTRIBUTE_MANAGEMENT } type_e;

    union {
        struct {
            ifg_management_op ifg_op;
            la_slice_ifg ifg;
        } ifg_management;

        attribute_management_details attribute_management;
    } action;

    const la_object* dependee;
    la_amd_undo_callback_funct_t undo;
};

/// Interface for classes that participate in dependency management
class dependency_listener
{
public:
    virtual la_status notify_change(dependency_management_op op) = 0;

protected:
    virtual ~dependency_listener() = default;
};

/// @brief Counter related constants.
enum counter_direction_e {
    COUNTER_DIRECTION_INGRESS = 0,
    COUNTER_DIRECTION_EGRESS = 1,
    COUNTER_DIRECTION_NUM = 2,
    COUNTER_DIRECTION_INVALID,
};

// Types of counter users
enum counter_user_type_e {
    COUNTER_USER_TYPE_QOS = 0,
    COUNTER_USER_TYPE_DROP,
    COUNTER_USER_TYPE_SEC_ACE,
    COUNTER_USER_TYPE_TRAP,
    COUNTER_USER_TYPE_L2_AC_PORT,
    COUNTER_USER_TYPE_L3_AC_PORT,
    COUNTER_USER_TYPE_TUNNEL,
    COUNTER_USER_TYPE_SVI_OR_ADJACENCY,
    COUNTER_USER_TYPE_VOQ,
    COUNTER_USER_TYPE_METER,
    COUNTER_USER_TYPE_MPLS_NH,
    COUNTER_USER_TYPE_BFD,
    COUNTER_USER_TYPE_ERSPAN,
    COUNTER_USER_TYPE_L2_MIRROR,
    COUNTER_USER_TYPE_MPLS_DECAP,
    COUNTER_USER_TYPE_MPLS_GLOBAL,
    COUNTER_USER_TYPE_VNI,
    COUNTER_USER_TYPE_MCG,
    COUNTER_USER_TYPE_SR_DM,
    COUNTER_USER_TYPE_SECURITY_GROUP_CELL,
    COUNTER_USER_TYPE_L2_PWE_PORT,
    COUNTER_USER_TYPE_LAST,
    COUNTER_USER_TYPE_NUM = COUNTER_USER_TYPE_LAST,
};

// bitset of counter users.
using counter_user_group_bitset = std::bitset<COUNTER_USER_TYPE_NUM>;

// vector of counter users.
using counter_user_group_vec = std::vector<counter_user_type_e>;

/// @brief Expected size of counter-sets
enum {
    PER_PCP_COUNTER_SET_SIZE = 8,
    PER_QOS_TC_SET_SIZE = 32,
    PER_L3_PROTOCOL_SET_SIZE = (size_t)la_l3_protocol_e::LAST,
    PER_PACKET_TYPE_COUNTER_SET_SIZE = (size_t)la_rate_limiters_packet_type_e::LAST,
};

/// @brief QoS field values' prefix for QoS tag mappings.
enum {
    PCPDEI_KEY_PREFIX = 0x40,
    DSCP_KEY_PREFIX = 0x00,
    MPLS_TC_KEY_PREFIX = 0x58,
};

/// @brief QoS fields related constants
enum {
    MAX_IP_DSCP_VALUE = (1 << 6),
    MAX_VLAN_PCPDEI_VALUE = (1 << 4),
    MAX_MPLS_TC_VALUE = (1 << 3),
};

/// @brief NH-type related constants used in resolution NPL
enum class npl_nh_type_e {
    NPL_NH_TYPE_GLEAN = ((1 << 13) | (1 << 0)),
    NPL_NH_TYPE_DROP = ((1 << 13) | (1 << 1)),
    NPL_NH_TYPE_NULL = ((1 << 13) | (1 << 2)),
    NPL_NH_TYPE_USER_TRAP1 = ((1 << 13) | (1 << 3)),
    NPL_NH_TYPE_USER_TRAP2 = ((1 << 13) | (1 << 4)),
};

/// @brief Device modes
enum class device_mode_e {
    INVALID,
    STANDALONE,
    LINECARD,
    FABRIC_ELEMENT,
};

/// @brief Device mode numbers as documented in frm_db.lbr > DeviceConfigReg > DeviceType
enum class frm_device_config_mode_e {
    SA = 0,   // Standalone (engine is inactive)
    LC = 1,   // Line card
    FE2 = 2,  // FE2 fabric mode
    FE13 = 3, // FE13 fabric mode
    TOR = 4,
};

/// @brief Device mode numbers as documented in fte_db.lbr > DeviceConfigReg > DeviceType
enum class fte_device_config_mode_e {
    SA = 0,   // Standalone (engine is inactive)
    LC = 1,   // Line card
    FE2 = 2,  // FE2 fabric mode
    FE13 = 3, // FE13 fabric mode
};

enum class device_property_type_e {
    UNKNOWN,
    BOOLEAN,
    INTEGER,
    STRING,
};

static inline device_property_type_e
get_device_property_type(la_device_property_e p)
{
    if (p >= la_device_property_e::FIRST_BOOLEAN_PROPERTY && p <= la_device_property_e::LAST_BOOLEAN_PROPERTY) {
        return device_property_type_e::BOOLEAN;
    }
    if (p >= la_device_property_e::FIRST_INTEGER_PROPERTY && p <= la_device_property_e::LAST_INTEGER_PROPERTY) {
        return device_property_type_e::INTEGER;
    }
    if (p >= la_device_property_e::FIRST_STRING_PROPERTY && p <= la_device_property_e::LAST_STRING_PROPERTY) {
        return device_property_type_e::STRING;
    }

    return device_property_type_e::UNKNOWN;
}

struct bfd_packet_intervals {
    std::chrono::microseconds desired_min_tx_interval{};
    std::chrono::microseconds required_min_rx_interval{};
    uint8_t detection_time_multiplier{};
};

inline bool
operator<(const bfd_packet_intervals& lhs, const bfd_packet_intervals& rhs)
{
    return std::tie(lhs.desired_min_tx_interval, lhs.required_min_rx_interval, lhs.detection_time_multiplier)
           < std::tie(rhs.desired_min_tx_interval, rhs.required_min_rx_interval, rhs.detection_time_multiplier);
}

/// @brief MTU programmed will be reduced by following ether encap bytes as npl checks for L3 packet length for mtu check.
static const uint16_t LA_MTU_ETHER_ENCAP_LEN = 14;

/// @brief MTU max value.
static const uint16_t LA_MTU_MAX = (1 << 14) - 1;

/// @brief L3 MTU max value.
static const uint16_t LA_L3_MTU_MAX = (LA_MTU_MAX - LA_MTU_ETHER_ENCAP_LEN);

/// @brief MTU min value.
static const uint16_t LA_MTU_MIN = 64;

/// @brief Mirror command type
enum mirror_type_e {
    MIRROR_INGRESS,
    MIRROR_EGRESS,
};

} // namespace silicon_one

#endif // __HLD_TYPES_H__
