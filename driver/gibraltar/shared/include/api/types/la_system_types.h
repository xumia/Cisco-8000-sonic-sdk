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

#ifndef __LA_SYSTEM_TYPES_H__
#define __LA_SYSTEM_TYPES_H__

/// @file
/// @brief Leaba System definitions.
///
/// Defines System related types and enumerations used by the Leaba API.

#include "api/types/la_common_types.h"
#include "api/types/la_ethernet_types.h"
#include <vector>

struct _Aapl_t;
/// @brief Handler to Avago AAPL (ASIC and ASSP Programming Layer) interface.
///
/// Avago AAPL struct is used in all Avago API.
typedef struct _Aapl_t Aapl_t;

/// Forward declaration of json_t. This is an object matching the jansson library.
struct json_t;

namespace silicon_one
{
class la_device;
class la_erspan_mirror_command;
class la_flow_cache_handler;
class la_hbm_handler;
class la_ptp_handler;
class la_l2_mirror_command;
class la_l2_punt_destination;
class la_mac_port;
class la_mirror_command;
class la_npu_host_port;
class la_npu_host_destination;
class la_pci_port;
class la_punt_inject_port;
class la_punt_destination;
class la_recycle_port;
class la_system_port;
class la_spa_port;
class la_counter_set;
class la_fabric_port;
class la_remote_port;
class la_remote_device;
class la_stack_port;
class la_security_group_cell;
class la_pbts_map_profile;
class la_control_plane_classifier;

/// @brief Low-level device.
///
/// Base class providing low-level access API-s such as register/memory read/write,
/// interrupt management etc.
class ll_device;

/// @brief NPL tables.
///
/// Class providing low-level access API-s to NPL tables, such as insert/update/remove/lookup.
class device_tables;

/// @addtogroup SYSTEM
/// @{

/// @brief Slice mode.
///
/// Each slice is either a fabric or network slice.
///
/// Standalone devices have all slices set to network slice mode.
/// Linecard devices have a mix between network slices and fabric slices (4/2 or 3/3).
/// Fabric devices have all slices set to fabric slice mode.
///
/// Carrier fabrics allow proprietary message formats, and so carrier fabric slices
/// use a proprietary format for packet transfer across the fabric.
///
/// Data center fabric uses standard network protocols, simply assuming remote devices can be reached
/// from multiple data-center fabric slices for load-balancing purposes.
enum class la_slice_mode_e {
    INVALID = 0,    ///< Invalid slice.
    CARRIER_FABRIC, ///< Carrier fabric-facing slice.
    DC_FABRIC,      ///< DC fabric-facing slice.
    NETWORK,        ///< Network-facing slice.
    UDC,            ///< User-defined context slice.
    DISABLED,       ///< Slice is present, but not enabled.
    NUM_SLICE_MODES ///< Number of slice modes.
};

enum la_mac_port_max_lanes_e {
    SERDES = 8,  ///< Maximum of SerDes lanes in a port.
    PCS = 32,    ///< Maximum of PCS lanes in a port.
    KR = 4,      ///< Maximum of KR FEC lanes in a port.
    RS_FEC = 32, ///< Maximun number of RS-FEC lanes per port.
};

/// @brief Device properties.
enum class la_device_property_e {
    /// First boolean property
    FIRST_BOOLEAN_PROPERTY,
    FIRST = FIRST_BOOLEAN_PROPERTY,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// In a linecard device, in a 3/3 mix of network and fabric slices configuration, two ports from two network slices can be
    /// used as fabric ports.
    ///
    /// In enabled mode:
    /// - Network slice/IFG (0/0) and (2/1) have two SerDes elements less than regular IFGs, i.e., there are 16 SerDes elements
    ///   usable for network ports on these reduced IFGs.
    /// - Fabric slice/IFG (3/0) and (5/1) each have two SerDes elements more than regular IFGs. The surplus SerDes elements are
    ///   20, 21.
    ///
    /// If enabled, when creating MAC and fabric MAC ports the SerDes element IDs should adhere to the above restrictions.
    LC_56_FABRIC_PORT_MODE = FIRST_BOOLEAN_PROPERTY,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// Controls whether traffic destined for a local output port is forced through the traffic, or only passed locally. In
    /// enabled mode traffic to local output ports will be forwarded to the fabric.
    LC_FORCE_FORWARD_THROUGH_FABRIC_MODE,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// The reachability between linecard devices on the fabric can be discovered using an auto-discovery fabric routing
    /// protocol. This should be a system-wide configuration. In enable mode, a linecard device will advertise its device ID on
    /// all fabric ports.
    LC_ADVERTISE_DEVICE_ON_FABRIC_MODE,

    /// Property type: bool. <br>
    /// Default value: true. <br>
    ///
    /// There are two types of linecards: 2.4T and 3.6T
    LC_TYPE_2_4_T,

    /// Property type: bool. <br>
    /// Default value: true. <br>
    ///
    /// Using the leaba NIC driver.
    USING_LEABA_NIC,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// Improve nsim model accuracy to mimic real hardware, at the expense of lower control plane performance
    /// under simulation.
    ENABLE_NSIM_ACCURATE_SCALE_MODEL,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// If HBM enabled, the HBM channels will be initialized as part of the initialization.
    ENABLE_HBM,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// TEST_MODE_PUNT_EGRESS_PACKETS_TO_HOST should be enabled only in HW test environment. When enabled, all packets are punted to
    /// CPU with a special
    /// header identifying the packets' egress port.
    TEST_MODE_PUNT_EGRESS_PACKETS_TO_HOST,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// TEST_MODE_PACIFIC_A0_ALLOW_RCY_ON_ALL_SLICES should be enabled only in test environment. When enabled, recycle ports can be
    /// created on all slices in Pacific A0
    /// CPU with a special
    /// header identifying the packets' egress port.
    TEST_MODE_PACIFIC_A0_ALLOW_RCY_ON_ALL_SLICES,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// If true, device interrupts are handled internally and notifications are raised through notification API.
    /// If false, device interrupts are silently ignored.
    PROCESS_INTERRUPTS,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// If true, poll MSI interrupt register.
    /// If false, don't poll.
    POLL_MSI,

    RTL_SIMULATION_WORKAROUNDS,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// If true, assume the device is emulated.
    /// If false, don't assume the device is emulated.
    EMULATED_DEVICE,

    /// GB bring-up - START
    GB_INITIALIZE_CONFIG_MEMORIES,
    GB_INITIALIZE_OTHER,
    GB_A1_DISABLE_FIXES,
    GB_A2_DISABLE_FIXES,
    /// GB bring-up - END

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// Extend route DB into HBM.
    ///
    /// Works only if HBM is enabled.
    ENABLE_HBM_ROUTE_EXTENSION,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// Cache frequently used routes in on-die LPM.
    ///
    /// Works only if HBM is enabled and HBM_ROUTE_EXTENSION is enabled.
    ENABLE_HBM_ROUTE_EXTENSION_CACHING_MODE,

    /// Property type: bool. <br>
    /// Default value: true. <br>
    ///
    /// Enable IP Caches (EM and TCAM).
    ENABLE_LPM_IP_CACHE,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// Disable the electrical idle detection mechanism.
    ///
    DISABLE_ELECTRICAL_IDLE_DETECTION,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// If true, running memory MBIST will try to repair failed memories.
    /// If false, running memory MBIST will not try to repair and will fail on any failed memory.
    ENABLE_MBIST_REPAIR,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// If true, diagnostics_test() always succeeds, regardless if MBIST errors are found or not.
    /// If false, diagnostics_test() succeeds if there are no MBIST errors, and fails otherwise.
    IGNORE_MBIST_ERRORS,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// If true, device counters work on 29b Packet Counter 35b Byte Counter.
    /// If false, device counters work on 64b Packet Counter and 64b Byte Counter.
    ENABLE_NARROW_COUNTERS,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// If true, Global LSP counters are accounted as MPLS SR
    /// If false, Global LSP counters are accounted as MPLS
    ENABLE_MPLS_SR_ACCOUNTING,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// If true, PBTS resolution is enabled on Upper half of #silicon_one::la_prefix_object.
    /// If false, No PBTS resolution on full range of #silicon_one::la_prefix_object.
    ENABLE_PBTS,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// If true, Class ID ACL when configured, works with FEC or Next-hop's as destinations of route lookups.
    /// If False, Class ID ACL when configured, works with FEC or Next-hop's as destinations of route lookups.
    ENABLE_CLASS_ID_ACLS,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// If true, B0 revision works as like as A0 in every possible change.
    /// If false, All B0 fixes being enabled.
    ENABLE_PACIFIC_B0_IFG_CHANGES,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// If true, B0 OOB interleaving enabled.
    /// If false, B0 OOB interleaving disabled.
    ENABLE_PACIFIC_OOB_INTERLEAVING,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// When true, remote system ports are configured as-if they are local to the device, causing all dependent objects to be
    /// configured on the local device.
    /// This is a distributed systems, testing-oriented flag that should not be modified by general users.
    INSTANTIATE_REMOTE_SYSTEM_PORTS,

    // Following properties are used in MMU initialization to control LPM-HBM cache
    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// HBM move to read on empty.
    HBM_MOVE_TO_READ_ON_EMPTY,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// HBM move to write on empty.
    HBM_MOVE_TO_WRITE_ON_EMPTY,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// Enable SerDes NRZ fast tuning.
    ENABLE_SERDES_NRZ_FAST_TUNE,

    /// Property type: bool. <br>
    /// Default value: true. <br>
    ///
    /// Enable SerDes PAM4 fast tuning on Network Port.
    ENABLE_NETWORK_SERDES_PAM4_FAST_TUNE,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// Enable SerDes PAM4 fast tuning on Fabric Port.
    ENABLE_FABRIC_SERDES_PAM4_FAST_TUNE,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// Enable RS-KP4 FEC on Fabric Port.
    ENABLE_FABRIC_FEC_RS_KP4,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// Disable SerDes Post ANLT Tune.
    DISABLE_SERDES_POST_ANLT_TUNE,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// Disable SerDes Post ANLT Tune.
    ENABLE_SERDES_PRE_ICAL_PRIOR_ANLT,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// Enable SerDes DFE based electrical idle detection.
    SERDES_DFE_EID,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// Enable configuring serdes transmitter slip settings.
    ENABLE_SERDES_TX_SLIP,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// Enable serdes Tx refresh whenever link down in peer.
    ENABLE_SERDES_TX_REFRESH,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// Enable tuning based on fixed number of tune iterations.
    MAC_PORT_IGNORE_LONG_TUNE,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// Enable check of dfeTAP[0] == -0x1F for 25G SerDes speed.
    MAC_PORT_ENABLE_25G_DFETAP_CHECK,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// Enable check of degraded SER and high BER during link up algorithm.
    MAC_PORT_ENABLE_SER_CHECK,

    /// Property type: bool. <br>
    /// Default value: true. <br>
    ///
    /// Enable degraded SER in the interrupt mask for notification handling.
    ENABLE_MAC_PORT_DEGRADED_SER_NOTIFICATIONS,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// Enable SerDes low power mode.
    ENABLE_SERDES_LOW_POWER,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// If true, will reconnect even if in-flight operation is detected from previous SDK session.
    RECONNECT_IGNORE_IN_FLIGHT,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// If true, value of #silicon_one::la_device_property_e::MINIMUM_FABRIC_PORTS_FOR_CONNECTIVITY will be ignored, and instead,
    /// the value set by #silicon_one::la_device::set_minimum_fabric_links_per_lc API will be used.
    ENABLE_FE_PER_DEVICE_MIN_LINKS,

    /// Property type: bool. <br>
    /// Default value: true. <br>
    ///
    /// If true, will ignore SBus master MBIST failure.
    IGNORE_SBUS_MASTER_MBIST_FAILURE,

    /// Property type: bool. <br>
    /// Default value: true. <br>
    ///
    /// Enable/Disable device temperature and voltage monitoring.
    ENABLE_SENSOR_POLL,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// Enable Pacific SW based PFC, rather than HW based. Enabling this will set tuning parameters for this device.
    ENABLE_PACIFIC_SW_BASED_PFC,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// Enable PFC device tuning. Enabling this will set tuning parameters for this device. Not needed if
    /// ENABLE_PACIFIC_SW_BASED_PFC is set.
    ENABLE_PFC_DEVICE_TUNING,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// PACIFIC_PFC_HBM_ENABLED parameter.
    /// If true, enable PFC generation on Pacific when evicting VOQ to HBM. To enable PFC generation
    /// need to ensure that mirrors 28, 29 are not used.
    PACIFIC_PFC_HBM_ENABLED,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// SLEEP_IN_SET_MAX_BURST parameter.
    /// If true a sleep is added every time a shaper burst size is being configured, to verify no linked lists are being used.
    SLEEP_IN_SET_MAX_BURST,

    /// Propery type: bool. <br>
    /// Default value: false. <br>
    ///
    /// If true, will use dedicated statistical meter counters instead of existing internal exact meter mechanism.
    STATISTICAL_METER_COUNTING,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// If True, enable independent voqs for Explicit Congestion Notification (ECN) capable transport in the data plane.
    /// If False, disable independent voqs for Explicit Congestion Notification (ECN) capable transport in the data plane.
    ENABLE_ECN_QUEUING,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// Enable SerDes low dropout voltage regulator
    ENABLE_SERDES_LDO_VOLTAGE_REGULATOR,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// Enable Override SRM SerDes PLL KP/KF setting.
    ENABLE_SRM_OVERRIDE_PLL_KP_KF,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// Ignore initialization failures that occur in some components (see la_component_type_e) of the device.
    IGNORE_COMPONENT_INIT_FAILURES,

    /// Enable Stackwise Virtual Mode (SVL) of operating
    ENABLE_SVL_MODE,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// If true, with inbound mirror configured, custom metadata added to the mirrored packets will contain the destination system
    /// port of the original packet.
    /// If False, with inbound mirror configured, custom metadata added to the mirrored packet will not contain the destination
    /// system port of the original packet.
    DESTINATION_SYSTEM_PORT_IN_IBM_METADATA,

    /// Property type: bool. <br>
    /// Default value: true. <br>
    ///
    /// Enable power saving by switching off some components of the device.
    ENABLE_POWER_SAVING_MODE,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// Enable the InFO PMD/Phy interface if exist in device.
    ENABLE_INFO_PHY,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// Disable HBM for debugging purposes. Overrides ENABLE_HBM.
    FORCE_DISABLE_HBM,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// Skip HBM training
    HBM_SKIP_TRAINING,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// Enable dummy serdes handler.
    ENABLE_DUMMY_SERDES_HANDLER,

    /// Property type: bool. <br>
    /// Default value: false. <br>
    ///
    /// If true, enable optimization on boot.
    /// If false, no optimization on boot.
    ENABLE_BOOT_OPTIMIZATION,

    /// Last boolean property
    LAST_BOOLEAN_PROPERTY = ENABLE_BOOT_OPTIMIZATION,

    /// First integer property
    FIRST_INTEGER_PROPERTY,

    /// Property type: integer. <br>
    /// Default value: 0. <br>
    ///
    /// HBM frequency in MHz, used to initialize HBM. If 0, use system default.
    HBM_FREQUENCY = FIRST_INTEGER_PROPERTY,

    /// Property type: integer. <br>
    /// Default value: 0. <br>
    ///
    /// Mutliplier used for updating the statistical meter bucket.
    STATISTICAL_METER_MULTIPLIER,

    /// Property type: integer. <br>
    /// Default value: 0. <br>
    ///
    /// Polling interval for polling threads. If 0, use system default.
    POLL_INTERVAL_MILLISECONDS,

    /// Property type: integer. <br>
    /// Default value: 0. <br>
    ///
    /// Polling interval for fast polling threads. If 0, use system default.
    POLL_FAST_INTERVAL_MILLISECONDS,

    /// Property type: integer. <br>
    /// Default value: 1000. <br>
    ///
    /// Interrupt masks are restored every RESTORE_INTERRUPT_MASKS_INTERVAL_MILLISECONDS.
    /// The restoration frequency is upper bound by the frequency of polling, configured by POLL_INTERVAL_MILLISECONDS.
    RESTORE_INTERRUPT_MASKS_INTERVAL_MILLISECONDS,

    /// Property type: integer. <br>
    /// Default value: 1000. <br>
    ///
    /// Interval for polling non-wired interrupts.
    /// The frequency is upper bound by the frequency of polling, configured by POLL_INTERVAL_MILLISECONDS.
    POLL_NON_WIRED_INTERRUPTS_INTERVAL_MILLISECONDS,

    /// Property type: integer. <br>
    /// Default value: 100. <br>
    ///
    /// In case of interrupts storm, MSI is dampened with this interval.
    MSI_DAMPENING_INTERVAL_MILLISECONDS,

    /// Property type: integer. <br>
    /// Default value: 10. <br>
    ///
    /// MSI is considered in a storm state if this number of MSIs is not cleared in a sequence.
    MSI_DAMPENING_THRESHOLD,

    /// Property type: integer. <br>
    /// Default value: 100. <br>
    ///
    /// Interval for polling temperature and voltage sensors.
    /// Note that it takes two poll cycles to read specific sensor from two different locations on the ASIC. Reading the
    /// sensors is sequential and reading same sensor again is after reading all other sensors.
    SENSOR_POLL_INTERVAL_MILLISECONDS,

    /// Property type: integer. <br>
    /// Default value: 3000. <br>
    ///
    /// Threshold to declare failure in ms.
    TEMPERATURE_SENSOR_POLL_FAILURE_TIMEOUT_MILLISECONDS,

    /// Property type: integer. <br>
    /// Default value: 1. <br>
    ///
    /// This property is deprecated and will be removed in future SDK release.
    /// Please use #silicon_one::la_device::set_global_minimum_fabric_links instead.
    ///
    MINIMUM_FABRIC_PORTS_FOR_CONNECTIVITY,

    /// Property type: integer. <br>
    ///
    /// SerDes firmware revision number.
    /// Used to validate proper SerDes firmware revision is loaded to the SerDes when activated.
    /// If revision doesn't match will try to upload the SerDes firmware file.
    SERDES_FW_REVISION,

    /// Property type: integer. <br>
    ///
    /// SerDes firmware build number.
    /// Used to validate proper SerDes firmware build is loaded to the SerDes when activated.
    /// If build doesn't match will try to upload the SerDes firmware file.
    SERDES_FW_BUILD,

    /// Property type: integer. <br>
    ///
    /// SBUS master firmware revision number.
    /// Used to validate proper SBUS master firmware revision is loaded to the SBUS master when activated.
    SBUS_MASTER_FW_REVISION,

    /// Property type: integer. <br>
    ///
    /// SerDes firmware build number.
    /// Used to validate proper SBUS master firmware build is loaded to the SBUS master when activated.
    SBUS_MASTER_FW_BUILD,

    /// Property type: integer. <br>
    ///
    /// Timeout in seconds for MAC port to complete tuning.
    MAC_PORT_TUNE_TIMEOUT,

    /// Property type: integer. <br>
    ///
    /// Maximum number of re-tune if PAM4 is below threshold.
    MAC_PORT_PAM4_MAX_TUNE_RETRY,

    /// Property type: integer. <br>
    ///
    /// Minimum acceptable PAM4 eye height.
    MAC_PORT_PAM4_MIN_EYE_HEIGHT,

    /// Property type: integer. <br>
    ///
    /// Minimum acceptable NRZ eye height.
    MAC_PORT_NRZ_MIN_EYE_HEIGHT,

    /// Property type: integer. <br>
    ///
    /// Minimum acceptable 10G_NRZ eye height.
    MAC_PORT_10G_NRZ_MIN_EYE_HEIGHT,

    /// Property type: integer. <br>
    ///
    /// Timeout in seconds to get SerDes CDR lock on MAC port after tune completes.
    MAC_PORT_CDR_LOCK_AFTER_TUNE_TIMEOUT,

    /// Property type: integer. <br>
    ///
    /// Time in seconds for PCS to be up and stable before tune/lock iteration is declared successful.
    MAC_PORT_PCS_LOCK_TIME,

    /// Property type: integer. <br>
    /// Default value: 1. <br>
    ///
    /// Max size of FIFO containing snapshots of most recent SERDES tune data.
    /// This queue will be added to the MAC_PORT save_state JSON output if size > 0
    MAC_PORT_SAVE_STATE_SERDES_DEBUG_SNAPSHOTS,

    /// Property type: integer. <br>
    /// Default value: 30. <br>
    ///
    /// Max size of FIFO containing most recent MAC_PORT state transitions.
    /// This queue will be added to the MAC_PORT save_state JSON output if size > 0
    MAC_PORT_SAVE_STATE_SM_STATE_TRANSITION_CAPTURES,

    /// Property type: integer. <br>
    ///
    /// Number of successful tune/lock iterations required for PCS to be declared stable for a network port.
    /// Default value is 1.
    NETWORK_MAC_PORT_TUNE_AND_PCS_LOCK_ITER,

    /// Property type: integer. <br>
    ///
    /// Number of successful tune/lock iterations required for PCS to be declared stable for a fabric port.
    /// Default value is 1.
    FABRIC_MAC_PORT_TUNE_AND_PCS_LOCK_ITER,

    /// Property type: integer. <br>
    /// Property type: integer. <br>
    /// Default value: 500 milliseconds. <br>
    ///
    /// Timeout in milliseconds for MAC port to receive next page
    /// from peer. If elapsed, fallback restart auto negotiation.
    MAC_PORT_AUTO_NEGOTIATION_TIMEOUT,

    /// Default value: 3 Seconds. <br>
    ///
    /// Timeout in seconds for MAC port to complete SerDes PMD link training. If elapsed, fallback to AN.
    MAC_PORT_LINK_TRAINING_TIMEOUT,

    /// Default value: 1000 Milli-seconds. <br>
    ///
    /// NRZ Timeout in millie-seconds for MAC port to complete SerDes PMD link training.
    MAC_PORT_NRZ_LINK_TRAINING_TIMEOUT,

    /// Default value: 3000 Milli-seconds. <br>
    ///
    /// PAM4 Timeout in millie-seconds for MAC port to complete SerDes PMD link training.
    MAC_PORT_PAM4_LINK_TRAINING_TIMEOUT,

    /// Property type: integer. <br>
    /// Default value: 1. <br>
    ///
    /// Set serdes RXA power sequence mode.
    SERDES_RXA_POWER_SEQUENCE_MODE,

    /// Property type: integer. <br>
    /// Default value: 1. <br>
    ///
    /// Set PRESET selection for clause-136
    SERDES_CL136_PRESET_TYPE,

    /// Property type: integer. <br>
    /// Default value: 1000. <br>
    ///
    /// Number of LPM actions between rebalance algorithm runs.
    LPM_REBALANCE_INTERVAL,

    /// Property type: integer. <br>
    /// Default value: 80. <br>
    ///
    /// Balancing start threshold percentage between the least/most utilized LPM cores.
    LPM_REBALANCE_START_FAIRNESS_THRESHOLD_PERCENT,

    /// Property type: integer. <br>
    /// Default value: 90. <br>
    ///
    /// Balancing end threshold percentage between the least/most utilized LPM cores.
    LPM_REBALANCE_END_FAIRNESS_THRESHOLD_PERCENT,

    /// Property type: integer. <br>
    /// Default value: 1. <br>
    ///
    /// Weight of single width key for rebalance algorithm (indicates its load on LPM TCAM).
    LPM_TCAM_SINGLE_WIDTH_KEY_WEIGHT,

    /// Property type: integer. <br>
    /// Default value: 1. <br>
    ///
    /// Weight of double width key for rebalance algorithm (indicates its load on LPM TCAM).
    LPM_TCAM_DOUBLE_WIDTH_KEY_WEIGHT,

    /// Property type: integer. <br>
    /// Default value: 1. <br>
    ///
    /// Weight of quad width key for rebalance algorithm (indicates its load on LPM TCAM).
    LPM_TCAM_QUAD_WIDTH_KEY_WEIGHT,

    /// Default value: 4096. <br>
    ///
    /// Max number of buckets in LPM L2 SRAM (used for testing only).
    LPM_L2_MAX_SRAM_BUCKETS,

    /// Default value: 1. <br>
    ///
    /// Number of banksets in LPM TCAM.
    LPM_TCAM_NUM_BANKSETS,

    /// Default value: 512. <br>
    ///
    /// LPM TCAM bank size. Used for stress testing only.
    LPM_TCAM_BANK_SIZE,

    /// Property type: integer. <br>
    /// Default value: 1200000 KHz. <br>
    ///
    /// Device frequency in KHz.
    /// Must be configured before la_device::initialize(init_phase_e::DEVICE) is called.
    DEVICE_FREQUENCY,

    /// Property type: integer. <br>
    /// Default value: 5 MHz. <br>
    ///
    /// TAP clock frequency in MHz.
    /// Must be configured before la_device::initialize(init_phase_e::DEVICE) is called.
    TCK_FREQUENCY,

    /// Property type: integer. <br>
    /// Default value: 60*60*24 seconds (24h)
    ///
    /// Period over which interrupts are counted and threshold-based notifications are raised.
    RESET_INTERRUPT_COUNTERS_INTERVAL_SECONDS,

    /// Property type: integer. <br>
    /// Default value: 100
    ///
    /// Threshold for 1b ECC error in CONFIG memory entry to become a critical error, generating a soft/hard/device replace
    /// recommended action.
    INTERRUPT_THRESHOLD_MEM_CONFIG_ECC_1B,

    /// Property type: integer. <br>
    /// Default value: 100
    ///
    /// Threshold for 2b ECC error in CONFIG memory entry to become a critical error, generating a soft/hard/device replace
    /// recommended action.
    INTERRUPT_THRESHOLD_MEM_CONFIG_ECC_2B,

    /// Property type: integer. <br>
    /// Default value: 100
    ///
    /// Threshold for parity error in CONFIG memory entry to become a critical error, generating a soft/hard/device replace
    /// recommended action.
    INTERRUPT_THRESHOLD_MEM_CONFIG_PARITY,

    /// Property type: integer. <br>
    /// Default value: 100
    ///
    /// Threshold for 1b ECC error in VOLATILE memory entry to become a critical error, generating a soft/hard/device replace
    /// recommended action.
    INTERRUPT_THRESHOLD_MEM_VOLATILE_ECC_1B,

    /// Property type: integer. <br>
    /// Default value: 10
    ///
    /// Threshold for 2b ECC error in VOLATILE memory entry to become a critical error, generating a soft/hard/device replace
    /// recommended action.
    INTERRUPT_THRESHOLD_MEM_VOLATILE_ECC_2B,

    /// Property type: integer. <br>
    /// Default value: 10
    ///
    /// Threshold for parity error in VOLATILE memory entry to become a critical error, generating a soft/hard/device replace
    /// recommended action.
    INTERRUPT_THRESHOLD_MEM_VOLATILE_PARITY,

    /// Property type: integer. <br>
    /// Default value: 100
    ///
    /// Threshold for 1b ECC error in LPM SRAM to become a critical error, generating a soft/hard/device replace
    /// recommended action.
    INTERRUPT_THRESHOLD_LPM_SRAM_ECC_1B,

    /// Property type: integer. <br>
    /// Default value: 10
    ///
    /// Threshold for 2b ECC error in LPM SRAM to become a critical error, generating a soft/hard/device replace
    /// recommended action.
    INTERRUPT_THRESHOLD_LPM_SRAM_ECC_2B,

    /// Property type: integer. <br>
    /// Default value: 2^30
    ///
    /// Max counter threshold.
    /// If counter exceeds this value, an interrupt will be generated and SDK will collect this counter immediately.
    /// Valid only for narrow counters mode.
    MAX_COUNTER_THRESHOLD,

    /// Property type: integer. <br>
    /// Default value: 6000. <br>
    ///
    /// Delay before AAPL exec, in Core cycles.
    AAPL_IFG_DELAY_BEFORE_EXEC,

    /// Property type: integer. <br>
    /// Default value: 500. <br>
    ///
    /// Delay before AAPL exec, in Core cycles.
    AAPL_HBM_DELAY_BEFORE_EXEC,

    /// Property type: integer. <br>
    /// Default value: 10. <br>
    ///
    /// Delay before AAPL poll, in Core cycles.
    AAPL_IFG_DELAY_BEFORE_POLL,

    /// Property type: integer. <br>
    /// Default value: 10. <br>
    ///
    /// Delay before AAPL poll, in Core cycles.
    AAPL_HBM_DELAY_BEFORE_POLL,

    /// Property type: integer. <br>
    /// Default value: 0. <br>
    ///
    /// Delay in AAPL poll, in Core cycles while waiting for response.
    AAPL_IFG_DELAY_IN_POLL,

    /// Property type: integer. <br>
    /// Default value: 100. <br>
    ///
    /// Number of poll iterations to check completion of SBus master command on IFG SBus.
    AAPL_IFG_POLL_TIMEOUT,

    // Following properties are used in MMU initialization to control LPM-HBM cache
    /// Property type: integer. <br>
    /// Default value: 512. <br>
    ///
    /// HBM READ cycles.
    HBM_READ_CYCLES,

    /// Property type: integer. <br>
    /// Default value: 512. <br>
    ///
    /// HBM WRITE cycles.
    HBM_WRITE_CYCLES,

    /// Property type: integer. <br>
    /// Default value: 0. <br>
    ///
    /// HBM min move to read.
    HBM_MIN_MOVE_TO_READ,

    /// Property type: integer. <br>
    /// Default value: 0. <br>
    ///
    /// HBM LPM flavor mode. Legal values are 0, 1 and 2:
    /// 0 - NO_FAVOR_LPM : Dont consider LPM fill level when moving to read
    /// 1 - FAVOR_LPM : Use LPM fill level when moving to read
    /// 2 - FAVOR_LPM_MIN_WRITE : only move from write to read when there is LPM pending AND min of 256 cycles of write has passed
    HBM_LPM_FAVOR_MODE,

    /// Property type: integer. <br>
    /// Special value 0 - no limit on the number of save-files.
    /// Default value: 10.<br>
    ///
    /// Maximum number of files that the periodic save state will create.
    /// After reaching the maximum number of files, oldest file will be deleted.
    MAX_NUMBER_OF_PERIODIC_SAVE_STATE_FILES,

    /// Property type: integer. <br>
    /// Default value: 7. <br>
    ///
    /// HBM PHY parameter.
    HBM_PHY_T_RDLAT_OFFSET,

    /// Property type: integer. <br>
    /// Default value: 64k <br>
    ///
    /// Multicast MCID Scale Threshold
    /// Setting this value below 64k allows multicast groups created above
    /// the threshold to use local MCIDs thus allowing better utilization of
    /// the 64k MCID range across linecards. Any multicast groups created
    /// below the threshold will be required to be the same on all linecards.
    MULTICAST_MCID_SCALE_THRESHOLD,

    /// Property type: integer. <br>
    /// Default value: 256. <br>
    ///
    /// Max number of LPTS entry counters.
    LPTS_MAX_ENTRY_COUNTERS,

    /// Property type: integer. <br>
    /// Default value: 128. <br>
    ///
    /// Max number of PCL IDs.
    MAX_NUM_PCL_GIDS,

    /// Property type: integer. <br>
    /// Default value: 256. <br>
    ///
    /// Max number of sgacl cell counters.
    SGACL_MAX_CELL_COUNTERS,

    /// Property type: integer. <br>
    /// Default value: 120. <br>
    ///
    /// Time in seconds for Port to be in link-up before doing SerDes Tx refresh.
    LINKUP_TIME_BEFORE_SERDES_REFRESH,

    /// Property type: integer. <br>
    /// Default value: 0. <br>
    ///
    /// Is this ASIC is a lower rate GB board or a regular Gibralter? <br>
    /// GIBRALTAR_REGULAR; MATILDA_64; MATILDA_32A;MATILDA_32B; or a GB_8T type.<br>
    /// See enum at device_modle_types.h
    /// This should typically be set from the eFuse
    MATILDA_MODEL_TYPE,

    /// Property type: Read only integer. <br>
    /// Efuse burned refclk, 5 bits, bit[4] Valid bit. bits[3:0] bit per IFG
    EFUSE_REFCLK_SETTINGS,

    /// Default value: 0. <br>
    ///
    /// refclk selection, 12 bits, bit per IFG
    DEV_REFCLK_SEL,

    /// Default value: 1.
    /// Valid values are [1,6]
    ///
    /// Out of Band inject credits count
    OOB_INJ_CREDITS,

    /// Property type: integer. <br>
    /// Default value: 0. <br>
    ///
    /// Setting the probability for the PFC pilot mirror. Unit is prob = n/1000.
    PACIFIC_PFC_PILOT_PROBABILITY,

    /// Property type: integer. <br>
    /// Default value: 0. <br>
    ///
    /// Setting the probability for the PFC measurement mirror. Unit is prob = n/1000.
    PACIFIC_PFC_MEASUREMENT_PROBABILITY,

    /// Property type: integer. <br>
    /// Default value: Different default value in each project <br>
    ///
    /// Deivice's credit size.
    CREDIT_SIZE_IN_BYTES,

    /// Property type: integer. <br>
    /// Default value: Different default value in each project <br>
    ///
    ///  Number of SerDes to be configured as Multi-Port PHY
    NUM_MULTIPORT_PHY,

    /// Property type: integer. <br>
    /// Default value: 0. <br>
    ///
    /// Age out interval of counters shadow for fast read feature.
    /// When zero the feature disabled.
    COUNTERS_SHADOW_AGE_OUT,

    /// Property type: integer. <br>
    /// Default value: 20000. <br>
    ///
    /// Delay between consecutive meter bucket reads during meter refill in nanoseconds
    METER_BUCKET_REFILL_POLLING_DELAY,

    /// Last integer property
    LAST_INTEGER_PROPERTY = METER_BUCKET_REFILL_POLLING_DELAY,

    /// First string property
    FIRST_STRING_PROPERTY,

    /// Property type: string. <br>
    ///
    /// SerDes firmware file name.
    SERDES_FW_FILE_NAME = FIRST_STRING_PROPERTY,

    /// Property type: string. <br>
    ///
    /// SBUS master firmware file name.
    SBUS_MASTER_FW_FILE_NAME,

    /// Last string property
    LAST_STRING_PROPERTY = SBUS_MASTER_FW_FILE_NAME,

    /// Last property
    LAST = LAST_STRING_PROPERTY,

    /// Number of boolean properties
    NUM_BOOLEAN_PROPERTIES = (int)LAST_BOOLEAN_PROPERTY - (int)FIRST_BOOLEAN_PROPERTY + 1,

    /// Number of integer properties
    NUM_INTEGER_PROPERTIES = (int)LAST_INTEGER_PROPERTY - (int)FIRST_INTEGER_PROPERTY + 1,

    /// Number of string properties
    NUM_STRING_PROPERTIES = (int)LAST_STRING_PROPERTY - (int)FIRST_STRING_PROPERTY + 1,
};

/// @brief Slice CLOS topology direction.
///
/// In a CLOS topology tree linecard devices are the leaf nodes, regarded as the lowest in the tree. The spine fabric-element
/// devices are regarded the highest in the tree.
enum class la_clos_direction_e {
    DOWN = 0, ///< Down towards the leaf linecard devices.
    UP        ///< Up towards the spine fabric-element devices.
};

/// @}

/// @brief Temperature sensors.
enum class la_temperature_sensor_e {
    PACIFIC_FIRST = 0,
    PACIFIC_SENSOR_1 = PACIFIC_FIRST, ///< Temperature sensor 1, SBUS master Read.
    PACIFIC_SENSOR_2,                 ///< Temperature sensor 2, SBUS master Read.
    PACIFIC_SENSOR_1_DIRECT,          ///< Temperature sensor 1, Direct Read.
    PACIFIC_SENSOR_2_DIRECT,          ///< Temperature sensor 2, Direct Read.
    PACIFIC_HBM_SENSOR_1,             ///< Temperature sensor 1 on HBM.
    PACIFIC_HBM_SENSOR_2,             ///< Temperature sensor 2 on HBM.
    PACIFIC_LAST = PACIFIC_HBM_SENSOR_2,
    PACIFIC_NUM_SENSORS = PACIFIC_LAST - PACIFIC_FIRST + 1,

    GIBRALTAR_FIRST,
    GIBRALTAR_SENSOR_0 = GIBRALTAR_FIRST, ///< Temperature sensor 0.
    GIBRALTAR_SENSOR_1,                   ///< Temperature sensor 1.
    GIBRALTAR_SENSOR_2,                   ///< Temperature sensor 2.
    GIBRALTAR_SENSOR_3,                   ///< Temperature sensor 3.
    GIBRALTAR_SENSOR_4,                   ///< Temperature sensor 4.
    GIBRALTAR_SENSOR_5,                   ///< Temperature sensor 5.
    GIBRALTAR_SENSOR_6,                   ///< Temperature sensor 6.
    GIBRALTAR_SENSOR_7,                   ///< Temperature sensor 7.
    GIBRALTAR_SENSOR_8,                   ///< Temperature sensor 8.
    GIBRALTAR_SENSOR_9,                   ///< Temperature sensor 9.
    GIBRALTAR_HBM_SENSOR_0,               ///< Temperature sensor 0 on HBM.
    GIBRALTAR_HBM_SENSOR_1,               ///< Temperature sensor 1 on HBM.
    GIBRALTAR_LAST = GIBRALTAR_HBM_SENSOR_1,
    GIBRALTAR_NUM_SENSORS = GIBRALTAR_LAST - GIBRALTAR_FIRST + 1,

    ASIC4_FIRST,
    ASIC4_SENSOR_0 = ASIC4_FIRST, ///< Temperature sensor 0.
    ASIC4_SENSOR_1,                   ///< Temperature sensor 1.
    ASIC4_SENSOR_2,                   ///< Temperature sensor 2.
    ASIC4_SENSOR_3,                   ///< Temperature sensor 3.
    ASIC4_SENSOR_4,                   ///< Temperature sensor 4.
    ASIC4_SENSOR_5,                   ///< Temperature sensor 5.
    ASIC4_SENSOR_6,                   ///< Temperature sensor 6.
    ASIC4_SENSOR_7,                   ///< Temperature sensor 7.
    ASIC4_SENSOR_8,                   ///< Temperature sensor 8.
    ASIC4_SENSOR_9,                   ///< Temperature sensor 9.
    ASIC4_HBM_SENSOR_0,               ///< Temperature sensor 0 on HBM.
    ASIC4_HBM_SENSOR_1,               ///< Temperature sensor 1 on HBM.
    ASIC4_LAST = ASIC4_HBM_SENSOR_1,
    ASIC4_NUM_SENSORS = ASIC4_LAST - ASIC4_FIRST + 1,

    ASIC3_FIRST,
    ASIC3_SENSOR_0 = ASIC3_FIRST, ///< Temperature sensor 0.
    ASIC3_SENSOR_1,                  ///< Temperature sensor 1.
    ASIC3_SENSOR_2,                  ///< Temperature sensor 2.
    ASIC3_SENSOR_3,                  ///< Temperature sensor 3.
    ASIC3_SENSOR_4,                  ///< Temperature sensor 4.
    ASIC3_SENSOR_5,                  ///< Temperature sensor 5.
    ASIC3_SENSOR_6,                  ///< Temperature sensor 6.
    ASIC3_SENSOR_7,                  ///< Temperature sensor 7.
    ASIC3_SENSOR_8,                  ///< Temperature sensor 8.
    ASIC3_SENSOR_9,                  ///< Temperature sensor 9.
    ASIC3_SENSOR_10,                 ///< Temperature sensor 10.
    ASIC3_CHIPLET_SENSOR_0,          ///< Temperature sensor on Chiplet 0.
    ASIC3_CHIPLET_SENSOR_1,          ///< Temperature sensor on Chiplet 1.
    ASIC3_CHIPLET_SENSOR_2,          ///< Temperature sensor on Chiplet 2.
    ASIC3_CHIPLET_SENSOR_3,          ///< Temperature sensor on Chiplet 3.
    ASIC3_CHIPLET_SENSOR_4,          ///< Temperature sensor on Chiplet 4.
    ASIC3_CHIPLET_SENSOR_5,          ///< Temperature sensor on chiplet 5.
    ASIC3_CHIPLET_SENSOR_6,          ///< Temperature sensor on Chiplet 6.
    ASIC3_CHIPLET_SENSOR_7,          ///< Temperature sensor on Chiplet 7.
    ASIC3_LAST = ASIC3_CHIPLET_SENSOR_7,
    ASIC3_NUM_SENSORS = ASIC3_LAST - ASIC3_FIRST + 1,

    ASIC5_FIRST,
    ASIC5_SENSOR_0 = ASIC5_FIRST, ///< Temperature sensor 0.
    ASIC5_SENSOR_1,               ///< Temperature sensor 1.
    ASIC5_SENSOR_2,               ///< Temperature sensor 2.
    ASIC5_SENSOR_3,               ///< Temperature sensor 3.
    ASIC5_SENSOR_4,               ///< Temperature sensor 4.
    ASIC5_SENSOR_5,               ///< Temperature sensor 5.
    ASIC5_SENSOR_6,               ///< Temperature sensor 6.
    ASIC5_SENSOR_7,               ///< Temperature sensor 7.
    ASIC5_SENSOR_8,               ///< Temperature sensor 8.
    ASIC5_SENSOR_9,               ///< Temperature sensor 9.
    ASIC5_LAST = ASIC5_SENSOR_9,
    ASIC5_NUM_SENSORS = ASIC5_LAST - ASIC5_FIRST + 1,
};

/// @brief Temperature in degrees Celsius.
typedef float la_temperature_t;

/// @brief Voltage sensors.
enum class la_voltage_sensor_e {
    PACIFIC_FIRST = 0,
    PACIFIC_SENSOR_1_VDD = PACIFIC_FIRST, ///< Voltage sensor 1, VDD Voltage
    PACIFIC_SENSOR_1_AVDD,                ///< Voltage sensor 1, AVDD Voltage
    PACIFIC_SENSOR_2_VDD,                 ///< Voltage sensor 2, VDD Voltage
    PACIFIC_SENSOR_2_AVDD,                ///< Voltage sensor 2, AVDD Voltage
    PACIFIC_LAST = PACIFIC_SENSOR_2_AVDD,
    PACIFIC_NUM_SENSORS = PACIFIC_LAST - PACIFIC_FIRST + 1,

    GIBRALTAR_FIRST,
    GIBRALTAR_SENSOR_0 = GIBRALTAR_FIRST, ///< Voltage sensor 0.
    GIBRALTAR_SENSOR_1,                   ///< Voltage sensor 1.
    GIBRALTAR_SENSOR_2,                   ///< Voltage sensor 2.
    GIBRALTAR_SENSOR_3,                   ///< Voltage sensor 3.
    GIBRALTAR_SENSOR_4,                   ///< Voltage sensor 4.
    GIBRALTAR_SENSOR_5,                   ///< Voltage sensor 5.
    GIBRALTAR_SENSOR_6,                   ///< Voltage sensor 6.
    GIBRALTAR_SENSOR_7,                   ///< Voltage sensor 7.
    GIBRALTAR_SENSOR_8,                   ///< Voltage sensor 8.
    GIBRALTAR_SENSOR_9,                   ///< Voltage sensor 9.
    GIBRALTAR_LAST = GIBRALTAR_SENSOR_9,
    GIBRALTAR_NUM_SENSORS = GIBRALTAR_LAST - GIBRALTAR_FIRST + 1,

    ASIC4_FIRST,
    ASIC4_SENSOR_0 = ASIC4_FIRST, ///< Voltage sensor 0.
    ASIC4_SENSOR_1,                   ///< Voltage sensor 1.
    ASIC4_SENSOR_2,                   ///< Voltage sensor 2.
    ASIC4_SENSOR_3,                   ///< Voltage sensor 3.
    ASIC4_SENSOR_4,                   ///< Voltage sensor 4.
    ASIC4_SENSOR_5,                   ///< Voltage sensor 5.
    ASIC4_SENSOR_6,                   ///< Voltage sensor 6.
    ASIC4_SENSOR_7,                   ///< Voltage sensor 7.
    ASIC4_SENSOR_8,                   ///< Voltage sensor 8.
    ASIC4_SENSOR_9,                   ///< Voltage sensor 9.
    ASIC4_LAST = ASIC4_SENSOR_9,
    ASIC4_NUM_SENSORS = ASIC4_LAST - ASIC4_FIRST + 1,

    ASIC3_FIRST,
    ASIC3_SENSOR_0 = ASIC3_FIRST, ///< Voltage sensor 0.
    ASIC3_SENSOR_1,                  ///< Voltage sensor 1.
    ASIC3_SENSOR_2,                  ///< Voltage sensor 2.
    ASIC3_SENSOR_3,                  ///< Voltage sensor 3.
    ASIC3_SENSOR_4,                  ///< Voltage sensor 4.
    ASIC3_SENSOR_5,                  ///< Voltage sensor 5.
    ASIC3_SENSOR_6,                  ///< Voltage sensor 6.
    ASIC3_SENSOR_7,                  ///< Voltage sensor 7.
    ASIC3_SENSOR_8,                  ///< Voltage sensor 8.
    ASIC3_SENSOR_9,                  ///< Voltage sensor 9.
    ASIC3_SENSOR_10,                 ///< voltage sensor 10.
    ASIC3_CHIPLET_SENSOR_0,          ///< voltage sensor on Chiplet 0.
    ASIC3_CHIPLET_SENSOR_1,          ///< voltage sensor on Chiplet 1.
    ASIC3_CHIPLET_SENSOR_2,          ///< voltage sensor on Chiplet 2.
    ASIC3_CHIPLET_SENSOR_3,          ///< voltage sensor on Chiplet 3.
    ASIC3_CHIPLET_SENSOR_4,          ///< voltage sensor on Chiplet 4.
    ASIC3_CHIPLET_SENSOR_5,          ///< voltage sensor on Chiplet 5.
    ASIC3_CHIPLET_SENSOR_6,          ///< voltage sensor on Chiplet 6.
    ASIC3_CHIPLET_SENSOR_7,          ///< voltage sensor on Chiplet 7.
    ASIC3_LAST = ASIC3_CHIPLET_SENSOR_7,
    ASIC3_NUM_SENSORS = ASIC3_LAST - ASIC3_FIRST + 1,

    ASIC5_FIRST,
    ASIC5_SENSOR_0 = ASIC5_FIRST, ///< Voltage sensor 0.
    ASIC5_SENSOR_1,               ///< Voltage sensor 1.
    ASIC5_SENSOR_2,               ///< Voltage sensor 2.
    ASIC5_SENSOR_3,               ///< Voltage sensor 3.
    ASIC5_SENSOR_4,               ///< Voltage sensor 4.
    ASIC5_SENSOR_5,               ///< Voltage sensor 5.
    ASIC5_SENSOR_6,               ///< Voltage sensor 6.
    ASIC5_SENSOR_7,               ///< Voltage sensor 7.
    ASIC5_SENSOR_8,               ///< Voltage sensor 8.
    ASIC5_SENSOR_9,               ///< Voltage sensor 9.
    ASIC5_LAST = ASIC5_SENSOR_9,
    ASIC5_NUM_SENSORS = ASIC5_LAST - ASIC5_FIRST + 1,
};

/// @brief Voltage in Volts.
typedef float la_voltage_t;

/// @addtogroup PORT
/// @{

/// Global ID of system port.
typedef la_uint_t la_system_port_gid_t;

/// System Port Aggregate Port global ID.
/// @ingroup PORT_SPA
typedef la_uint_t la_spa_port_gid_t;

/// Mirror command global ID.
/// @ingroup PACKET
typedef la_uint8_t la_mirror_gid_t;

/// port extender vlan header id.
typedef la_uint16_t la_port_extender_vid_t;

typedef std::vector<la_device_id_t> la_device_id_vec_t;

/// @brief Resource instance index.
///
/// Identifies a specific resource instance.
typedef size_t la_resource_instance_index_t;
static const la_resource_instance_index_t LA_RESOURCE_INSTANCE_INDEX_INVALID = (la_resource_instance_index_t)(-1);

/// @brief Stage of the device.
enum class la_stage_e {
    INGRESS, ///< Related to the RX part.
    EGRESS,  ///< Related to the TX part.
};

/// @}

/// @brief Resource descriptor: type, location.
struct la_resource_descriptor {

    /// @brief Resource type.
    enum class type_e {
        AC_PROFILE = 0,
        ACL_GROUP,
        CENTRAL_EM,
        COUNTER_BANK,
        EGRESS_ENC_EM0,
        EGRESS_ENC_EM1,
        EGRESS_ENC_EM2,
        EGRESS_ENC_EM3,
        EGRESS_ENC_EM4,
        EGRESS_ENC_EM5,
        EGRESS_IPV4_ACL,
        EGRESS_IPV6_ACL,
        EGRESS_LARGE_ENCAP_EM,
        EGRESS_L3_DLP0_EM,
        EGRESS_SMALL_ENCAP_EM,
        EGRESS_QOS_PROFILES,
        INGRESS_ETH_NARROW_DB1_INTERFACE0_ACL,
        INGRESS_ETH_NARROW_DB2_INTERFACE0_ACL,
        INGRESS_IPV4_NARROW_DB1_INTERFACE0_ACL,
        INGRESS_IPV4_NARROW_DB2_INTERFACE0_ACL,
        INGRESS_IPV4_NARROW_DB3_INTERFACE0_ACL,
        INGRESS_IPV4_NARROW_DB4_INTERFACE0_ACL,
        INGRESS_IPV4_WIDE_DB1_INTERFACE0_ACL,
        INGRESS_IPV4_WIDE_DB2_INTERFACE0_ACL,
        INGRESS_IPV4_WIDE_DB3_INTERFACE0_ACL,
        INGRESS_IPV4_WIDE_DB4_INTERFACE0_ACL,
        INGRESS_IPV6_NARROW_DB1_INTERFACE0_ACL,
        INGRESS_IPV6_NARROW_DB2_INTERFACE0_ACL,
        INGRESS_IPV6_NARROW_DB3_INTERFACE0_ACL,
        INGRESS_IPV6_NARROW_DB4_INTERFACE0_ACL,
        INGRESS_IPV6_WIDE_DB1_INTERFACE0_ACL,
        INGRESS_IPV6_WIDE_DB2_INTERFACE0_ACL,
        INGRESS_IPV6_WIDE_DB3_INTERFACE0_ACL,
        INGRESS_IPV6_WIDE_DB4_INTERFACE0_ACL,
        INGRESS_QOS_PROFILES,
        IPV4_LPTS,
        IPV4_VRF_DIP_EM_TABLE,
        IPV6_COMPRESSED_SIPS,
        IPV6_LPTS,
        IPV6_VRF_DIP_EM_TABLE,
        L2_SERVICE_PORT,
        L3_AC_PORT,
        LPM,
        LPM_IPV4_ROUTES,
        LPM_IPV6_ROUTES,
        MAC_FORWARDING_TABLE,
        MC_EMDB,
        METER_ACTION,
        METER_PROFILE,
        MY_IPV4_TABLE,
        NATIVE_CE_PTR_TABLE,
        NATIVE_FEC_ENTRY,
        NEXT_HOP,
        PROTECTION_GROUP,
        RTF_CONF_SET,
        SIP_INDEX_TABLE,
        STAGE1_LB_GROUP,
        STAGE1_LB_MEMBER,
        STAGE1_PROTECTION_MONITOR,
        STAGE2_LB_GROUP,
        STAGE2_LB_MEMBER,
        STAGE2_PROTECTION_MONITOR,
        STAGE3_LB_GROUP,
        STAGE3_LB_MEMBER,
        TC_PROFILE,
        TCAM_EGRESS_NARROW_POOL_0,
        TCAM_EGRESS_WIDE,
        TCAM_INGRESS_NARROW_POOL_0,
        TCAM_INGRESS_NARROW_POOL_1,
        TCAM_INGRESS_WIDE,
        TUNNEL_0_EM,
        TUNNEL_1_EM,
        VOQ_CGM_EVICTED_PROFILE,
        VOQ_CGM_PROFILE,
        LAST = VOQ_CGM_PROFILE,
        UNSPECIFIED
    };

    type_e m_resource_type; ///< Resource type.

    union location {
        la_slice_pair_id_t slice_pair_id; ///< For per slice-pair resources.
        la_slice_id_t slice_id;           ///< For per slice resources.
        la_slice_ifg slice_ifg_id;        ///< For per IFG resource.
    } m_index; ///< Each resource has its own granularity: can be per device/slice/slice_pair/IFG. This member represents the
               /// physical location.
};

/// @brief Resource usage descriptor.
struct la_resource_usage_descriptor {
    la_resource_descriptor desc; ///< Resource's descriptor.
    size_t state;                ///< Resource state.
    size_t used;                 ///< Resource's usage.
    size_t total;                ///< Total physical Resources.
};

/// @brief Resource granularity
enum class la_resource_granularity {
    IFG,        ///< Per IFG resource.
    SLICE,      ///< Per slice resource.
    SLICE_PAIR, ///< Per slice-pair resource.
    DEVICE,     ///< Global resource.
};

/// @brief Resource notification thresholds.
struct la_resource_thresholds {
    double high_watermark; ///< High watermark.
    double low_watermark;  ///< Low watermark.
};

/// @brief Device information.
struct la_device_info_t {
    la_device_revision_e family; ///< Device family number.
    la_uint_t extension;         ///< Device extension number.
    la_uint_t revision;          ///< Device revision number.
    la_uint_t part_num;          ///< Device part number.
};

using la_resource_usage_descriptor_vec = std::vector<la_resource_usage_descriptor>;

/// @brief I2C register read/write access
///
/// @param[in]    user_data   Opaque platform's private data.
/// @param[in]    is_read     Read operation when true, write otherwise.
/// @param[in]    addr        Register address.
/// @param[inout] val         Register value.
///
/// @retval  LA_STATUS_SUCCESS    Operation completed successfully.
/// @retval  LA_STATUS_EUNKNOWN   Internal error.
typedef la_status (*la_i2c_register_access_cb)(uintptr_t user_data, bool is_read, uint32_t addr, uint32_t* val);

struct la_dma_desc {
    void* virt_addr;    ///< Virtual address in caller process's address space.
    uint64_t phys_addr; ///< Physical address in PCI domain.
    size_t length;      ///< Length in bytes.
    bool is_64bit;      ///< True if 64bit coherent DMA is enabled.
                        ///< False if 32bit coherent DMA is enabled.
};

/// @brief Allocate contiguous and coherent DMA buffer.
///
/// @param[in]  user_data   Opaque platform's private data.
/// @param[in]  length      Length of DMA buffer in bytes.
/// @param[out] desc        DMA descriptor.
///
/// @retval     LA_STATUS_SUCCESS      Operation completed successfully.
/// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
typedef la_status (*la_dma_alloc_cb)(uintptr_t user_data, size_t length, la_dma_desc& desc);

/// @brief Free DMA buffer
///
/// @param[in] desc DMA descriptor.
typedef void (*la_dma_free_cb)(uintptr_t user_data, const la_dma_desc& desc);

/// @brief Open device and interrupt file descriptors.
///
/// @param[in]  user_data            Opaque platform's private data.
/// @param[out] device_fd            An open device file descriptor
/// @param[out] interrupt_fd         An open interrupt file descriptor.
/// @param[out] interrut_width_bytes Width of interrupt counter.
///
/// @note 'device_fd' is going to be used to map device's memory at offset zero using mmap().
///
/// @retval     LA_STATUS_SUCCESS      Operation completed successfully.
/// @retval     LA_STATUS_EINVAL       Device ID is out of range.
/// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
typedef la_status (*la_open_device_cb)(uintptr_t user_data, int& device_fd, int& interrupt_fd, size_t& interrupt_width_bytes);

/// @brief Close device and interrupt file descriptors.
///
/// @param[in]  user_data    Opaque platform's private data.
/// @param[in]  device_fd    An open device file descriptor.
/// @param[in]  interrupt_fd An open interrupt file descriptor.
///
/// @retval     LA_STATUS_SUCCESS      Operation completed successfully.
/// @retval     LA_STATUS_EINVAL       Device ID is out of range.
/// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
typedef la_status (*la_close_device_cb)(uintptr_t user_data, int device_fd, int interrupt_fd);

/// @brief Platform-specific operations
struct la_platform_cbs {
    /// @brief Opaque platform's private data.
    uintptr_t user_data;

    /// @brief I2C registers access.
    la_i2c_register_access_cb i2c_register_access;

    /// @brief Allocate contiguous and coherent DMA buffer.
    la_dma_alloc_cb dma_alloc;

    /// @brief Free DMA buffer.
    la_dma_free_cb dma_free;

    /// @brief Open interrupt file descriptor.
    la_open_device_cb open_device;

    /// @brief Close interrupt file descriptor.
    la_close_device_cb close_device;
};

} // namespace silicon_one

#endif // __LA_SYSTEM_TYPES_H__
