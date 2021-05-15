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

#ifndef __LA_TM_TYPES_H__
#define __LA_TM_TYPES_H__

#include <stddef.h>
#include <stdint.h>
#include <vector>

#include "api/types/la_common_types.h"

/// @file
/// @brief Leaba Traffic Management definitions.
///
/// Defines TM related types and enumerations used by the Leaba API.

namespace silicon_one
{
class la_voq_set;

class la_interface_scheduler;

class la_ifg_scheduler;
class la_system_port_scheduler;
class la_system_port;
class la_logical_port_scheduler;
class la_output_queue_scheduler;
class la_tc_profile;
class la_fabric_port_scheduler;
class la_voq_cgm_profile;
}

/// @addtogroup TM_TYPES
/// @{

/// @brief Fabric mode.
///
/// Fabric mode defines the load balancing method of the fabric.
enum class la_fabric_mode_e {
    FLB,    ///< Flow load balancing. Load balancing is based on flow signature.
    RLB_SN, ///< Random load balancing using sequence numbers. Flows are load-balanced across all links.
    RLB_TS, ///< Random load balancing using timestamps. Flows are load-balanced across all links.\n
            ///< This mode requires fabric to be based on a Leaba device as well, and configured for RLB TS mode.
    SLB,    ///< Segment load balancing. This mode is relevant for DC fabrics.
};

/// @}
/// @addtogroup MULTICAST
/// @{
/// @brief Replication paradigm.
///
/// Replication paradigm defines where to replicate a multicast packet of a multicast group.
enum class la_replication_paradigm_e {
    INGRESS, ///< Ingress replication.
             ///< All replication will be done on network slice of the ingress device.
    EGRESS,  ///< Egress replication.
             ///< Each device and slice will receive single packet and replicate the
             ///< minimum required.
};

/// @}
/// @addtogroup TM_VOQ
/// @{

/// @brief      Output queue credit scheduler VSC attachment mode.
///
/// @details    A Virtual Scheduler Connection is attached to either one or two groups
///             in an OQCS, with a limited subset of topologies.
///             This enum details the possible mapping options.
///             Groups' priorities are group0, group1... group7.
enum class la_oq_vsc_mapping_e {
    RR0 = 0, ///< VSC mapped to group 0
    RR1,     ///< VSC mapped to group 1
    RR2,     ///< VSC mapped to group 2
    RR3,     ///< VSC mapped to group 3
    RR0_RR2, ///< VSC mapped to groups 0 and 2
    RR0_RR3, ///< VSC mapped to groups 0 and 3
    RR1_RR2, ///< VSC mapped to groups 1 and 2
    RR1_RR3, ///< VSC mapped to groups 1 and 3
    RR4,     ///< VSC mapped to group 4
    RR5,     ///< VSC mapped to group 5
    RR6,     ///< VSC mapped to group 6
    RR7,     ///< VSC mapped to group 7
};

/// @}
/// @addtogroup TM_SCH
/// @{

/// @brief Defines the number of quantization regions and configurable thresholds of link thresholds for fabric scheduling.
enum {
    // Number of regions
    LA_FABRIC_VALID_LINKS_QUANTIZATION_REGIONS = 4,
    LA_FABRIC_CONGESTED_LINKS_QUANTIZATION_REGIONS = 4,

    // Number of thresholds
    LA_FABRIC_VALID_LINKS_CONFIGURABLE_THRESHOLDS = LA_FABRIC_VALID_LINKS_QUANTIZATION_REGIONS - 1,
    LA_FABRIC_CONGESTED_LINKS_CONFIGURABLE_THRESHOLDS = LA_FABRIC_CONGESTED_LINKS_QUANTIZATION_REGIONS - 1,
};

/// @brief Virtual Scheduler Connection global ID.
///
/// A credit scheduler allocates credits to an attached VSC.
/// Each of the scheduler's VSC-s uniquely identifies an ingress VOQ.
typedef la_uint_t la_vsc_gid_t;

/// @brief Virtual output queue global ID.
typedef la_uint_t la_voq_gid_t;

/// @brief Rate in measurement-units per second.
///
/// When the context is data rate, the rate is in bits per second (bps).
/// When the context is packet rate, the rate is in packets per second (pps).
typedef la_uint64_t la_rate_t;

/// @brief Weight for WFQ scheduling.
typedef la_uint32_t la_wfq_weight_t;

// Constants
/// Unlimited rate.
static const la_rate_t LA_RATE_UNLIMITED = -1;

///@brief System port scheduler ID.
typedef la_uint_t la_system_port_scheduler_id_t;

/// Predefined system port scheduler ID for host system port.
static const la_system_port_scheduler_id_t LA_SYSTEM_PORT_SCHEDULER_ID_HOST = 18;

/// Predefined system port scheduler ID for recycle system port.
static const la_system_port_scheduler_id_t LA_SYSTEM_PORT_SCHEDULER_ID_RECYCLE = 19;

/// Predefined Invalid system port scheduler ID.
static const la_system_port_scheduler_id_t LA_SYSTEM_PORT_SCHEDULER_ID_INVALID = -1;

/// @brief VSC ID attached to the output queue scheduler.
///
/// VSC ID should be unique ID in the egress IFG.
typedef la_uint_t la_vsc_gid_t;

/// Predefined Invalid VSC ID.
static const la_vsc_gid_t LA_VSC_GID_INVALID = -1;

/// @brief Vector of VSC IDs attached to the output queue scheduler.
typedef std::vector<la_vsc_gid_t> la_vsc_gid_vec_t;

/// @brief Output queue scheduler group.
///        Credits within a group are distributed in a round-robin manner.
typedef la_uint_t la_oqcs_group_id_t;

/// @brief Output queue scheduler ID.
typedef la_uint_t la_oq_id_t;

/// @brief Map Output queue credit scheduler to logical port and priorities.
struct la_oq_pg {
    silicon_one::la_output_queue_scheduler* oqcs; ///< Map LPSE to OQ scheduler
    la_vsc_gid_t pg_eir;                          ///< Map LPSE to EIR weight index of the output queue credit scheduler.
    la_vsc_gid_t pg_cir;                          ///< Map LPSE to CIR weight index of the output queue credit scheduler.
};

/// @brief Output queue vector attached to specific logical port.
using la_oq_pg_vec_t = std::vector<la_oq_pg>;

/// @brief Defines attached VSC to output queue credit scheduler.
struct la_vsc_oq {
    la_vsc_gid_t vsc;         ///< Map OQ to VSCS entries
    la_oq_vsc_mapping_e map;  ///< The mapping type from the output queue to the VSC.
    la_device_id_t device_id; ///< Source device of the VSC.
    la_slice_id_t slice_id;   ///< Source slice of the VSC.
    la_voq_gid_t voq_id;      ///< Source VOQ ID of the VSC.
};

/// @brief VSC vector attached to specific output queue.
using la_vsc_oq_vec_t = std::vector<la_vsc_oq>;

/// @brief Defines VOQ set attachment to logical port
struct la_sysport_voq {
    silicon_one::la_system_port* system_port; ///< Destination system port for the VOQ attachment
    silicon_one::la_voq_set* voq_set;         ///< Attached VOQ set
};

/// @brief VOQ set vector for a specific logical port
using la_sysport_voq_vec_t = std::vector<la_sysport_voq>;

/// @brief Device specific size of native VOQ set size.
enum { NATIVE_VOQ_SET_SIZE = 16 };

/// @brief Size of sampling-space used for sampling probablity in mirror commands.
enum { MIRROR_SAMPLING_SPACE_SIZE = (1 << 18) };
static const float MIRROR_SAMPLING_FREQUENCY_GRANULARITY = 1.0f / MIRROR_SAMPLING_SPACE_SIZE;

/// @brief Quantization thresholds for valid fabric links, in number of links.
///
/// Thresholds are provided for all N-1 regions. The first region's lower-limit is 0 and the last region's upper-limit is infinity.
/// For 'x' the data value and 'i' the selected region; if threshold[i] == x == threshold[i+n], region i+1 will be selected,
/// otherwise if threshold[i-1] <= x < threshold[i], region i will be selected.
struct la_fabric_valid_links_thresholds {
    la_uint_t thresholds[LA_FABRIC_VALID_LINKS_CONFIGURABLE_THRESHOLDS];
};

/// @brief Quantization thresholds for congested fabric links, in number of links.
///
/// Thresholds are provided for all N-1 regions. The first region's lower-limit is 0 and the last region's upper-limit is infinity.
/// For 'x' the data value and 'i' the selected region; if threshold[i] == x == threshold[i+n], region i+1 will be selected,
/// otherwise if threshold[i-1] <= x < threshold[i], region i will be selected.
struct la_fabric_congested_links_thresholds {
    la_uint_t thresholds[LA_FABRIC_CONGESTED_LINKS_CONFIGURABLE_THRESHOLDS];
};

/// @}

#endif // __LA_TM_TYPES_H__
