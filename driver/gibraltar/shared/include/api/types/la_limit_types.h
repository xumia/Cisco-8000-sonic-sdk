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

#ifndef __LA_LIMIT_TYPES_H__
#define __LA_LIMIT_TYPES_H__

namespace silicon_one
{

/// @addtogroup SYSTEM
/// @{

/// @brief Leaba limit type
enum class limit_type_e {
    DEVICE__NUM_CGM_HBM_POOLS,                                  ///< Number of HBM partitions.
    DEVICE__MAX_SMS_BYTES_QUANTIZATION_THRESHOLD,               ///< SMS overall size-in-bytes max quantization threshold.
    DEVICE__SMS_NUM_BYTES_QUANTIZATION_REGIONS,                 ///< SMS overall size-in-bytes number of quantization regions.
    DEVICE__SMS_NUM_BYTES_QUANTIZATION_CONFIGURABLE_THRESHOLDS, ///< SMS overall size-in-bytes number of configurable thresholds.

    DEVICE__MAX_SMS_PACKETS_QUANTIZATION_THRESHOLD,               ///< SMS overall size-in-packets max quantization threshold.
    DEVICE__SMS_NUM_PACKETS_QUANTIZATION_REGIONS,                 ///< SMS overall size-in-packets number of quantization regions.
    DEVICE__SMS_NUM_PACKETS_QUANTIZATION_CONFIGURABLE_THRESHOLDS, ///< SMS overall size-in-packets number of configurable
                                                                  /// thresholds.
    DEVICE__MAX_SMS_NUM_EVICTED_BUFF_QUANTIZATION_THRESHOLD,      ///< All evicted VOQs size in bytes max quantization threshold.
    DEVICE__SMS_NUM_EVICTED_BUFF_QUANTIZATION_REGIONS, ///< All evicted VOQs size in bytes number of quantization regions.
    DEVICE__SMS_NUM_EVICTED_BUFF_QUANTIZATION_CONFIGURABLE_THRESHOLDS, ///< All evicted VOQs number of configurable thresholds.
    DEVICE__MAX_HBM_NUM_OF_VOQS_QUANTIZATION_THRESHOLD,                ///< Number of VOQs-in-HBM max quantization threshold.
    DEVICE__HBM_NUM_OF_VOQS_QUANTIZATION_REGIONS,                      ///< Number of VOQs-in-HBM numer of quantization regions.
    DEVICE__HBM_NUM_OF_VOQS_QUANTIZATION_CONFIGURABLE_THRESHOLDS,      ///< Number of VOQs-in-HBM number of configurable thresholds.
    DEVICE__MAX_HBM_POOL_BYTES_QUANTIZATION_THRESHOLD,     ///< HBM pool overall size-in-bytes max quantization threshold.
    DEVICE__HBM_NUM_POOL_FREE_BLOCKS_QUANTIZATION_REGIONS, ///< HBM pool free blocks number of quantization regions.
    DEVICE__HBM_NUM_POOL_FREE_BLOCKS_QUANTIZATION_CONFIGURABLE_THRESHOLDS, ///< HBM pool overall bytes number of configurable
                                                                           /// thresholds.
    DEVICE__MAX_HBM_BLOCKS_BY_VOQ_QUANTIZATION_THRESHOLD, ///< HBM overall number of blocks max quantization threshold.
    DEVICE__HBM_NUM_BLOCKS_BY_VOQ_QUANTIZATION_REGIONS,   ///< VOQ-in-HBM used blocks number of quantization regions.
    DEVICE__HBM_NUM_BLOCKS_BY_VOQ_QUANTIZATION_CONFIGURABLE_THRESHOLDS, ///< VOQ-in-HBM overall blocks number of configurable
                                                                        /// thresholds.
    DEVICE__MAX_HBM_VOQ_AGE_QUANTIZATION_THRESHOLD,                     ///< HBM queue are max quantization threhshold.
    DEVICE__HBM_NUM_VOQ_AGE_QUANTIZATION_REGIONS, ///< VOQ-in-HBM age of oldest packet number of quatization regions.
    DEVICE__HBM_NUM_VOQ_AGE_QUANTIZATION_CONFIGURABLE_THRESHOLDS, ///< VOQ-in-HBM age number of configurable thresholds.
    DEVICE__NUM_LOCAL_VOQS,                                       ///< Number of local-only VOQ-s for standalone systems.
    DEVICE__NUM_SYSTEM_VOQS,                                      ///< Number of system-aware VOQ-s for distributed systems.
    DEVICE__NUM_TC_PROFILES,                                      ///< Number of TC profiles that user can create.
    DEVICE__FIRST_ALLOCATABLE_VOQ,                                ///< Lowest VOQ number user can allocate.
    DEVICE__MIN_ALLOCATABLE_VSC,                                  ///< Lowest VSC number user can allocate.
    DEVICE__MAX_ALLOCATABLE_VSC,                                  ///< Highest VSC number user can allocate.
    DEVICE__MAX_PREFIX_OBJECT_GIDS,                               ///< Number of overall IGP Prefix Objects.
    DEVICE__MAX_SR_EXTENDED_POLICIES,                             ///< Number of SR policies that support 4 or more outgoing labels.
    DEVICE__MAX_OIDS,                                             ///< Number of objects that can have object-IDs.
    DEVICE__MAX_ERSPAN_SESSION_ID,                                ///< Highest ERSPAN session ID that can be used.
    DEVICE__MAX_L3_PROTECTION_GROUP_GIDS,                         ///< Number of overall L3 Protection Groups.
    DEVICE__MIN_SYSTEM_PORT_GID,                                  ///< Lowest system port GID number user can allocate.
    DEVICE__MAX_SYSTEM_PORT_GID,                                  ///< Highest system port GID number user can allocate.
    DEVICE__MAX_L2_AC_PORT_GID,                                   ///< Highest system L2 AC port GID number user can allocate.
    DEVICE__NUM_ACL_TCAM_POOLS,                                   ///< Number of ACL TCAM pools.

    COUNTER_SET__MAX_PQ_COUNTER_OFFSET, ///< Max offset whithin a counter set.
    COUNTER_SET__MAX_PIF_COUNTER_OFFSET,

    VOQ_CGM_PROFILE__SMS_NUM_BYTES_QUANTIZATION_REGIONS,    ///< VOQ-in-SMS size in bytes number of quantization regions.
    VOQ_CGM_PROFILE__SMS_NUM_PACKETS_QUANTIZATION_REGIONS,  ///< VOQ-in-SMS size in packets number of quantization regions.
    VOQ_CGM_PROFILE__SMS_NUM_AGE_QUANTIZATION_REGIONS,      ///< VOQ-in-SMS age of oldest packet number of quantization regions.
    VOQ_CGM_PROFILE__WRED_NUM_BLOCKS_QUANTIZATION_REGIONS,  ///< WRED number of quantization regions.
    VOQ_CGM_PROFILE__NUM_PACKET_SIZE_REGIONS,               ///< Number of packet size regions.
    VOQ_CGM_PROFILE__SMS_NUM_BYTES_DROP_PROBABILITY_LEVELS, ///< VOQ-in-SMS size in bytes number of drop probability levels.
    VOQ_CGM_PROFILE__SMS_NUM_BYTES_MARK_PROBABILITY_LEVELS, ///< VOQ-in-SMS size in bytes number of mark probability levels.

    VOQ_CGM_PROFILE__SMS_NUM_BYTES_QUANTIZATION_CONFIGURABLE_THRESHOLDS,   ///< VOQ-in-SMS size in bytes number of configurable
                                                                           /// thresholds.
    VOQ_CGM_PROFILE__SMS_NUM_PACKETS_QUANTIZATION_CONFIGURABLE_THRESHOLDS, ///< VOQ-in-SMS size in packets number of configurable
                                                                           /// thresholds.
    VOQ_CGM_PROFILE__SMS_NUM_AGE_QUANTIZATION_CONFIGURABLE_THRESHOLDS, ///< VOQ-in-SMS age of oldest packet number of configurable
                                                                       /// thresholds.
    VOQ_CGM_PROFILE__WRED_NUM_BLOCKS_QUANTIZATION_CONFIGURABLE_THRESHOLDS, ///< WRED number of configurable thresholds.
    VOQ_CGM_PROFILE__MAX_VOQ_SMS_BYTES,                                    ///< VOQ-in-SMS size in bytes max quantization threshold.
    VOQ_CGM_PROFILE__MAX_VOQ_SMS_PACKETS, ///< VOQ-in-SMS size in packets max quantization threshold.
    VOQ_CGM_PROFILE__MAX_VOQ_SMS_AGE,     ///< VOQ-in-SMS age of oldest packet max quantization threshold.
    VOQ_CGM_PROFILE__MAX_VOQ_HBM_SIZE,    ///< VOQ-in-HBM size in bytes max quantization threshold.

    ROUTE__MAX_CLASS_IDENTIFIER, ///<  Maximum allowed class ID for a route
    HOST__MAX_CLASS_IDENTIFIER,  ///<  Maximum allowed class ID for a host

    METER_PROFILE__MAX_BURST_SIZE,      ///< METER_PROFILE max bucket size in bytes.
    METER_PROFILE__MAX_PPS_BURST_SIZE,  ///< METER_PROFILE max bucket size in packets.
    STAT_METER_PROFILE__MAX_BURST_SIZE, ///< Max bucket size for a profile to be attached to a stat meter.

    MLDP_MIN_RPF_ID, // MLDP lowest RPF Id
    MLDP_MAX_RPF_ID, // MLDP highest RPF Id

    DEVICE__MAX_INGRESS_MIRROR_GID, ///<  Maximum allowed GID of a mirror command used for ingress
    DEVICE__MIN_INGRESS_MIRROR_GID, ///<  Minimum allowed GID of a mirror command used for ingress
    DEVICE__MAX_EGRESS_MIRROR_GID,  ///<  Maximum allowed GID of a mirror command used for egress
    DEVICE__MIN_EGRESS_MIRROR_GID   ///<  Minimum allowed GID of a mirror command used for egress

};

/// @brief Leaba limit type
enum class la_precision_type_e {
    VOQ_CGM_PROBABILITY_PRECISION,                   ///< Precision for floating-point VOQ CGM probability operation
    METER_PROFILE__CBS_RESOLUTION,                   ///< Resolution for meter CBS
    METER_PROFILE__EBS_RESOLUTION,                   ///< Resolution for meter EBS
    METER_PROFILE__STATISTICAL_METER_CBS_RESOLUTION, ///< Resolution for PPS meter CBS
    METER_PROFILE__STATISTICAL_METER_EBS_RESOLUTION, ///< Resolution for PPS meter EBS

};

} // namespace silicon_one

#endif // __LA_LIMIT_TYPE_H__
