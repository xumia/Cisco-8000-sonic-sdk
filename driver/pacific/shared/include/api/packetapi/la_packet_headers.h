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

#ifndef __LA_PACKET_HEADERS_H__
#define __LA_PACKET_HEADERS_H__

namespace silicon_one
{

#pragma pack(push, 1)
/// @brief Packet header when injecting encapsulated packet, ready to be sent on the wire.
///
/// Directly forwarded to DSP/BVN destination, applying the specified PHB.
#define SIZEOF_LA_PACKET_INJECT_HEADER_DOWN 17
union la_packet_inject_header_down {
    struct {
        uint64_t ext_type : 8;     //<  Must be INJECT_HEADER_EXT_TYPE_NONE
        uint64_t internal : 8;     //<  Must be 0
        uint64_t lm_offset : 7;    //<  Counter stamp - offset
        uint64_t padding1 : 1;     //<  padding
        uint64_t lm_opcode : 4;    //<  Counter stamp - opcode
        uint64_t ts_offset : 7;    //<  Time stamp - offset
        uint64_t padding2 : 1;     //<  padding
        uint64_t ts_opcode : 4;    //<  Time stamp - opcode
        uint64_t padding3 : 4;     //<  padding
        uint64_t down_nh : 12;     //<  NH
        uint64_t l3_dlp : 16;      //<  L3 DLP
        uint64_t counter_ptr : 20; //<  Counter pointer (TBD)
        uint64_t padding4 : 8;     //<  padding.
        uint64_t dest : 20;        //<  Destination ID - DSP or BVN.
        uint64_t phb_dp : 2;       //<  Drop Precedence of the packet. 0 means green.
        uint64_t phb_tc : 3;       //<  Traffic Class of the packet. According to 802.1q, 7 is high.
        uint64_t encap : 3;        //<  Encapsulation type
        uint64_t type : 8;         //<  Inject type
    };
    uint8_t raw[SIZEOF_LA_PACKET_INJECT_HEADER_DOWN];
};

/// @brief Packet header when injecting encapsulated packet, ready to be sent on the wire, with time extension.
///
/// Directly forwarded to DSP/BVN destination, applying the specified PHB.
#define SIZEOF_LA_PACKET_INJECT_HEADER_DOWN_WITH_TIME_EXT 21
union la_packet_inject_header_down_with_time_ext {
    struct {
        uint64_t cpu_time : 32;    //<  Time extension, for use when sending PTP sync/delay request
        uint64_t ext_type : 8;     //<  Must be INJECT_HEADER_EXT_TYPE_TIME
        uint64_t internal : 8;     //<  Must be 0
        uint64_t lm_offset : 7;    //<  Counter stamp - offset
        uint64_t padding1 : 1;     //<  padding
        uint64_t lm_opcode : 4;    //<  Counter stamp - opcode
        uint64_t ts_offset : 7;    //<  Time stamp - offset
        uint64_t padding2 : 1;     //<  padding
        uint64_t ts_opcode : 4;    //<  Time stamp - opcode
        uint64_t padding3 : 4;     //<  padding
        uint64_t down_nh : 12;     //<  NH
        uint64_t l3_dlp : 16;      //<  L3 DLP
        uint64_t counter_ptr : 20; //<  Counter pointer (TBD)
        uint64_t padding4 : 8;     //<  padding.
        uint64_t dest : 20;        //<  Destination ID - DSP or BVN.
        uint64_t phb_dp : 2;       //<  Drop Precedence of the packet. 0 means green.
        uint64_t phb_tc : 3;       //<  Traffic Class of the packet. According to 802.1q, 7 is high
        uint64_t encap : 3;        //<  Encapsulation type
        uint64_t type : 8;         //<  Inject type
    };
    uint8_t raw[SIZEOF_LA_PACKET_INJECT_HEADER_DOWN_WITH_TIME_EXT];
};

/// @brief Packet header when injecting an Ethernet packet.
///
/// The packet will be processed as a regular packet.
#define SIZEOF_LA_PACKET_INJECT_HEADER_UP 17
union la_packet_inject_header_up {
    struct {
        uint64_t ext_type : 8;     ///<  Must be INJECT_HEADER_EXT_TYPE_NONE
        uint64_t internal : 8;     ///<  Internal. Must be set to 0
        uint64_t lm_offset : 7;    ///<  Counter stamp - offset
        uint64_t padding1 : 1;     ///<  padding
        uint64_t lm_opcode : 4;    ///<  Counter stamp - opcode
        uint64_t ts_offset : 7;    ///<  Time stamp - offset
        uint64_t padding2 : 1;     ///<  padding
        uint64_t ts_opcode : 4;    ///<  Time stamp - opcode
        uint64_t padding3 : 32;    ///<  Padding.
        uint64_t counter_ptr : 20; ///<  Counter pointer (TBD)
        uint64_t ssp_gid : 12;     ///<  Source system port GID.
        uint64_t fwd_qos_tag : 7;  ///<  QOS tag (DSCP).
        uint64_t qos_group : 7;    ///<  QOS group.
        uint64_t phb_dp : 2;       ///<  Drop Precedence of the packet. 0 means green.
        uint64_t phb_tc : 3;       ///<  Traffic Class of the packet. According to 802.1q, 7 is high.
        uint64_t phb_src : 1;      ///< Source for obtaining TC either from inject packet or packet processing.
        uint64_t padding4 : 4;     ///<  Padding.
        uint64_t type : 8;         ///<  Inject type (INJECT_HEADER_TYPE_ETH_UP)
    };
    uint8_t raw[SIZEOF_LA_PACKET_INJECT_HEADER_UP];
};

/// @brief Packet header when injecting an Ethernet packet with forwarding destination replaced by the destination in the inject
/// header. For example, client can specify MCID as the destination.
///
/// The packet will be processed as a regular packet. But the forwarding destination replaced by the destination in the inject
/// heade.
#define SIZEOF_LA_PACKET_INJECT_HEADER_UP_DESTINATION_OVERRIDE 17
union la_packet_inject_header_up_destination_override {
    struct {
        uint64_t ext_type : 8;     ///<  Must be INJECT_HEADER_EXT_TYPE_NONE
        uint64_t internal : 8;     ///<  Internal. Must be set to 0
        uint64_t lm_offset : 7;    ///<  Counter stamp - offset
        uint64_t padding1 : 1;     ///<  padding
        uint64_t lm_opcode : 4;    ///<  Counter stamp - opcode
        uint64_t ts_offset : 7;    ///<  Time stamp - offset
        uint64_t padding2 : 1;     ///<  padding
        uint64_t ts_opcode : 4;    ///<  Time stamp - opcode
        uint64_t padding3 : 32;    ///<  Padding.
        uint64_t counter_ptr : 20; ///<  Counter pointer (TBD)
        uint64_t ssp_gid : 12;     ///<  Source system port GID.
        uint64_t destination : 20; ///<  Destination
        uint64_t padding4 : 4;     ///<  Padding.
        uint64_t type : 8;         ///<  Inject type (INJECT_HEADER_TYPE_ETH_UP)
    };
    uint8_t raw[SIZEOF_LA_PACKET_INJECT_HEADER_UP_DESTINATION_OVERRIDE];
};

/// @brief Packet header when injecting an Ethernet packet, with time extension.
///
/// The packet will be processed as a regular packet.
#define SIZEOF_LA_PACKET_INJECT_HEADER_UP_WITH_TIME_EXT 21
union la_packet_inject_header_up_with_time_ext {
    struct {
        uint64_t cpu_time : 32;    // Time extension, for use when sending PTP sync/delay request
        uint64_t ext_type : 8;     //<  Must be INJECT_HEADER_EXT_TYPE_TIME
        uint64_t internal : 8;     ///<  Internal. Must be set to 0
        uint64_t lm_offset : 7;    ///<  Counter stamp - offset
        uint64_t padding1 : 1;     ///<  padding
        uint64_t lm_opcode : 4;    ///<  Counter stamp - opcode
        uint64_t ts_offset : 7;    ///<  Time stamp - offset
        uint64_t padding2 : 1;     ///<  padding
        uint64_t ts_opcode : 4;    ///<  Time stamp - opcode
        uint64_t padding3 : 32;    ///<  Padding.
        uint64_t counter_ptr : 20; ///<  Counter pointer (TBD)
        uint64_t ssp_gid : 12;     ///<  Source system port GID.
        uint64_t fwd_qos_tag : 7;  ///<  QOS tag (DSCP).
        uint64_t qos_group : 7;    ///<  QOS group.
        uint64_t phb_dp : 2;       ///<  Drop Precedence of the packet. 0 means green.
        uint64_t phb_tc : 3;       ///<  Traffic Class of the packet. According to 802.1q, 7 is high.
        uint64_t padding4 : 5;     ///<  Padding.
        uint64_t type : 8;         ///<  Inject type (INJECT_HEADER_TYPE_ETH_UP)
    };
    uint8_t raw[SIZEOF_LA_PACKET_INJECT_HEADER_UP_WITH_TIME_EXT];
};

/// @brief Punt packet header.
#define SIZEOF_LA_PACKET_PUNT_HEADER 28
union la_packet_punt_header {
    struct {
        uint64_t receive_time : 32;      ///<  RX nanosecond time
        uint64_t time_stamp : 64;        ///<  Time stamp value.
        uint64_t relay_id : 14;          ///<  Punt relay ID.
        uint64_t padding1 : 2;           ///<  padding
        uint64_t destination_lp : 20;    ///<  Destination logical port GID.
        uint64_t source_lp : 20;         ///<  Source logical port GID.
        uint64_t destination_sp : 16;    ///<  Destination system port GID.
        uint64_t source_sp : 16;         ///<  Source system port GID.
        uint64_t lpts_flow_type : 8;     ///<  LPTS flow type.
        uint64_t code : 8;               ///<  Punt code.
        uint64_t source : 4;             ///<  Punt source.
        uint64_t next_header_offset : 8; ///<  Offset to L3 header.
        uint64_t padding2 : 3;           ///<  padding
        uint64_t fwd_header_type : 4;    ///<  Forward header type.
        uint64_t next_header : 5;        ///<  Next header protocol.
    };
    uint8_t raw[SIZEOF_LA_PACKET_PUNT_HEADER];
};

/// @brief MAC learn record packet header.
#define SIZEOF_LA_LEARN_RECORD_HEADER 5
union la_learn_record_header {
    struct {
        uint8_t num_lr_records; ///<  Number of Learn Records
        uint32_t lri_header;    ///<  LRI (Learn Record In) header
    };
    uint8_t raw[SIZEOF_LA_LEARN_RECORD_HEADER];
};

/// @brief MAC learn record header.
#define SIZEOF_LA_LEARN_RECORD 11
union la_learn_record {
    struct {
        uint8_t mact_ldb : 4;   ///<  Internal(device) MAC table ID
        uint64_t mac_sa : 48;   ///<  Source MAC address
        uint32_t relay_id : 14; ///<  MAC Relay ID
        uint32_t slp : 20;      ///<  Source Logical Port
        uint8_t command : 2;    ///<  Learn Command Type
    };
    uint8_t raw[SIZEOF_LA_LEARN_RECORD];
};

/// @brief MAC learn notification.
#define NUM_LEARN_RECORDS_PER_NOTIFICATION 11
#define SIZEOF_LA_LEARN_NOTIFICATION (NUM_LEARN_RECORDS_PER_NOTIFICATION * SIZEOF_LA_LEARN_RECORD + SIZEOF_LA_LEARN_RECORD_HEADER)
union la_learn_notification {
    struct {
        la_learn_record records[NUM_LEARN_RECORDS_PER_NOTIFICATION]; ///<  11 Learn Records
        la_learn_record_header header;                               ///<  Learn Record Header
    };
    uint8_t raw[SIZEOF_LA_LEARN_NOTIFICATION];
};

#pragma pack(pop)

static inline void
packet_header_bswap(const unsigned char* c_header, size_t bytes_nr, unsigned char* out_npl_header)
{
    for (size_t src_index = 0; src_index < bytes_nr; src_index++) {
        size_t dst_index = bytes_nr - src_index - 1;

        out_npl_header[dst_index] = c_header[src_index];
    }
}
} // namespace silicon_one

#endif // __LA_PACKET_HEADERS_H__
