
// This file has been automatically generated using nplc.py. Do not edit it manually.
// Version: 1.76.2_0.0.0.0 generated on devsrv15.leaba.local at 2021-05-12 16:09:15



#ifndef __NPL_TABLE_TYPES_H__
#define __NPL_TABLE_TYPES_H__

#include "nplapi/npl_enums.h"
#include "nplapi/npl_enum_to_string.h"
#include "nplapi/npl_types.h"
#include "common/bit_vector.h"
using silicon_one::bit_vector;
using silicon_one::bit_vector64_t;
using silicon_one::bit_vector128_t;
using silicon_one::bit_vector192_t;
using silicon_one::bit_vector384_t;
#include <memory.h>

#pragma pack(push, 1)

/// API-s for table: acl_map_fi_header_type_to_protocol_number_table

typedef enum
{
    NPL_ACL_MAP_FI_HEADER_TYPE_TO_PROTOCOL_NUMBER_TABLE_ACTION_UPDATE = 0x0
} npl_acl_map_fi_header_type_to_protocol_number_table_action_e;

struct npl_acl_map_fi_header_type_to_protocol_number_table_update_payload_t
{
    uint64_t is_valid : 1;
    uint64_t acl_l4_protocol : 2;
    npl_protocol_type_padded_t protocol_type;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_acl_map_fi_header_type_to_protocol_number_table_update_payload_t element);
std::string to_short_string(npl_acl_map_fi_header_type_to_protocol_number_table_update_payload_t element);

struct npl_acl_map_fi_header_type_to_protocol_number_table_key_t
{
    npl_protocol_type_e fi_hdr_type;
    
    npl_acl_map_fi_header_type_to_protocol_number_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_acl_map_fi_header_type_to_protocol_number_table_key_t element);
std::string to_short_string(struct npl_acl_map_fi_header_type_to_protocol_number_table_key_t element);

struct npl_acl_map_fi_header_type_to_protocol_number_table_value_t
{
    npl_acl_map_fi_header_type_to_protocol_number_table_action_e action;
    union npl_acl_map_fi_header_type_to_protocol_number_table_payloads_t {
        npl_acl_map_fi_header_type_to_protocol_number_table_update_payload_t update;
    } payloads;
    std::string npl_action_enum_to_string(const npl_acl_map_fi_header_type_to_protocol_number_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_ACL_MAP_FI_HEADER_TYPE_TO_PROTOCOL_NUMBER_TABLE_ACTION_UPDATE:
            {
                return "NPL_ACL_MAP_FI_HEADER_TYPE_TO_PROTOCOL_NUMBER_TABLE_ACTION_UPDATE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_acl_map_fi_header_type_to_protocol_number_table_action_e");
        }
        return "";
    }
    npl_acl_map_fi_header_type_to_protocol_number_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_acl_map_fi_header_type_to_protocol_number_table_value_t element);
std::string to_short_string(struct npl_acl_map_fi_header_type_to_protocol_number_table_value_t element);

/// API-s for table: additional_labels_table

typedef enum
{
    NPL_ADDITIONAL_LABELS_TABLE_ACTION_WRITE = 0x0
} npl_additional_labels_table_action_e;

struct npl_additional_labels_table_key_t
{
    uint64_t labels_index : 12;
    
    npl_additional_labels_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_additional_labels_table_key_t element);
std::string to_short_string(struct npl_additional_labels_table_key_t element);

struct npl_additional_labels_table_value_t
{
    npl_additional_labels_table_action_e action;
    union npl_additional_labels_table_payloads_t {
        npl_additional_labels_t additional_labels;
    } payloads;
    std::string npl_action_enum_to_string(const npl_additional_labels_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_ADDITIONAL_LABELS_TABLE_ACTION_WRITE:
            {
                return "NPL_ADDITIONAL_LABELS_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_additional_labels_table_action_e");
        }
        return "";
    }
    npl_additional_labels_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_additional_labels_table_value_t element);
std::string to_short_string(struct npl_additional_labels_table_value_t element);

/// API-s for table: all_reachable_vector

typedef enum
{
    NPL_ALL_REACHABLE_VECTOR_ACTION_WRITE = 0x0
} npl_all_reachable_vector_action_e;

struct npl_all_reachable_vector_key_t
{
    
    
    npl_all_reachable_vector_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_all_reachable_vector_key_t element);
std::string to_short_string(struct npl_all_reachable_vector_key_t element);

struct npl_all_reachable_vector_value_t
{
    npl_all_reachable_vector_action_e action;
    union npl_all_reachable_vector_payloads_t {
        npl_all_reachable_vector_result_t all_reachable_vector_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_all_reachable_vector_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_ALL_REACHABLE_VECTOR_ACTION_WRITE:
            {
                return "NPL_ALL_REACHABLE_VECTOR_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_all_reachable_vector_action_e");
        }
        return "";
    }
    npl_all_reachable_vector_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_all_reachable_vector_value_t element);
std::string to_short_string(struct npl_all_reachable_vector_value_t element);

/// API-s for table: bfd_desired_tx_interval_table

typedef enum
{
    NPL_BFD_DESIRED_TX_INTERVAL_TABLE_ACTION_WRITE = 0x0
} npl_bfd_desired_tx_interval_table_action_e;

struct npl_bfd_desired_tx_interval_table_key_t
{
    uint64_t interval_selector : 3;
    
    npl_bfd_desired_tx_interval_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_bfd_desired_tx_interval_table_key_t element);
std::string to_short_string(struct npl_bfd_desired_tx_interval_table_key_t element);

struct npl_bfd_desired_tx_interval_table_value_t
{
    npl_bfd_desired_tx_interval_table_action_e action;
    union npl_bfd_desired_tx_interval_table_payloads_t {
        uint64_t desired_min_tx_interval : 32;
    } payloads;
    std::string npl_action_enum_to_string(const npl_bfd_desired_tx_interval_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_BFD_DESIRED_TX_INTERVAL_TABLE_ACTION_WRITE:
            {
                return "NPL_BFD_DESIRED_TX_INTERVAL_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_bfd_desired_tx_interval_table_action_e");
        }
        return "";
    }
    npl_bfd_desired_tx_interval_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_bfd_desired_tx_interval_table_value_t element);
std::string to_short_string(struct npl_bfd_desired_tx_interval_table_value_t element);

/// API-s for table: bfd_detection_multiple_table

typedef enum
{
    NPL_BFD_DETECTION_MULTIPLE_TABLE_ACTION_WRITE = 0x0
} npl_bfd_detection_multiple_table_action_e;

struct npl_bfd_detection_multiple_table_key_t
{
    uint64_t interval_selector : 3;
    
    npl_bfd_detection_multiple_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_bfd_detection_multiple_table_key_t element);
std::string to_short_string(struct npl_bfd_detection_multiple_table_key_t element);

struct npl_bfd_detection_multiple_table_value_t
{
    npl_bfd_detection_multiple_table_action_e action;
    union npl_bfd_detection_multiple_table_payloads_t {
        uint64_t detection_mult : 8;
    } payloads;
    std::string npl_action_enum_to_string(const npl_bfd_detection_multiple_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_BFD_DETECTION_MULTIPLE_TABLE_ACTION_WRITE:
            {
                return "NPL_BFD_DETECTION_MULTIPLE_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_bfd_detection_multiple_table_action_e");
        }
        return "";
    }
    npl_bfd_detection_multiple_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_bfd_detection_multiple_table_value_t element);
std::string to_short_string(struct npl_bfd_detection_multiple_table_value_t element);

/// API-s for table: bfd_event_queue_table

typedef enum
{
    NPL_BFD_EVENT_QUEUE_TABLE_ACTION_NO_OP = 0x0
} npl_bfd_event_queue_table_action_e;

struct npl_bfd_event_queue_table_key_t
{
    uint64_t rmep_id : 13;
    uint64_t mep_id : 13;
    npl_oamp_event_type_e oamp_event;
    uint64_t diag_code : 5;
    uint64_t flags_and_state : 8;
    
    npl_bfd_event_queue_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_bfd_event_queue_table_key_t element);
std::string to_short_string(struct npl_bfd_event_queue_table_key_t element);

struct npl_bfd_event_queue_table_value_t
{
    npl_bfd_event_queue_table_action_e action;
    std::string npl_action_enum_to_string(const npl_bfd_event_queue_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_BFD_EVENT_QUEUE_TABLE_ACTION_NO_OP:
            {
                return "NPL_BFD_EVENT_QUEUE_TABLE_ACTION_NO_OP(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_bfd_event_queue_table_action_e");
        }
        return "";
    }
    npl_bfd_event_queue_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_bfd_event_queue_table_value_t element);
std::string to_short_string(struct npl_bfd_event_queue_table_value_t element);

/// API-s for table: bfd_inject_inner_da_high_table

typedef enum
{
    NPL_BFD_INJECT_INNER_DA_HIGH_TABLE_ACTION_SET_INJECT_INNER_DA = 0x0
} npl_bfd_inject_inner_da_high_table_action_e;

struct npl_bfd_inject_inner_da_high_table_set_inject_inner_da_payload_t
{
    uint64_t da : 16;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_bfd_inject_inner_da_high_table_set_inject_inner_da_payload_t element);
std::string to_short_string(npl_bfd_inject_inner_da_high_table_set_inject_inner_da_payload_t element);

struct npl_bfd_inject_inner_da_high_table_key_t
{
    
    
    npl_bfd_inject_inner_da_high_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_bfd_inject_inner_da_high_table_key_t element);
std::string to_short_string(struct npl_bfd_inject_inner_da_high_table_key_t element);

struct npl_bfd_inject_inner_da_high_table_value_t
{
    npl_bfd_inject_inner_da_high_table_action_e action;
    union npl_bfd_inject_inner_da_high_table_payloads_t {
        npl_bfd_inject_inner_da_high_table_set_inject_inner_da_payload_t set_inject_inner_da;
    } payloads;
    std::string npl_action_enum_to_string(const npl_bfd_inject_inner_da_high_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_BFD_INJECT_INNER_DA_HIGH_TABLE_ACTION_SET_INJECT_INNER_DA:
            {
                return "NPL_BFD_INJECT_INNER_DA_HIGH_TABLE_ACTION_SET_INJECT_INNER_DA(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_bfd_inject_inner_da_high_table_action_e");
        }
        return "";
    }
    npl_bfd_inject_inner_da_high_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_bfd_inject_inner_da_high_table_value_t element);
std::string to_short_string(struct npl_bfd_inject_inner_da_high_table_value_t element);

/// API-s for table: bfd_inject_inner_da_low_table

typedef enum
{
    NPL_BFD_INJECT_INNER_DA_LOW_TABLE_ACTION_SET_INJECT_INNER_DA = 0x0
} npl_bfd_inject_inner_da_low_table_action_e;

struct npl_bfd_inject_inner_da_low_table_set_inject_inner_da_payload_t
{
    uint64_t da : 32;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_bfd_inject_inner_da_low_table_set_inject_inner_da_payload_t element);
std::string to_short_string(npl_bfd_inject_inner_da_low_table_set_inject_inner_da_payload_t element);

struct npl_bfd_inject_inner_da_low_table_key_t
{
    
    
    npl_bfd_inject_inner_da_low_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_bfd_inject_inner_da_low_table_key_t element);
std::string to_short_string(struct npl_bfd_inject_inner_da_low_table_key_t element);

struct npl_bfd_inject_inner_da_low_table_value_t
{
    npl_bfd_inject_inner_da_low_table_action_e action;
    union npl_bfd_inject_inner_da_low_table_payloads_t {
        npl_bfd_inject_inner_da_low_table_set_inject_inner_da_payload_t set_inject_inner_da;
    } payloads;
    std::string npl_action_enum_to_string(const npl_bfd_inject_inner_da_low_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_BFD_INJECT_INNER_DA_LOW_TABLE_ACTION_SET_INJECT_INNER_DA:
            {
                return "NPL_BFD_INJECT_INNER_DA_LOW_TABLE_ACTION_SET_INJECT_INNER_DA(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_bfd_inject_inner_da_low_table_action_e");
        }
        return "";
    }
    npl_bfd_inject_inner_da_low_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_bfd_inject_inner_da_low_table_value_t element);
std::string to_short_string(struct npl_bfd_inject_inner_da_low_table_value_t element);

/// API-s for table: bfd_inject_inner_ethernet_header_static_table

typedef enum
{
    NPL_BFD_INJECT_INNER_ETHERNET_HEADER_STATIC_TABLE_ACTION_SET_INNER_INJECT_ETH = 0x0
} npl_bfd_inject_inner_ethernet_header_static_table_action_e;

struct npl_bfd_inject_inner_ethernet_header_static_table_set_inner_inject_eth_payload_t
{
    uint64_t type : 16;
    uint64_t pkt_size : 14;
    uint64_t size1 : 8;
    uint64_t size2 : 8;
    uint64_t size3 : 8;
    uint64_t bitmap : 6;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_bfd_inject_inner_ethernet_header_static_table_set_inner_inject_eth_payload_t element);
std::string to_short_string(npl_bfd_inject_inner_ethernet_header_static_table_set_inner_inject_eth_payload_t element);

struct npl_bfd_inject_inner_ethernet_header_static_table_key_t
{
    uint64_t requires_inject_up : 1;
    npl_bfd_transport_and_label_t transport;
    
    npl_bfd_inject_inner_ethernet_header_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_bfd_inject_inner_ethernet_header_static_table_key_t element);
std::string to_short_string(struct npl_bfd_inject_inner_ethernet_header_static_table_key_t element);

struct npl_bfd_inject_inner_ethernet_header_static_table_value_t
{
    npl_bfd_inject_inner_ethernet_header_static_table_action_e action;
    union npl_bfd_inject_inner_ethernet_header_static_table_payloads_t {
        npl_bfd_inject_inner_ethernet_header_static_table_set_inner_inject_eth_payload_t set_inner_inject_eth;
    } payloads;
    std::string npl_action_enum_to_string(const npl_bfd_inject_inner_ethernet_header_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_BFD_INJECT_INNER_ETHERNET_HEADER_STATIC_TABLE_ACTION_SET_INNER_INJECT_ETH:
            {
                return "NPL_BFD_INJECT_INNER_ETHERNET_HEADER_STATIC_TABLE_ACTION_SET_INNER_INJECT_ETH(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_bfd_inject_inner_ethernet_header_static_table_action_e");
        }
        return "";
    }
    npl_bfd_inject_inner_ethernet_header_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_bfd_inject_inner_ethernet_header_static_table_value_t element);
std::string to_short_string(struct npl_bfd_inject_inner_ethernet_header_static_table_value_t element);

/// API-s for table: bfd_inject_ttl_static_table

typedef enum
{
    NPL_BFD_INJECT_TTL_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_bfd_inject_ttl_static_table_action_e;

struct npl_bfd_inject_ttl_static_table_key_t
{
    uint64_t requires_inject_up : 1;
    uint64_t requires_label : 1;
    
    npl_bfd_inject_ttl_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_bfd_inject_ttl_static_table_key_t element);
std::string to_short_string(struct npl_bfd_inject_ttl_static_table_key_t element);

struct npl_bfd_inject_ttl_static_table_value_t
{
    npl_bfd_inject_ttl_static_table_action_e action;
    union npl_bfd_inject_ttl_static_table_payloads_t {
        npl_bfd_inject_ttl_t bfd_inject_ttl;
    } payloads;
    std::string npl_action_enum_to_string(const npl_bfd_inject_ttl_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_BFD_INJECT_TTL_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_BFD_INJECT_TTL_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_bfd_inject_ttl_static_table_action_e");
        }
        return "";
    }
    npl_bfd_inject_ttl_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_bfd_inject_ttl_static_table_value_t element);
std::string to_short_string(struct npl_bfd_inject_ttl_static_table_value_t element);

/// API-s for table: bfd_ipv6_sip_A_table

typedef enum
{
    NPL_BFD_IPV6_SIP_A_TABLE_ACTION_WRITE = 0x0
} npl_bfd_ipv6_sip_A_table_action_e;

struct npl_bfd_ipv6_sip_A_table_key_t
{
    npl_bfd_ipv6_selector_t bfd_ipv6_selector;
    
    npl_bfd_ipv6_sip_A_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_bfd_ipv6_sip_A_table_key_t element);
std::string to_short_string(struct npl_bfd_ipv6_sip_A_table_key_t element);

struct npl_bfd_ipv6_sip_A_table_value_t
{
    npl_bfd_ipv6_sip_A_table_action_e action;
    union npl_bfd_ipv6_sip_A_table_payloads_t {
        npl_bfd_local_ipv6_sip_t bfd_local_ipv6_A_sip;
    } payloads;
    std::string npl_action_enum_to_string(const npl_bfd_ipv6_sip_A_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_BFD_IPV6_SIP_A_TABLE_ACTION_WRITE:
            {
                return "NPL_BFD_IPV6_SIP_A_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_bfd_ipv6_sip_A_table_action_e");
        }
        return "";
    }
    npl_bfd_ipv6_sip_A_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_bfd_ipv6_sip_A_table_value_t element);
std::string to_short_string(struct npl_bfd_ipv6_sip_A_table_value_t element);

/// API-s for table: bfd_ipv6_sip_B_table

typedef enum
{
    NPL_BFD_IPV6_SIP_B_TABLE_ACTION_WRITE = 0x0
} npl_bfd_ipv6_sip_B_table_action_e;

struct npl_bfd_ipv6_sip_B_table_key_t
{
    npl_bfd_ipv6_selector_t bfd_ipv6_selector;
    
    npl_bfd_ipv6_sip_B_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_bfd_ipv6_sip_B_table_key_t element);
std::string to_short_string(struct npl_bfd_ipv6_sip_B_table_key_t element);

struct npl_bfd_ipv6_sip_B_table_value_t
{
    npl_bfd_ipv6_sip_B_table_action_e action;
    union npl_bfd_ipv6_sip_B_table_payloads_t {
        npl_bfd_local_ipv6_sip_t bfd_local_ipv6_B_sip;
    } payloads;
    std::string npl_action_enum_to_string(const npl_bfd_ipv6_sip_B_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_BFD_IPV6_SIP_B_TABLE_ACTION_WRITE:
            {
                return "NPL_BFD_IPV6_SIP_B_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_bfd_ipv6_sip_B_table_action_e");
        }
        return "";
    }
    npl_bfd_ipv6_sip_B_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_bfd_ipv6_sip_B_table_value_t element);
std::string to_short_string(struct npl_bfd_ipv6_sip_B_table_value_t element);

/// API-s for table: bfd_ipv6_sip_C_table

typedef enum
{
    NPL_BFD_IPV6_SIP_C_TABLE_ACTION_WRITE = 0x0
} npl_bfd_ipv6_sip_C_table_action_e;

struct npl_bfd_ipv6_sip_C_table_key_t
{
    npl_bfd_ipv6_selector_t bfd_ipv6_selector;
    
    npl_bfd_ipv6_sip_C_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_bfd_ipv6_sip_C_table_key_t element);
std::string to_short_string(struct npl_bfd_ipv6_sip_C_table_key_t element);

struct npl_bfd_ipv6_sip_C_table_value_t
{
    npl_bfd_ipv6_sip_C_table_action_e action;
    union npl_bfd_ipv6_sip_C_table_payloads_t {
        npl_bfd_local_ipv6_sip_t bfd_local_ipv6_C_sip;
    } payloads;
    std::string npl_action_enum_to_string(const npl_bfd_ipv6_sip_C_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_BFD_IPV6_SIP_C_TABLE_ACTION_WRITE:
            {
                return "NPL_BFD_IPV6_SIP_C_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_bfd_ipv6_sip_C_table_action_e");
        }
        return "";
    }
    npl_bfd_ipv6_sip_C_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_bfd_ipv6_sip_C_table_value_t element);
std::string to_short_string(struct npl_bfd_ipv6_sip_C_table_value_t element);

/// API-s for table: bfd_ipv6_sip_D_table

typedef enum
{
    NPL_BFD_IPV6_SIP_D_TABLE_ACTION_WRITE = 0x0
} npl_bfd_ipv6_sip_D_table_action_e;

struct npl_bfd_ipv6_sip_D_table_key_t
{
    npl_bfd_ipv6_selector_t bfd_ipv6_selector;
    
    npl_bfd_ipv6_sip_D_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_bfd_ipv6_sip_D_table_key_t element);
std::string to_short_string(struct npl_bfd_ipv6_sip_D_table_key_t element);

struct npl_bfd_ipv6_sip_D_table_value_t
{
    npl_bfd_ipv6_sip_D_table_action_e action;
    union npl_bfd_ipv6_sip_D_table_payloads_t {
        npl_bfd_local_ipv6_sip_t bfd_local_ipv6_D_sip;
    } payloads;
    std::string npl_action_enum_to_string(const npl_bfd_ipv6_sip_D_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_BFD_IPV6_SIP_D_TABLE_ACTION_WRITE:
            {
                return "NPL_BFD_IPV6_SIP_D_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_bfd_ipv6_sip_D_table_action_e");
        }
        return "";
    }
    npl_bfd_ipv6_sip_D_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_bfd_ipv6_sip_D_table_value_t element);
std::string to_short_string(struct npl_bfd_ipv6_sip_D_table_value_t element);

/// API-s for table: bfd_punt_encap_static_table

typedef enum
{
    NPL_BFD_PUNT_ENCAP_STATIC_TABLE_ACTION_BFD_HDR_PUNT_ENCAP_ACTION = 0x0
} npl_bfd_punt_encap_static_table_action_e;

struct npl_bfd_punt_encap_static_table_bfd_hdr_punt_encap_action_payload_t
{
    uint64_t fwd_offset : 7;
    npl_npu_mirror_or_redirect_encap_type_e nmret;
    npl_lpts_tcam_first_result_encap_data_msb_t lpts_punt_encap;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_bfd_punt_encap_static_table_bfd_hdr_punt_encap_action_payload_t element);
std::string to_short_string(npl_bfd_punt_encap_static_table_bfd_hdr_punt_encap_action_payload_t element);

struct npl_bfd_punt_encap_static_table_key_t
{
    uint64_t encap_result : 1;
    
    npl_bfd_punt_encap_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_bfd_punt_encap_static_table_key_t element);
std::string to_short_string(struct npl_bfd_punt_encap_static_table_key_t element);

struct npl_bfd_punt_encap_static_table_value_t
{
    npl_bfd_punt_encap_static_table_action_e action;
    union npl_bfd_punt_encap_static_table_payloads_t {
        npl_bfd_punt_encap_static_table_bfd_hdr_punt_encap_action_payload_t bfd_hdr_punt_encap_action;
    } payloads;
    std::string npl_action_enum_to_string(const npl_bfd_punt_encap_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_BFD_PUNT_ENCAP_STATIC_TABLE_ACTION_BFD_HDR_PUNT_ENCAP_ACTION:
            {
                return "NPL_BFD_PUNT_ENCAP_STATIC_TABLE_ACTION_BFD_HDR_PUNT_ENCAP_ACTION(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_bfd_punt_encap_static_table_action_e");
        }
        return "";
    }
    npl_bfd_punt_encap_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_bfd_punt_encap_static_table_value_t element);
std::string to_short_string(struct npl_bfd_punt_encap_static_table_value_t element);

/// API-s for table: bfd_required_tx_interval_table

typedef enum
{
    NPL_BFD_REQUIRED_TX_INTERVAL_TABLE_ACTION_WRITE = 0x0
} npl_bfd_required_tx_interval_table_action_e;

struct npl_bfd_required_tx_interval_table_key_t
{
    uint64_t interval_selector : 3;
    
    npl_bfd_required_tx_interval_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_bfd_required_tx_interval_table_key_t element);
std::string to_short_string(struct npl_bfd_required_tx_interval_table_key_t element);

struct npl_bfd_required_tx_interval_table_value_t
{
    npl_bfd_required_tx_interval_table_action_e action;
    union npl_bfd_required_tx_interval_table_payloads_t {
        uint64_t required_min_tx_interval : 32;
    } payloads;
    std::string npl_action_enum_to_string(const npl_bfd_required_tx_interval_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_BFD_REQUIRED_TX_INTERVAL_TABLE_ACTION_WRITE:
            {
                return "NPL_BFD_REQUIRED_TX_INTERVAL_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_bfd_required_tx_interval_table_action_e");
        }
        return "";
    }
    npl_bfd_required_tx_interval_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_bfd_required_tx_interval_table_value_t element);
std::string to_short_string(struct npl_bfd_required_tx_interval_table_value_t element);

/// API-s for table: bfd_rx_table

typedef enum
{
    NPL_BFD_RX_TABLE_ACTION_WRITE = 0x0
} npl_bfd_rx_table_action_e;

struct npl_bfd_rx_table_key_t
{
    uint64_t your_discr_31_16_ : 16;
    uint64_t your_discr_23_16_ : 8;
    uint64_t dst_port : 16;
    npl_bfd_session_protocol_e protocol_type;
    
    npl_bfd_rx_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_bfd_rx_table_key_t element);
std::string to_short_string(struct npl_bfd_rx_table_key_t element);

struct npl_bfd_rx_table_value_t
{
    npl_bfd_rx_table_action_e action;
    union npl_bfd_rx_table_payloads_t {
        npl_bfd_em_lookup_t bfd_em_lookup_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_bfd_rx_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_BFD_RX_TABLE_ACTION_WRITE:
            {
                return "NPL_BFD_RX_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_bfd_rx_table_action_e");
        }
        return "";
    }
    npl_bfd_rx_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_bfd_rx_table_value_t element);
std::string to_short_string(struct npl_bfd_rx_table_value_t element);

/// API-s for table: bfd_set_inject_type_static_table

typedef enum
{
    NPL_BFD_SET_INJECT_TYPE_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_bfd_set_inject_type_static_table_action_e;

struct npl_bfd_set_inject_type_static_table_key_t
{
    uint64_t pd_pd_npu_host_inject_fields_aux_data_bfd_requires_inject_up : 1;
    
    npl_bfd_set_inject_type_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_bfd_set_inject_type_static_table_key_t element);
std::string to_short_string(struct npl_bfd_set_inject_type_static_table_key_t element);

struct npl_bfd_set_inject_type_static_table_value_t
{
    npl_bfd_set_inject_type_static_table_action_e action;
    union npl_bfd_set_inject_type_static_table_payloads_t {
        npl_inject_header_type_e packet_inject_header_inject_header_type;
    } payloads;
    std::string npl_action_enum_to_string(const npl_bfd_set_inject_type_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_BFD_SET_INJECT_TYPE_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_BFD_SET_INJECT_TYPE_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_bfd_set_inject_type_static_table_action_e");
        }
        return "";
    }
    npl_bfd_set_inject_type_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_bfd_set_inject_type_static_table_value_t element);
std::string to_short_string(struct npl_bfd_set_inject_type_static_table_value_t element);

/// API-s for table: bfd_udp_port_map_static_table

typedef enum
{
    NPL_BFD_UDP_PORT_MAP_STATIC_TABLE_ACTION_BFD_UDP_PORT_RESULT = 0x0
} npl_bfd_udp_port_map_static_table_action_e;

struct npl_bfd_udp_port_map_static_table_bfd_udp_port_result_payload_t
{
    uint64_t bfd_valid : 1;
    uint64_t pl_inc : 2;
    uint64_t macro_id : 8;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_bfd_udp_port_map_static_table_bfd_udp_port_result_payload_t element);
std::string to_short_string(npl_bfd_udp_port_map_static_table_bfd_udp_port_result_payload_t element);

struct npl_bfd_udp_port_map_static_table_key_t
{
    uint64_t pd_redirect_stage_vars_skip_bfd_or_ttl_255 : 1;
    npl_protocol_type_e packet_header_info_type;
    uint64_t packet_ipv4_header_protocol : 8;
    uint64_t packet_ipv6_header_next_header : 8;
    uint64_t packet_header_1__udp_header_dst_port : 16;
    
    npl_bfd_udp_port_map_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_bfd_udp_port_map_static_table_key_t element);
std::string to_short_string(struct npl_bfd_udp_port_map_static_table_key_t element);

struct npl_bfd_udp_port_map_static_table_value_t
{
    npl_bfd_udp_port_map_static_table_action_e action;
    union npl_bfd_udp_port_map_static_table_payloads_t {
        npl_bfd_udp_port_map_static_table_bfd_udp_port_result_payload_t bfd_udp_port_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_bfd_udp_port_map_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_BFD_UDP_PORT_MAP_STATIC_TABLE_ACTION_BFD_UDP_PORT_RESULT:
            {
                return "NPL_BFD_UDP_PORT_MAP_STATIC_TABLE_ACTION_BFD_UDP_PORT_RESULT(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_bfd_udp_port_map_static_table_action_e");
        }
        return "";
    }
    npl_bfd_udp_port_map_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_bfd_udp_port_map_static_table_value_t element);
std::string to_short_string(struct npl_bfd_udp_port_map_static_table_value_t element);

/// API-s for table: bfd_udp_port_static_table

typedef enum
{
    NPL_BFD_UDP_PORT_STATIC_TABLE_ACTION_BFD_UDP_PORT_STATIC_RESULT = 0x0
} npl_bfd_udp_port_static_table_action_e;

struct npl_bfd_udp_port_static_table_bfd_udp_port_static_result_payload_t
{
    npl_l4_ports_header_t l4_ports;
    uint64_t length : 16;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_bfd_udp_port_static_table_bfd_udp_port_static_result_payload_t element);
std::string to_short_string(npl_bfd_udp_port_static_table_bfd_udp_port_static_result_payload_t element);

struct npl_bfd_udp_port_static_table_key_t
{
    npl_bfd_session_type_e pd_pd_npu_host_inject_fields_aux_data_bfd_session_type;
    
    npl_bfd_udp_port_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_bfd_udp_port_static_table_key_t element);
std::string to_short_string(struct npl_bfd_udp_port_static_table_key_t element);

struct npl_bfd_udp_port_static_table_value_t
{
    npl_bfd_udp_port_static_table_action_e action;
    union npl_bfd_udp_port_static_table_payloads_t {
        npl_bfd_udp_port_static_table_bfd_udp_port_static_result_payload_t bfd_udp_port_static_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_bfd_udp_port_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_BFD_UDP_PORT_STATIC_TABLE_ACTION_BFD_UDP_PORT_STATIC_RESULT:
            {
                return "NPL_BFD_UDP_PORT_STATIC_TABLE_ACTION_BFD_UDP_PORT_STATIC_RESULT(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_bfd_udp_port_static_table_action_e");
        }
        return "";
    }
    npl_bfd_udp_port_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_bfd_udp_port_static_table_value_t element);
std::string to_short_string(struct npl_bfd_udp_port_static_table_value_t element);

/// API-s for table: bitmap_oqg_map_table

typedef enum
{
    NPL_BITMAP_OQG_MAP_TABLE_ACTION_WRITE = 0x0
} npl_bitmap_oqg_map_table_action_e;

struct npl_bitmap_oqg_map_table_key_t
{
    uint64_t bitmap_oqg_map_index_index : 8;
    
    npl_bitmap_oqg_map_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_bitmap_oqg_map_table_key_t element);
std::string to_short_string(struct npl_bitmap_oqg_map_table_key_t element);

struct npl_bitmap_oqg_map_table_value_t
{
    npl_bitmap_oqg_map_table_action_e action;
    union npl_bitmap_oqg_map_table_payloads_t {
        uint64_t bitmap_oqg_map_result_oqg_id : 8;
    } payloads;
    std::string npl_action_enum_to_string(const npl_bitmap_oqg_map_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_BITMAP_OQG_MAP_TABLE_ACTION_WRITE:
            {
                return "NPL_BITMAP_OQG_MAP_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_bitmap_oqg_map_table_action_e");
        }
        return "";
    }
    npl_bitmap_oqg_map_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_bitmap_oqg_map_table_value_t element);
std::string to_short_string(struct npl_bitmap_oqg_map_table_value_t element);

/// API-s for table: bvn_tc_map_table

typedef enum
{
    NPL_BVN_TC_MAP_TABLE_ACTION_WRITE = 0x0
} npl_bvn_tc_map_table_action_e;

struct npl_bvn_tc_map_table_key_t
{
    uint64_t tc_map_profile : 3;
    uint64_t tc : 3;
    
    npl_bvn_tc_map_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_bvn_tc_map_table_key_t element);
std::string to_short_string(struct npl_bvn_tc_map_table_key_t element);

struct npl_bvn_tc_map_table_value_t
{
    npl_bvn_tc_map_table_action_e action;
    union npl_bvn_tc_map_table_payloads_t {
        uint64_t bvn_offset : 3;
    } payloads;
    std::string npl_action_enum_to_string(const npl_bvn_tc_map_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_BVN_TC_MAP_TABLE_ACTION_WRITE:
            {
                return "NPL_BVN_TC_MAP_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_bvn_tc_map_table_action_e");
        }
        return "";
    }
    npl_bvn_tc_map_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_bvn_tc_map_table_value_t element);
std::string to_short_string(struct npl_bvn_tc_map_table_value_t element);

/// API-s for table: calc_checksum_enable_table

typedef enum
{
    NPL_CALC_CHECKSUM_ENABLE_TABLE_ACTION_WRITE = 0x0
} npl_calc_checksum_enable_table_action_e;

struct npl_calc_checksum_enable_table_key_t
{
    npl_fwd_header_type_e txpp_npe_to_npe_metadata_fwd_header_type;
    
    npl_calc_checksum_enable_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_calc_checksum_enable_table_key_t element);
std::string to_short_string(struct npl_calc_checksum_enable_table_key_t element);

struct npl_calc_checksum_enable_table_value_t
{
    npl_calc_checksum_enable_table_action_e action;
    union npl_calc_checksum_enable_table_payloads_t {
        npl_calc_checksum_enable_t calc_checksum_enable;
    } payloads;
    std::string npl_action_enum_to_string(const npl_calc_checksum_enable_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_CALC_CHECKSUM_ENABLE_TABLE_ACTION_WRITE:
            {
                return "NPL_CALC_CHECKSUM_ENABLE_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_calc_checksum_enable_table_action_e");
        }
        return "";
    }
    npl_calc_checksum_enable_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_calc_checksum_enable_table_value_t element);
std::string to_short_string(struct npl_calc_checksum_enable_table_value_t element);

/// API-s for table: ccm_flags_table

typedef enum
{
    NPL_CCM_FLAGS_TABLE_ACTION_WRITE = 0x0
} npl_ccm_flags_table_action_e;

struct npl_ccm_flags_table_key_t
{
    uint64_t tx_rdi : 1;
    uint64_t ccm_period : 3;
    
    npl_ccm_flags_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ccm_flags_table_key_t element);
std::string to_short_string(struct npl_ccm_flags_table_key_t element);

struct npl_ccm_flags_table_value_t
{
    npl_ccm_flags_table_action_e action;
    union npl_ccm_flags_table_payloads_t {
        uint64_t flags : 8;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ccm_flags_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_CCM_FLAGS_TABLE_ACTION_WRITE:
            {
                return "NPL_CCM_FLAGS_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ccm_flags_table_action_e");
        }
        return "";
    }
    npl_ccm_flags_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ccm_flags_table_value_t element);
std::string to_short_string(struct npl_ccm_flags_table_value_t element);

/// API-s for table: cif2npa_c_lri_macro

typedef enum
{
    NPL_CIF2NPA_C_LRI_MACRO_ACTION_WRITE = 0x0
} npl_cif2npa_c_lri_macro_action_e;

struct npl_cif2npa_c_lri_macro_key_t
{
    
    
    npl_cif2npa_c_lri_macro_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_cif2npa_c_lri_macro_key_t element);
std::string to_short_string(struct npl_cif2npa_c_lri_macro_key_t element);

struct npl_cif2npa_c_lri_macro_value_t
{
    npl_cif2npa_c_lri_macro_action_e action;
    union npl_cif2npa_c_lri_macro_payloads_t {
        uint64_t next_macro_update_next_macro_id : 8;
    } payloads;
    std::string npl_action_enum_to_string(const npl_cif2npa_c_lri_macro_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_CIF2NPA_C_LRI_MACRO_ACTION_WRITE:
            {
                return "NPL_CIF2NPA_C_LRI_MACRO_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_cif2npa_c_lri_macro_action_e");
        }
        return "";
    }
    npl_cif2npa_c_lri_macro_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_cif2npa_c_lri_macro_value_t element);
std::string to_short_string(struct npl_cif2npa_c_lri_macro_value_t element);

/// API-s for table: cif2npa_c_mps_macro

typedef enum
{
    NPL_CIF2NPA_C_MPS_MACRO_ACTION_WRITE = 0x0
} npl_cif2npa_c_mps_macro_action_e;

struct npl_cif2npa_c_mps_macro_key_t
{
    
    
    npl_cif2npa_c_mps_macro_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_cif2npa_c_mps_macro_key_t element);
std::string to_short_string(struct npl_cif2npa_c_mps_macro_key_t element);

struct npl_cif2npa_c_mps_macro_value_t
{
    npl_cif2npa_c_mps_macro_action_e action;
    union npl_cif2npa_c_mps_macro_payloads_t {
        uint64_t next_macro_update_next_macro_id : 8;
    } payloads;
    std::string npl_action_enum_to_string(const npl_cif2npa_c_mps_macro_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_CIF2NPA_C_MPS_MACRO_ACTION_WRITE:
            {
                return "NPL_CIF2NPA_C_MPS_MACRO_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_cif2npa_c_mps_macro_action_e");
        }
        return "";
    }
    npl_cif2npa_c_mps_macro_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_cif2npa_c_mps_macro_value_t element);
std::string to_short_string(struct npl_cif2npa_c_mps_macro_value_t element);

/// API-s for table: counters_block_config_table

typedef enum
{
    NPL_COUNTERS_BLOCK_CONFIG_TABLE_ACTION_WRITE = 0x0
} npl_counters_block_config_table_action_e;

struct npl_counters_block_config_table_key_t
{
    uint64_t counter_block_id : 7;
    
    npl_counters_block_config_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_counters_block_config_table_key_t element);
std::string to_short_string(struct npl_counters_block_config_table_key_t element);

struct npl_counters_block_config_table_value_t
{
    npl_counters_block_config_table_action_e action;
    union npl_counters_block_config_table_payloads_t {
        npl_counters_block_config_t counters_block_config;
    } payloads;
    std::string npl_action_enum_to_string(const npl_counters_block_config_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_COUNTERS_BLOCK_CONFIG_TABLE_ACTION_WRITE:
            {
                return "NPL_COUNTERS_BLOCK_CONFIG_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_counters_block_config_table_action_e");
        }
        return "";
    }
    npl_counters_block_config_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_counters_block_config_table_value_t element);
std::string to_short_string(struct npl_counters_block_config_table_value_t element);

/// API-s for table: counters_voq_block_map_table

typedef enum
{
    NPL_COUNTERS_VOQ_BLOCK_MAP_TABLE_ACTION_WRITE = 0x0
} npl_counters_voq_block_map_table_action_e;

struct npl_counters_voq_block_map_table_key_t
{
    uint64_t voq_base_id : 10;
    
    npl_counters_voq_block_map_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_counters_voq_block_map_table_key_t element);
std::string to_short_string(struct npl_counters_voq_block_map_table_key_t element);

struct npl_counters_voq_block_map_table_value_t
{
    npl_counters_voq_block_map_table_action_e action;
    union npl_counters_voq_block_map_table_payloads_t {
        npl_counters_voq_block_map_result_t counters_voq_block_map_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_counters_voq_block_map_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_COUNTERS_VOQ_BLOCK_MAP_TABLE_ACTION_WRITE:
            {
                return "NPL_COUNTERS_VOQ_BLOCK_MAP_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_counters_voq_block_map_table_action_e");
        }
        return "";
    }
    npl_counters_voq_block_map_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_counters_voq_block_map_table_value_t element);
std::string to_short_string(struct npl_counters_voq_block_map_table_value_t element);

/// API-s for table: cud_is_multicast_bitmap

typedef enum
{
    NPL_CUD_IS_MULTICAST_BITMAP_ACTION_WRITE = 0x0
} npl_cud_is_multicast_bitmap_action_e;

struct npl_cud_is_multicast_bitmap_key_t
{
    uint64_t tx_cud_prefix : 4;
    
    npl_cud_is_multicast_bitmap_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_cud_is_multicast_bitmap_key_t element);
std::string to_short_string(struct npl_cud_is_multicast_bitmap_key_t element);

struct npl_cud_is_multicast_bitmap_value_t
{
    npl_cud_is_multicast_bitmap_action_e action;
    union npl_cud_is_multicast_bitmap_payloads_t {
        uint64_t cud_mapping_local_vars_cud_is_multicast : 1;
    } payloads;
    std::string npl_action_enum_to_string(const npl_cud_is_multicast_bitmap_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_CUD_IS_MULTICAST_BITMAP_ACTION_WRITE:
            {
                return "NPL_CUD_IS_MULTICAST_BITMAP_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_cud_is_multicast_bitmap_action_e");
        }
        return "";
    }
    npl_cud_is_multicast_bitmap_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_cud_is_multicast_bitmap_value_t element);
std::string to_short_string(struct npl_cud_is_multicast_bitmap_value_t element);

/// API-s for table: cud_narrow_hw_table

typedef enum
{
    NPL_CUD_NARROW_HW_TABLE_ACTION_WRITE = 0x0
} npl_cud_narrow_hw_table_action_e;

struct npl_cud_narrow_hw_table_key_t
{
    uint64_t cud_mapping_local_vars_mc_copy_id_12_0_ : 13;
    
    npl_cud_narrow_hw_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_cud_narrow_hw_table_key_t element);
std::string to_short_string(struct npl_cud_narrow_hw_table_key_t element);

struct npl_cud_narrow_hw_table_value_t
{
    npl_cud_narrow_hw_table_action_e action;
    union npl_cud_narrow_hw_table_payloads_t {
        uint64_t cud_mapping_local_vars_narrow_mc_cud : 40;
    } payloads;
    std::string npl_action_enum_to_string(const npl_cud_narrow_hw_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_CUD_NARROW_HW_TABLE_ACTION_WRITE:
            {
                return "NPL_CUD_NARROW_HW_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_cud_narrow_hw_table_action_e");
        }
        return "";
    }
    npl_cud_narrow_hw_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_cud_narrow_hw_table_value_t element);
std::string to_short_string(struct npl_cud_narrow_hw_table_value_t element);

/// API-s for table: cud_wide_hw_table

typedef enum
{
    NPL_CUD_WIDE_HW_TABLE_ACTION_WRITE = 0x0
} npl_cud_wide_hw_table_action_e;

struct npl_cud_wide_hw_table_key_t
{
    uint64_t cud_mapping_local_vars_mc_copy_id_12_1_ : 12;
    
    npl_cud_wide_hw_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_cud_wide_hw_table_key_t element);
std::string to_short_string(struct npl_cud_wide_hw_table_key_t element);

struct npl_cud_wide_hw_table_value_t
{
    npl_cud_wide_hw_table_action_e action;
    union npl_cud_wide_hw_table_payloads_t {
        npl_cud_mapping_local_vars_t_anonymous_union_wide_mc_cud_t cud_mapping_local_vars_wide_mc_cud;
    } payloads;
    std::string npl_action_enum_to_string(const npl_cud_wide_hw_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_CUD_WIDE_HW_TABLE_ACTION_WRITE:
            {
                return "NPL_CUD_WIDE_HW_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_cud_wide_hw_table_action_e");
        }
        return "";
    }
    npl_cud_wide_hw_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_cud_wide_hw_table_value_t element);
std::string to_short_string(struct npl_cud_wide_hw_table_value_t element);

/// API-s for table: default_egress_ipv4_sec_acl_table

typedef enum
{
    NPL_DEFAULT_EGRESS_IPV4_SEC_ACL_TABLE_ACTION_WRITE = 0x0
} npl_default_egress_ipv4_sec_acl_table_action_e;

struct npl_default_egress_ipv4_sec_acl_table_key_t
{
    uint64_t sip : 32;
    uint64_t dip : 32;
    uint64_t src_port : 16;
    uint64_t dst_port : 16;
    uint64_t fwd_qos_tag_5_0_ : 6;
    uint64_t new_ttl : 8;
    uint64_t protocol : 8;
    uint64_t tcp_flags : 6;
    npl_bool_t ip_first_fragment;
    uint64_t acl_id : 4;
    
    npl_default_egress_ipv4_sec_acl_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_default_egress_ipv4_sec_acl_table_key_t element);
std::string to_short_string(struct npl_default_egress_ipv4_sec_acl_table_key_t element);

struct npl_default_egress_ipv4_sec_acl_table_value_t
{
    npl_default_egress_ipv4_sec_acl_table_action_e action;
    union npl_default_egress_ipv4_sec_acl_table_payloads_t {
        npl_egress_sec_acl_result_t egress_sec_acl_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_default_egress_ipv4_sec_acl_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_DEFAULT_EGRESS_IPV4_SEC_ACL_TABLE_ACTION_WRITE:
            {
                return "NPL_DEFAULT_EGRESS_IPV4_SEC_ACL_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_default_egress_ipv4_sec_acl_table_action_e");
        }
        return "";
    }
    npl_default_egress_ipv4_sec_acl_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_default_egress_ipv4_sec_acl_table_value_t element);
std::string to_short_string(struct npl_default_egress_ipv4_sec_acl_table_value_t element);

/// API-s for table: default_egress_ipv6_acl_sec_table

typedef enum
{
    NPL_DEFAULT_EGRESS_IPV6_ACL_SEC_TABLE_ACTION_WRITE = 0x0
} npl_default_egress_ipv6_acl_sec_table_action_e;

struct npl_default_egress_ipv6_acl_sec_table_key_t
{
    uint64_t next_header : 8;
    uint64_t dst_port : 16;
    uint64_t acl_id : 4;
    uint64_t dip[2];
    npl_bool_t first_fragment;
    uint64_t sip[2];
    uint64_t src_port : 16;
    uint64_t qos_tag : 6;
    uint64_t tcp_flags : 6;
    
    npl_default_egress_ipv6_acl_sec_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector384_t pack(void) const;
    void unpack(bit_vector384_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_default_egress_ipv6_acl_sec_table_key_t element);
std::string to_short_string(struct npl_default_egress_ipv6_acl_sec_table_key_t element);

struct npl_default_egress_ipv6_acl_sec_table_value_t
{
    npl_default_egress_ipv6_acl_sec_table_action_e action;
    union npl_default_egress_ipv6_acl_sec_table_payloads_t {
        npl_egress_sec_acl_result_t sec_action;
    } payloads;
    std::string npl_action_enum_to_string(const npl_default_egress_ipv6_acl_sec_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_DEFAULT_EGRESS_IPV6_ACL_SEC_TABLE_ACTION_WRITE:
            {
                return "NPL_DEFAULT_EGRESS_IPV6_ACL_SEC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_default_egress_ipv6_acl_sec_table_action_e");
        }
        return "";
    }
    npl_default_egress_ipv6_acl_sec_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_default_egress_ipv6_acl_sec_table_value_t element);
std::string to_short_string(struct npl_default_egress_ipv6_acl_sec_table_value_t element);

/// API-s for table: dest_slice_voq_map_table

typedef enum
{
    NPL_DEST_SLICE_VOQ_MAP_TABLE_ACTION_WRITE = 0x0
} npl_dest_slice_voq_map_table_action_e;

struct npl_dest_slice_voq_map_table_key_t
{
    uint64_t calc_msvoq_num_input_tx_slice : 3;
    
    npl_dest_slice_voq_map_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_dest_slice_voq_map_table_key_t element);
std::string to_short_string(struct npl_dest_slice_voq_map_table_key_t element);

struct npl_dest_slice_voq_map_table_value_t
{
    npl_dest_slice_voq_map_table_action_e action;
    union npl_dest_slice_voq_map_table_payloads_t {
        npl_dest_slice_voq_map_table_result_t dest_slice_voq_map_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_dest_slice_voq_map_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_DEST_SLICE_VOQ_MAP_TABLE_ACTION_WRITE:
            {
                return "NPL_DEST_SLICE_VOQ_MAP_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_dest_slice_voq_map_table_action_e");
        }
        return "";
    }
    npl_dest_slice_voq_map_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_dest_slice_voq_map_table_value_t element);
std::string to_short_string(struct npl_dest_slice_voq_map_table_value_t element);

/// API-s for table: destination_decoding_table

typedef enum
{
    NPL_DESTINATION_DECODING_TABLE_ACTION_WRITE = 0x0
} npl_destination_decoding_table_action_e;

struct npl_destination_decoding_table_key_t
{
    uint64_t destination_encoding : 5;
    
    npl_destination_decoding_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_destination_decoding_table_key_t element);
std::string to_short_string(struct npl_destination_decoding_table_key_t element);

struct npl_destination_decoding_table_value_t
{
    npl_destination_decoding_table_action_e action;
    union npl_destination_decoding_table_payloads_t {
        npl_destination_decoding_table_result_t destination_decoding_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_destination_decoding_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_DESTINATION_DECODING_TABLE_ACTION_WRITE:
            {
                return "NPL_DESTINATION_DECODING_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_destination_decoding_table_action_e");
        }
        return "";
    }
    npl_destination_decoding_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_destination_decoding_table_value_t element);
std::string to_short_string(struct npl_destination_decoding_table_value_t element);

/// API-s for table: device_mode_table

typedef enum
{
    NPL_DEVICE_MODE_TABLE_ACTION_WRITE = 0x0
} npl_device_mode_table_action_e;

struct npl_device_mode_table_key_t
{
    
    
    npl_device_mode_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_device_mode_table_key_t element);
std::string to_short_string(struct npl_device_mode_table_key_t element);

struct npl_device_mode_table_value_t
{
    npl_device_mode_table_action_e action;
    union npl_device_mode_table_payloads_t {
        npl_device_mode_table_result_t device_mode_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_device_mode_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_DEVICE_MODE_TABLE_ACTION_WRITE:
            {
                return "NPL_DEVICE_MODE_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_device_mode_table_action_e");
        }
        return "";
    }
    npl_device_mode_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_device_mode_table_value_t element);
std::string to_short_string(struct npl_device_mode_table_value_t element);

/// API-s for table: dsp_l2_attributes_table

typedef enum
{
    NPL_DSP_L2_ATTRIBUTES_TABLE_ACTION_WRITE = 0x0
} npl_dsp_l2_attributes_table_action_e;

struct npl_dsp_l2_attributes_table_key_t
{
    uint64_t omd_txpp : 6;
    
    npl_dsp_l2_attributes_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_dsp_l2_attributes_table_key_t element);
std::string to_short_string(struct npl_dsp_l2_attributes_table_key_t element);

struct npl_dsp_l2_attributes_table_value_t
{
    npl_dsp_l2_attributes_table_action_e action;
    union npl_dsp_l2_attributes_table_payloads_t {
        npl_dsp_l2_attributes_t dsp_l2_attributes;
    } payloads;
    std::string npl_action_enum_to_string(const npl_dsp_l2_attributes_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_DSP_L2_ATTRIBUTES_TABLE_ACTION_WRITE:
            {
                return "NPL_DSP_L2_ATTRIBUTES_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_dsp_l2_attributes_table_action_e");
        }
        return "";
    }
    npl_dsp_l2_attributes_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_dsp_l2_attributes_table_value_t element);
std::string to_short_string(struct npl_dsp_l2_attributes_table_value_t element);

/// API-s for table: dsp_l3_attributes_table

typedef enum
{
    NPL_DSP_L3_ATTRIBUTES_TABLE_ACTION_WRITE = 0x0
} npl_dsp_l3_attributes_table_action_e;

struct npl_dsp_l3_attributes_table_key_t
{
    uint64_t omd_txpp : 6;
    
    npl_dsp_l3_attributes_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_dsp_l3_attributes_table_key_t element);
std::string to_short_string(struct npl_dsp_l3_attributes_table_key_t element);

struct npl_dsp_l3_attributes_table_value_t
{
    npl_dsp_l3_attributes_table_action_e action;
    union npl_dsp_l3_attributes_table_payloads_t {
        npl_dsp_l3_attributes_t dsp_l3_attributes;
    } payloads;
    std::string npl_action_enum_to_string(const npl_dsp_l3_attributes_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_DSP_L3_ATTRIBUTES_TABLE_ACTION_WRITE:
            {
                return "NPL_DSP_L3_ATTRIBUTES_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_dsp_l3_attributes_table_action_e");
        }
        return "";
    }
    npl_dsp_l3_attributes_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_dsp_l3_attributes_table_value_t element);
std::string to_short_string(struct npl_dsp_l3_attributes_table_value_t element);

/// API-s for table: dummy_dip_index_table

typedef enum
{
    NPL_DUMMY_DIP_INDEX_TABLE_ACTION_WRITE = 0x0
} npl_dummy_dip_index_table_action_e;

struct npl_dummy_dip_index_table_key_t
{
    npl_dip_index_t dummy_dip_index;
    
    npl_dummy_dip_index_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_dummy_dip_index_table_key_t element);
std::string to_short_string(struct npl_dummy_dip_index_table_key_t element);

struct npl_dummy_dip_index_table_value_t
{
    npl_dummy_dip_index_table_action_e action;
    union npl_dummy_dip_index_table_payloads_t {
        npl_bool_t dummy_data;
    } payloads;
    std::string npl_action_enum_to_string(const npl_dummy_dip_index_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_DUMMY_DIP_INDEX_TABLE_ACTION_WRITE:
            {
                return "NPL_DUMMY_DIP_INDEX_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_dummy_dip_index_table_action_e");
        }
        return "";
    }
    npl_dummy_dip_index_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_dummy_dip_index_table_value_t element);
std::string to_short_string(struct npl_dummy_dip_index_table_value_t element);

/// API-s for table: ecn_remark_static_table

typedef enum
{
    NPL_ECN_REMARK_STATIC_TABLE_ACTION_SET_VALUE = 0x0
} npl_ecn_remark_static_table_action_e;

struct npl_ecn_remark_static_table_set_value_payload_t
{
    uint64_t new_ecn : 2;
    uint64_t en_ecn_counting : 1;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_ecn_remark_static_table_set_value_payload_t element);
std::string to_short_string(npl_ecn_remark_static_table_set_value_payload_t element);

struct npl_ecn_remark_static_table_key_t
{
    npl_bool_t pd_cong_on;
    npl_fwd_header_type_e tx_npu_header_fwd_header_type;
    uint64_t packet_ipv4_header_tos_3_0_ : 4;
    uint64_t packet_ipv6_header_tos_3_0_ : 4;
    
    npl_ecn_remark_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ecn_remark_static_table_key_t element);
std::string to_short_string(struct npl_ecn_remark_static_table_key_t element);

struct npl_ecn_remark_static_table_value_t
{
    npl_ecn_remark_static_table_action_e action;
    union npl_ecn_remark_static_table_payloads_t {
        npl_ecn_remark_static_table_set_value_payload_t set_value;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ecn_remark_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_ECN_REMARK_STATIC_TABLE_ACTION_SET_VALUE:
            {
                return "NPL_ECN_REMARK_STATIC_TABLE_ACTION_SET_VALUE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ecn_remark_static_table_action_e");
        }
        return "";
    }
    npl_ecn_remark_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ecn_remark_static_table_value_t element);
std::string to_short_string(struct npl_ecn_remark_static_table_value_t element);

/// API-s for table: egress_mac_ipv4_sec_acl_table

typedef enum
{
    NPL_EGRESS_MAC_IPV4_SEC_ACL_TABLE_ACTION_WRITE = 0x0
} npl_egress_mac_ipv4_sec_acl_table_action_e;

struct npl_egress_mac_ipv4_sec_acl_table_key_t
{
    npl_ipv4_sip_dip_t sip_dip;
    npl_l4_ports_header_t l4_ports;
    npl_tos_t tos;
    npl_ipv4_ttl_and_protocol_t ttl_and_protocol;
    uint64_t tcp_flags : 6;
    npl_bool_t ip_first_fragment;
    uint64_t acl_id : 4;
    
    npl_egress_mac_ipv4_sec_acl_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_egress_mac_ipv4_sec_acl_table_key_t element);
std::string to_short_string(struct npl_egress_mac_ipv4_sec_acl_table_key_t element);

struct npl_egress_mac_ipv4_sec_acl_table_value_t
{
    npl_egress_mac_ipv4_sec_acl_table_action_e action;
    union npl_egress_mac_ipv4_sec_acl_table_payloads_t {
        npl_egress_sec_acl_result_t egress_sec_acl_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_egress_mac_ipv4_sec_acl_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_EGRESS_MAC_IPV4_SEC_ACL_TABLE_ACTION_WRITE:
            {
                return "NPL_EGRESS_MAC_IPV4_SEC_ACL_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_egress_mac_ipv4_sec_acl_table_action_e");
        }
        return "";
    }
    npl_egress_mac_ipv4_sec_acl_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_egress_mac_ipv4_sec_acl_table_value_t element);
std::string to_short_string(struct npl_egress_mac_ipv4_sec_acl_table_value_t element);

/// API-s for table: egress_nh_and_svi_direct0_table

typedef enum
{
    NPL_EGRESS_NH_AND_SVI_DIRECT0_TABLE_ACTION_WRITE = 0x0
} npl_egress_nh_and_svi_direct0_table_action_e;

struct npl_egress_nh_and_svi_direct0_table_key_t
{
    npl_egress_direct0_key_t egress_direct0_key;
    
    npl_egress_nh_and_svi_direct0_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_egress_nh_and_svi_direct0_table_key_t element);
std::string to_short_string(struct npl_egress_nh_and_svi_direct0_table_key_t element);

struct npl_egress_nh_and_svi_direct0_table_value_t
{
    npl_egress_nh_and_svi_direct0_table_action_e action;
    union npl_egress_nh_and_svi_direct0_table_payloads_t {
        npl_nh_and_svi_payload_t nh_and_svi_payload;
    } payloads;
    std::string npl_action_enum_to_string(const npl_egress_nh_and_svi_direct0_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_EGRESS_NH_AND_SVI_DIRECT0_TABLE_ACTION_WRITE:
            {
                return "NPL_EGRESS_NH_AND_SVI_DIRECT0_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_egress_nh_and_svi_direct0_table_action_e");
        }
        return "";
    }
    npl_egress_nh_and_svi_direct0_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_egress_nh_and_svi_direct0_table_value_t element);
std::string to_short_string(struct npl_egress_nh_and_svi_direct0_table_value_t element);

/// API-s for table: egress_nh_and_svi_direct1_table

typedef enum
{
    NPL_EGRESS_NH_AND_SVI_DIRECT1_TABLE_ACTION_WRITE = 0x0
} npl_egress_nh_and_svi_direct1_table_action_e;

struct npl_egress_nh_and_svi_direct1_table_key_t
{
    npl_egress_direct1_key_t egress_direct1_key;
    
    npl_egress_nh_and_svi_direct1_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_egress_nh_and_svi_direct1_table_key_t element);
std::string to_short_string(struct npl_egress_nh_and_svi_direct1_table_key_t element);

struct npl_egress_nh_and_svi_direct1_table_value_t
{
    npl_egress_nh_and_svi_direct1_table_action_e action;
    union npl_egress_nh_and_svi_direct1_table_payloads_t {
        npl_nh_and_svi_payload_t nh_and_svi_payload;
    } payloads;
    std::string npl_action_enum_to_string(const npl_egress_nh_and_svi_direct1_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_EGRESS_NH_AND_SVI_DIRECT1_TABLE_ACTION_WRITE:
            {
                return "NPL_EGRESS_NH_AND_SVI_DIRECT1_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_egress_nh_and_svi_direct1_table_action_e");
        }
        return "";
    }
    npl_egress_nh_and_svi_direct1_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_egress_nh_and_svi_direct1_table_value_t element);
std::string to_short_string(struct npl_egress_nh_and_svi_direct1_table_value_t element);

/// API-s for table: em_mp_table

typedef enum
{
    NPL_EM_MP_TABLE_ACTION_WRITE = 0x0
} npl_em_mp_table_action_e;

struct npl_em_mp_table_key_t
{
    uint64_t your_discr : 32;
    uint64_t udp_dest_port : 16;
    
    npl_em_mp_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_em_mp_table_key_t element);
std::string to_short_string(struct npl_em_mp_table_key_t element);

struct npl_em_mp_table_value_t
{
    npl_em_mp_table_action_e action;
    union npl_em_mp_table_payloads_t {
        npl_em_payload_t bfd_em_payload;
    } payloads;
    std::string npl_action_enum_to_string(const npl_em_mp_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_EM_MP_TABLE_ACTION_WRITE:
            {
                return "NPL_EM_MP_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_em_mp_table_action_e");
        }
        return "";
    }
    npl_em_mp_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_em_mp_table_value_t element);
std::string to_short_string(struct npl_em_mp_table_value_t element);

/// API-s for table: em_pfc_cong_table

typedef enum
{
    NPL_EM_PFC_CONG_TABLE_ACTION_WRITE = 0x0
} npl_em_pfc_cong_table_action_e;

struct npl_em_pfc_cong_table_key_t
{
    uint64_t slice : 3;
    uint64_t tc : 3;
    uint64_t dsp1 : 12;
    uint64_t dsp2 : 12;
    uint64_t dsp3 : 12;
    uint64_t dsp4 : 6;
    
    npl_em_pfc_cong_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_em_pfc_cong_table_key_t element);
std::string to_short_string(struct npl_em_pfc_cong_table_key_t element);

struct npl_em_pfc_cong_table_value_t
{
    npl_em_pfc_cong_table_action_e action;
    union npl_em_pfc_cong_table_payloads_t {
        npl_em_payload_t em_payload;
    } payloads;
    std::string npl_action_enum_to_string(const npl_em_pfc_cong_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_EM_PFC_CONG_TABLE_ACTION_WRITE:
            {
                return "NPL_EM_PFC_CONG_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_em_pfc_cong_table_action_e");
        }
        return "";
    }
    npl_em_pfc_cong_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_em_pfc_cong_table_value_t element);
std::string to_short_string(struct npl_em_pfc_cong_table_value_t element);

/// API-s for table: ene_byte_addition_static_table

typedef enum
{
    NPL_ENE_BYTE_ADDITION_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_ene_byte_addition_static_table_action_e;

struct npl_ene_byte_addition_static_table_key_t
{
    npl_ene_macro_id_t pd_first_ene_macro;
    npl_ene_macro_id_t pd_ene_macro_ids_0_;
    npl_ene_macro_id_t pd_ene_macro_ids_1_;
    npl_ene_macro_id_t pd_ene_macro_ids_2_;
    
    npl_ene_byte_addition_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ene_byte_addition_static_table_key_t element);
std::string to_short_string(struct npl_ene_byte_addition_static_table_key_t element);

struct npl_ene_byte_addition_static_table_value_t
{
    npl_ene_byte_addition_static_table_action_e action;
    union npl_ene_byte_addition_static_table_payloads_t {
        uint64_t padding_vars_ene_byte_addition : 14;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ene_byte_addition_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_ENE_BYTE_ADDITION_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_ENE_BYTE_ADDITION_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ene_byte_addition_static_table_action_e");
        }
        return "";
    }
    npl_ene_byte_addition_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ene_byte_addition_static_table_value_t element);
std::string to_short_string(struct npl_ene_byte_addition_static_table_value_t element);

/// API-s for table: ene_macro_code_tpid_profile_static_table

typedef enum
{
    NPL_ENE_MACRO_CODE_TPID_PROFILE_STATIC_TABLE_ACTION_SET_VALUE = 0x0
} npl_ene_macro_code_tpid_profile_static_table_action_e;

struct npl_ene_macro_code_tpid_profile_static_table_set_value_payload_t
{
    npl_ene_macro_id_t ene_encap_macro_id;
    uint64_t ene_encap_tpid : 16;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_ene_macro_code_tpid_profile_static_table_set_value_payload_t element);
std::string to_short_string(npl_ene_macro_code_tpid_profile_static_table_set_value_payload_t element);

struct npl_ene_macro_code_tpid_profile_static_table_key_t
{
    uint64_t tpid_profile : 2;
    npl_nh_ene_macro_code_e macro_code;
    
    npl_ene_macro_code_tpid_profile_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ene_macro_code_tpid_profile_static_table_key_t element);
std::string to_short_string(struct npl_ene_macro_code_tpid_profile_static_table_key_t element);

struct npl_ene_macro_code_tpid_profile_static_table_value_t
{
    npl_ene_macro_code_tpid_profile_static_table_action_e action;
    union npl_ene_macro_code_tpid_profile_static_table_payloads_t {
        npl_ene_macro_code_tpid_profile_static_table_set_value_payload_t set_value;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ene_macro_code_tpid_profile_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_ENE_MACRO_CODE_TPID_PROFILE_STATIC_TABLE_ACTION_SET_VALUE:
            {
                return "NPL_ENE_MACRO_CODE_TPID_PROFILE_STATIC_TABLE_ACTION_SET_VALUE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ene_macro_code_tpid_profile_static_table_action_e");
        }
        return "";
    }
    npl_ene_macro_code_tpid_profile_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ene_macro_code_tpid_profile_static_table_value_t element);
std::string to_short_string(struct npl_ene_macro_code_tpid_profile_static_table_value_t element);

/// API-s for table: erpp_fabric_counters_offset_table

typedef enum
{
    NPL_ERPP_FABRIC_COUNTERS_OFFSET_TABLE_ACTION_UPDATE_COUNTER_OFFSET = 0x0
} npl_erpp_fabric_counters_offset_table_action_e;

struct npl_erpp_fabric_counters_offset_table_update_counter_offset_payload_t
{
    npl_common_cntr_offset_and_padding_t counter_offset;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_erpp_fabric_counters_offset_table_update_counter_offset_payload_t element);
std::string to_short_string(npl_erpp_fabric_counters_offset_table_update_counter_offset_payload_t element);

struct npl_erpp_fabric_counters_offset_table_key_t
{
    uint64_t vce : 1;
    uint64_t tc : 3;
    uint64_t dp : 2;
    
    npl_erpp_fabric_counters_offset_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_erpp_fabric_counters_offset_table_key_t element);
std::string to_short_string(struct npl_erpp_fabric_counters_offset_table_key_t element);

struct npl_erpp_fabric_counters_offset_table_value_t
{
    npl_erpp_fabric_counters_offset_table_action_e action;
    union npl_erpp_fabric_counters_offset_table_payloads_t {
        npl_erpp_fabric_counters_offset_table_update_counter_offset_payload_t update_counter_offset;
    } payloads;
    std::string npl_action_enum_to_string(const npl_erpp_fabric_counters_offset_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_ERPP_FABRIC_COUNTERS_OFFSET_TABLE_ACTION_UPDATE_COUNTER_OFFSET:
            {
                return "NPL_ERPP_FABRIC_COUNTERS_OFFSET_TABLE_ACTION_UPDATE_COUNTER_OFFSET(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_erpp_fabric_counters_offset_table_action_e");
        }
        return "";
    }
    npl_erpp_fabric_counters_offset_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_erpp_fabric_counters_offset_table_value_t element);
std::string to_short_string(struct npl_erpp_fabric_counters_offset_table_value_t element);

/// API-s for table: erpp_fabric_counters_table

typedef enum
{
    NPL_ERPP_FABRIC_COUNTERS_TABLE_ACTION_UPDATE_COUNTERS = 0x0
} npl_erpp_fabric_counters_table_action_e;

struct npl_erpp_fabric_counters_table_update_counters_payload_t
{
    uint64_t debug_conter_valid : 1;
    npl_counter_ptr_t debug_counter_ptr;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_erpp_fabric_counters_table_update_counters_payload_t element);
std::string to_short_string(npl_erpp_fabric_counters_table_update_counters_payload_t element);

struct npl_erpp_fabric_counters_table_key_t
{
    uint64_t dest_device : 9;
    uint64_t dest_slice : 3;
    uint64_t dest_oq : 9;
    
    npl_erpp_fabric_counters_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_erpp_fabric_counters_table_key_t element);
std::string to_short_string(struct npl_erpp_fabric_counters_table_key_t element);

struct npl_erpp_fabric_counters_table_value_t
{
    npl_erpp_fabric_counters_table_action_e action;
    union npl_erpp_fabric_counters_table_payloads_t {
        npl_erpp_fabric_counters_table_update_counters_payload_t update_counters;
    } payloads;
    std::string npl_action_enum_to_string(const npl_erpp_fabric_counters_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_ERPP_FABRIC_COUNTERS_TABLE_ACTION_UPDATE_COUNTERS:
            {
                return "NPL_ERPP_FABRIC_COUNTERS_TABLE_ACTION_UPDATE_COUNTERS(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_erpp_fabric_counters_table_action_e");
        }
        return "";
    }
    npl_erpp_fabric_counters_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_erpp_fabric_counters_table_value_t element);
std::string to_short_string(struct npl_erpp_fabric_counters_table_value_t element);

/// API-s for table: eth_meter_profile_mapping_table

typedef enum
{
    NPL_ETH_METER_PROFILE_MAPPING_TABLE_ACTION_WRITE = 0x0
} npl_eth_meter_profile_mapping_table_action_e;

struct npl_eth_meter_profile_mapping_table_key_t
{
    uint64_t qos_id : 4;
    
    npl_eth_meter_profile_mapping_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_eth_meter_profile_mapping_table_key_t element);
std::string to_short_string(struct npl_eth_meter_profile_mapping_table_key_t element);

struct npl_eth_meter_profile_mapping_table_value_t
{
    npl_eth_meter_profile_mapping_table_action_e action;
    union npl_eth_meter_profile_mapping_table_payloads_t {
        uint64_t slp_qos_id : 4;
    } payloads;
    std::string npl_action_enum_to_string(const npl_eth_meter_profile_mapping_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_ETH_METER_PROFILE_MAPPING_TABLE_ACTION_WRITE:
            {
                return "NPL_ETH_METER_PROFILE_MAPPING_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_eth_meter_profile_mapping_table_action_e");
        }
        return "";
    }
    npl_eth_meter_profile_mapping_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_eth_meter_profile_mapping_table_value_t element);
std::string to_short_string(struct npl_eth_meter_profile_mapping_table_value_t element);

/// API-s for table: eth_oam_set_da_mc2_static_table

typedef enum
{
    NPL_ETH_OAM_SET_DA_MC2_STATIC_TABLE_ACTION_SET_DA = 0x0
} npl_eth_oam_set_da_mc2_static_table_action_e;

struct npl_eth_oam_set_da_mc2_static_table_set_da_payload_t
{
    uint64_t da : 13;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_eth_oam_set_da_mc2_static_table_set_da_payload_t element);
std::string to_short_string(npl_eth_oam_set_da_mc2_static_table_set_da_payload_t element);

struct npl_eth_oam_set_da_mc2_static_table_key_t
{
    
    
    npl_eth_oam_set_da_mc2_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_eth_oam_set_da_mc2_static_table_key_t element);
std::string to_short_string(struct npl_eth_oam_set_da_mc2_static_table_key_t element);

struct npl_eth_oam_set_da_mc2_static_table_value_t
{
    npl_eth_oam_set_da_mc2_static_table_action_e action;
    union npl_eth_oam_set_da_mc2_static_table_payloads_t {
        npl_eth_oam_set_da_mc2_static_table_set_da_payload_t set_da;
    } payloads;
    std::string npl_action_enum_to_string(const npl_eth_oam_set_da_mc2_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_ETH_OAM_SET_DA_MC2_STATIC_TABLE_ACTION_SET_DA:
            {
                return "NPL_ETH_OAM_SET_DA_MC2_STATIC_TABLE_ACTION_SET_DA(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_eth_oam_set_da_mc2_static_table_action_e");
        }
        return "";
    }
    npl_eth_oam_set_da_mc2_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_eth_oam_set_da_mc2_static_table_value_t element);
std::string to_short_string(struct npl_eth_oam_set_da_mc2_static_table_value_t element);

/// API-s for table: eth_oam_set_da_mc_static_table

typedef enum
{
    NPL_ETH_OAM_SET_DA_MC_STATIC_TABLE_ACTION_SET_DA = 0x0
} npl_eth_oam_set_da_mc_static_table_action_e;

struct npl_eth_oam_set_da_mc_static_table_set_da_payload_t
{
    uint64_t da : 32;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_eth_oam_set_da_mc_static_table_set_da_payload_t element);
std::string to_short_string(npl_eth_oam_set_da_mc_static_table_set_da_payload_t element);

struct npl_eth_oam_set_da_mc_static_table_key_t
{
    
    
    npl_eth_oam_set_da_mc_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_eth_oam_set_da_mc_static_table_key_t element);
std::string to_short_string(struct npl_eth_oam_set_da_mc_static_table_key_t element);

struct npl_eth_oam_set_da_mc_static_table_value_t
{
    npl_eth_oam_set_da_mc_static_table_action_e action;
    union npl_eth_oam_set_da_mc_static_table_payloads_t {
        npl_eth_oam_set_da_mc_static_table_set_da_payload_t set_da;
    } payloads;
    std::string npl_action_enum_to_string(const npl_eth_oam_set_da_mc_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_ETH_OAM_SET_DA_MC_STATIC_TABLE_ACTION_SET_DA:
            {
                return "NPL_ETH_OAM_SET_DA_MC_STATIC_TABLE_ACTION_SET_DA(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_eth_oam_set_da_mc_static_table_action_e");
        }
        return "";
    }
    npl_eth_oam_set_da_mc_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_eth_oam_set_da_mc_static_table_value_t element);
std::string to_short_string(struct npl_eth_oam_set_da_mc_static_table_value_t element);

/// API-s for table: eth_rtf_conf_set_mapping_table

typedef enum
{
    NPL_ETH_RTF_CONF_SET_MAPPING_TABLE_ACTION_WRITE = 0x0
} npl_eth_rtf_conf_set_mapping_table_action_e;

struct npl_eth_rtf_conf_set_mapping_table_key_t
{
    npl_lp_rtf_conf_set_t lp_rtf_conf_set;
    npl_rtf_step_t rtf_step;
    
    npl_eth_rtf_conf_set_mapping_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_eth_rtf_conf_set_mapping_table_key_t element);
std::string to_short_string(struct npl_eth_rtf_conf_set_mapping_table_key_t element);

struct npl_eth_rtf_conf_set_mapping_table_value_t
{
    npl_eth_rtf_conf_set_mapping_table_action_e action;
    union npl_eth_rtf_conf_set_mapping_table_payloads_t {
        npl_eth_rtf_iteration_properties_t eth_rtf_iteration_prop;
    } payloads;
    std::string npl_action_enum_to_string(const npl_eth_rtf_conf_set_mapping_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_ETH_RTF_CONF_SET_MAPPING_TABLE_ACTION_WRITE:
            {
                return "NPL_ETH_RTF_CONF_SET_MAPPING_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_eth_rtf_conf_set_mapping_table_action_e");
        }
        return "";
    }
    npl_eth_rtf_conf_set_mapping_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_eth_rtf_conf_set_mapping_table_value_t element);
std::string to_short_string(struct npl_eth_rtf_conf_set_mapping_table_value_t element);

/// API-s for table: eve_byte_addition_static_table

typedef enum
{
    NPL_EVE_BYTE_ADDITION_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_eve_byte_addition_static_table_action_e;

struct npl_eve_byte_addition_static_table_key_t
{
    uint64_t padding_vars_eve_27_26_ : 2;
    uint64_t padding_vars_eve_16_14_ : 3;
    
    npl_eve_byte_addition_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_eve_byte_addition_static_table_key_t element);
std::string to_short_string(struct npl_eve_byte_addition_static_table_key_t element);

struct npl_eve_byte_addition_static_table_value_t
{
    npl_eve_byte_addition_static_table_action_e action;
    union npl_eve_byte_addition_static_table_payloads_t {
        uint64_t padding_vars_eve_byte_addition : 14;
    } payloads;
    std::string npl_action_enum_to_string(const npl_eve_byte_addition_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_EVE_BYTE_ADDITION_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_EVE_BYTE_ADDITION_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_eve_byte_addition_static_table_action_e");
        }
        return "";
    }
    npl_eve_byte_addition_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_eve_byte_addition_static_table_value_t element);
std::string to_short_string(struct npl_eve_byte_addition_static_table_value_t element);

/// API-s for table: eve_to_ethernet_ene_static_table

typedef enum
{
    NPL_EVE_TO_ETHERNET_ENE_STATIC_TABLE_ACTION_SET_VALUE = 0x0
} npl_eve_to_ethernet_ene_static_table_action_e;

struct npl_eve_to_ethernet_ene_static_table_set_value_payload_t
{
    uint64_t ene_encap_tpid : 16;
    npl_ene_macro_id_t ene_encap_macro_id;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_eve_to_ethernet_ene_static_table_set_value_payload_t element);
std::string to_short_string(npl_eve_to_ethernet_ene_static_table_set_value_payload_t element);

struct npl_eve_to_ethernet_ene_static_table_key_t
{
    npl_vlan_edit_command_main_type_e main_type;
    npl_svi_eve_sub_type_plus_prf_t sub_type;
    
    npl_eve_to_ethernet_ene_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_eve_to_ethernet_ene_static_table_key_t element);
std::string to_short_string(struct npl_eve_to_ethernet_ene_static_table_key_t element);

struct npl_eve_to_ethernet_ene_static_table_value_t
{
    npl_eve_to_ethernet_ene_static_table_action_e action;
    union npl_eve_to_ethernet_ene_static_table_payloads_t {
        npl_eve_to_ethernet_ene_static_table_set_value_payload_t set_value;
    } payloads;
    std::string npl_action_enum_to_string(const npl_eve_to_ethernet_ene_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_EVE_TO_ETHERNET_ENE_STATIC_TABLE_ACTION_SET_VALUE:
            {
                return "NPL_EVE_TO_ETHERNET_ENE_STATIC_TABLE_ACTION_SET_VALUE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_eve_to_ethernet_ene_static_table_action_e");
        }
        return "";
    }
    npl_eve_to_ethernet_ene_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_eve_to_ethernet_ene_static_table_value_t element);
std::string to_short_string(struct npl_eve_to_ethernet_ene_static_table_value_t element);

/// API-s for table: event_queue_table

typedef enum
{
    NPL_EVENT_QUEUE_TABLE_ACTION_WRITE = 0x0
} npl_event_queue_table_action_e;

struct npl_event_queue_table_key_t
{
    npl_event_queue_address_t event_queue_address;
    
    npl_event_queue_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_event_queue_table_key_t element);
std::string to_short_string(struct npl_event_queue_table_key_t element);

struct npl_event_queue_table_value_t
{
    npl_event_queue_table_action_e action;
    union npl_event_queue_table_payloads_t {
        npl_event_to_send_t event_queue_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_event_queue_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_EVENT_QUEUE_TABLE_ACTION_WRITE:
            {
                return "NPL_EVENT_QUEUE_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_event_queue_table_action_e");
        }
        return "";
    }
    npl_event_queue_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_event_queue_table_value_t element);
std::string to_short_string(struct npl_event_queue_table_value_t element);

/// API-s for table: external_aux_table

typedef enum
{
    NPL_EXTERNAL_AUX_TABLE_ACTION_WRITE = 0x0
} npl_external_aux_table_action_e;

struct npl_external_aux_table_key_t
{
    npl_aux_table_key_t aux_table_key;
    
    npl_external_aux_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_external_aux_table_key_t element);
std::string to_short_string(struct npl_external_aux_table_key_t element);

struct npl_external_aux_table_value_t
{
    npl_external_aux_table_action_e action;
    union npl_external_aux_table_payloads_t {
        npl_aux_table_result_t aux_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_external_aux_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_EXTERNAL_AUX_TABLE_ACTION_WRITE:
            {
                return "NPL_EXTERNAL_AUX_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_external_aux_table_action_e");
        }
        return "";
    }
    npl_external_aux_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_external_aux_table_value_t element);
std::string to_short_string(struct npl_external_aux_table_value_t element);

/// API-s for table: fabric_and_tm_header_size_static_table

typedef enum
{
    NPL_FABRIC_AND_TM_HEADER_SIZE_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_fabric_and_tm_header_size_static_table_action_e;

struct npl_fabric_and_tm_header_size_static_table_key_t
{
    npl_fabric_header_type_e fabric_header_type;
    npl_tm_header_type_e tm_header_type;
    uint64_t npuh_size : 7;
    
    npl_fabric_and_tm_header_size_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_fabric_and_tm_header_size_static_table_key_t element);
std::string to_short_string(struct npl_fabric_and_tm_header_size_static_table_key_t element);

struct npl_fabric_and_tm_header_size_static_table_value_t
{
    npl_fabric_and_tm_header_size_static_table_action_e action;
    union npl_fabric_and_tm_header_size_static_table_payloads_t {
        uint64_t fabric_tm_npu_headers_size : 6;
    } payloads;
    std::string npl_action_enum_to_string(const npl_fabric_and_tm_header_size_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_FABRIC_AND_TM_HEADER_SIZE_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_FABRIC_AND_TM_HEADER_SIZE_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_fabric_and_tm_header_size_static_table_action_e");
        }
        return "";
    }
    npl_fabric_and_tm_header_size_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_fabric_and_tm_header_size_static_table_value_t element);
std::string to_short_string(struct npl_fabric_and_tm_header_size_static_table_value_t element);

/// API-s for table: fabric_header_ene_macro_table

typedef enum
{
    NPL_FABRIC_HEADER_ENE_MACRO_TABLE_ACTION_UPDATE = 0x0
} npl_fabric_header_ene_macro_table_action_e;

struct npl_fabric_header_ene_macro_table_update_payload_t
{
    npl_ene_macro_id_t ene_macro_id;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_fabric_header_ene_macro_table_update_payload_t element);
std::string to_short_string(npl_fabric_header_ene_macro_table_update_payload_t element);

struct npl_fabric_header_ene_macro_table_key_t
{
    npl_fabric_header_type_e fabric_header_type;
    
    npl_fabric_header_ene_macro_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_fabric_header_ene_macro_table_key_t element);
std::string to_short_string(struct npl_fabric_header_ene_macro_table_key_t element);

struct npl_fabric_header_ene_macro_table_value_t
{
    npl_fabric_header_ene_macro_table_action_e action;
    union npl_fabric_header_ene_macro_table_payloads_t {
        npl_fabric_header_ene_macro_table_update_payload_t update;
    } payloads;
    std::string npl_action_enum_to_string(const npl_fabric_header_ene_macro_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_FABRIC_HEADER_ENE_MACRO_TABLE_ACTION_UPDATE:
            {
                return "NPL_FABRIC_HEADER_ENE_MACRO_TABLE_ACTION_UPDATE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_fabric_header_ene_macro_table_action_e");
        }
        return "";
    }
    npl_fabric_header_ene_macro_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_fabric_header_ene_macro_table_value_t element);
std::string to_short_string(struct npl_fabric_header_ene_macro_table_value_t element);

/// API-s for table: fabric_header_types_static_table

typedef enum
{
    NPL_FABRIC_HEADER_TYPES_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_fabric_header_types_static_table_action_e;

struct npl_fabric_header_types_static_table_key_t
{
    npl_fabric_header_type_e fabric_header_type;
    
    npl_fabric_header_types_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_fabric_header_types_static_table_key_t element);
std::string to_short_string(struct npl_fabric_header_types_static_table_key_t element);

struct npl_fabric_header_types_static_table_value_t
{
    npl_fabric_header_types_static_table_action_e action;
    union npl_fabric_header_types_static_table_payloads_t {
        npl_bool_t fabric_header_type_ok;
    } payloads;
    std::string npl_action_enum_to_string(const npl_fabric_header_types_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_FABRIC_HEADER_TYPES_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_FABRIC_HEADER_TYPES_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_fabric_header_types_static_table_action_e");
        }
        return "";
    }
    npl_fabric_header_types_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_fabric_header_types_static_table_value_t element);
std::string to_short_string(struct npl_fabric_header_types_static_table_value_t element);

/// API-s for table: fabric_headers_type_table

typedef enum
{
    NPL_FABRIC_HEADERS_TYPE_TABLE_ACTION_UPDATE_FABRIC_LOCAL_VARS = 0x0
} npl_fabric_headers_type_table_action_e;

struct npl_fabric_headers_type_table_update_fabric_local_vars_payload_t
{
    npl_fabric_header_type_e fabric_header_type;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_fabric_headers_type_table_update_fabric_local_vars_payload_t element);
std::string to_short_string(npl_fabric_headers_type_table_update_fabric_local_vars_payload_t element);

struct npl_fabric_headers_type_table_key_t
{
    npl_fabric_header_type_e initial_fabric_header_type;
    npl_plb_header_type_e plb_header_type;
    uint64_t start_packing : 1;
    
    npl_fabric_headers_type_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_fabric_headers_type_table_key_t element);
std::string to_short_string(struct npl_fabric_headers_type_table_key_t element);

struct npl_fabric_headers_type_table_value_t
{
    npl_fabric_headers_type_table_action_e action;
    union npl_fabric_headers_type_table_payloads_t {
        npl_fabric_headers_type_table_update_fabric_local_vars_payload_t update_fabric_local_vars;
    } payloads;
    std::string npl_action_enum_to_string(const npl_fabric_headers_type_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_FABRIC_HEADERS_TYPE_TABLE_ACTION_UPDATE_FABRIC_LOCAL_VARS:
            {
                return "NPL_FABRIC_HEADERS_TYPE_TABLE_ACTION_UPDATE_FABRIC_LOCAL_VARS(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_fabric_headers_type_table_action_e");
        }
        return "";
    }
    npl_fabric_headers_type_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_fabric_headers_type_table_value_t element);
std::string to_short_string(struct npl_fabric_headers_type_table_value_t element);

/// API-s for table: fabric_init_cfg

typedef enum
{
    NPL_FABRIC_INIT_CFG_ACTION_UPDATE = 0x0
} npl_fabric_init_cfg_action_e;

struct npl_fabric_init_cfg_update_payload_t
{
    npl_bool_t fabric_init_cfg_hit_;
    npl_fabric_cfg_t fabric_cfg_;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_fabric_init_cfg_update_payload_t element);
std::string to_short_string(npl_fabric_init_cfg_update_payload_t element);

struct npl_fabric_init_cfg_key_t
{
    uint64_t ser : 1;
    
    npl_fabric_init_cfg_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_fabric_init_cfg_key_t element);
std::string to_short_string(struct npl_fabric_init_cfg_key_t element);

struct npl_fabric_init_cfg_value_t
{
    npl_fabric_init_cfg_action_e action;
    union npl_fabric_init_cfg_payloads_t {
        npl_fabric_init_cfg_update_payload_t update;
    } payloads;
    std::string npl_action_enum_to_string(const npl_fabric_init_cfg_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_FABRIC_INIT_CFG_ACTION_UPDATE:
            {
                return "NPL_FABRIC_INIT_CFG_ACTION_UPDATE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_fabric_init_cfg_action_e");
        }
        return "";
    }
    npl_fabric_init_cfg_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_fabric_init_cfg_value_t element);
std::string to_short_string(struct npl_fabric_init_cfg_value_t element);

/// API-s for table: fabric_npuh_size_calculation_static_table

typedef enum
{
    NPL_FABRIC_NPUH_SIZE_CALCULATION_STATIC_TABLE_ACTION_UPDATE_NPUH_SIZE = 0x0
} npl_fabric_npuh_size_calculation_static_table_action_e;

struct npl_fabric_npuh_size_calculation_static_table_update_npuh_size_payload_t
{
    uint64_t is_inject_pkt : 1;
    uint64_t is_network_pkt : 1;
    uint64_t ene_with_soft_npuh : 1;
    uint64_t npuh_size : 7;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_fabric_npuh_size_calculation_static_table_update_npuh_size_payload_t element);
std::string to_short_string(npl_fabric_npuh_size_calculation_static_table_update_npuh_size_payload_t element);

struct npl_fabric_npuh_size_calculation_static_table_key_t
{
    uint64_t device_tx_cud_msb_4bits : 4;
    npl_fwd_header_type_e packet_tx_npu_header_fwd_header_type;
    npl_npu_mirror_or_redirect_encap_type_e packet_tx_npu_header_encap_encapsulation_type_redirect_encap_type;
    npl_bool_t packet_tx_npu_header_is_inject_up;
    
    npl_fabric_npuh_size_calculation_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_fabric_npuh_size_calculation_static_table_key_t element);
std::string to_short_string(struct npl_fabric_npuh_size_calculation_static_table_key_t element);

struct npl_fabric_npuh_size_calculation_static_table_value_t
{
    npl_fabric_npuh_size_calculation_static_table_action_e action;
    union npl_fabric_npuh_size_calculation_static_table_payloads_t {
        npl_fabric_npuh_size_calculation_static_table_update_npuh_size_payload_t update_npuh_size;
    } payloads;
    std::string npl_action_enum_to_string(const npl_fabric_npuh_size_calculation_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_FABRIC_NPUH_SIZE_CALCULATION_STATIC_TABLE_ACTION_UPDATE_NPUH_SIZE:
            {
                return "NPL_FABRIC_NPUH_SIZE_CALCULATION_STATIC_TABLE_ACTION_UPDATE_NPUH_SIZE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_fabric_npuh_size_calculation_static_table_action_e");
        }
        return "";
    }
    npl_fabric_npuh_size_calculation_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_fabric_npuh_size_calculation_static_table_value_t element);
std::string to_short_string(struct npl_fabric_npuh_size_calculation_static_table_value_t element);

/// API-s for table: fabric_out_color_map_table

typedef enum
{
    NPL_FABRIC_OUT_COLOR_MAP_TABLE_ACTION_WRITE = 0x0
} npl_fabric_out_color_map_table_action_e;

struct npl_fabric_out_color_map_table_key_t
{
    uint64_t out_color : 2;
    
    npl_fabric_out_color_map_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_fabric_out_color_map_table_key_t element);
std::string to_short_string(struct npl_fabric_out_color_map_table_key_t element);

struct npl_fabric_out_color_map_table_value_t
{
    npl_fabric_out_color_map_table_action_e action;
    union npl_fabric_out_color_map_table_payloads_t {
        uint64_t dp : 6;
    } payloads;
    std::string npl_action_enum_to_string(const npl_fabric_out_color_map_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_FABRIC_OUT_COLOR_MAP_TABLE_ACTION_WRITE:
            {
                return "NPL_FABRIC_OUT_COLOR_MAP_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_fabric_out_color_map_table_action_e");
        }
        return "";
    }
    npl_fabric_out_color_map_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_fabric_out_color_map_table_value_t element);
std::string to_short_string(struct npl_fabric_out_color_map_table_value_t element);

/// API-s for table: fabric_rx_fwd_error_handling_counter_table

typedef enum
{
    NPL_FABRIC_RX_FWD_ERROR_HANDLING_COUNTER_TABLE_ACTION_UPDATE_RESULT = 0x0
} npl_fabric_rx_fwd_error_handling_counter_table_action_e;

struct npl_fabric_rx_fwd_error_handling_counter_table_update_result_payload_t
{
    npl_counter_ptr_t counter;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_fabric_rx_fwd_error_handling_counter_table_update_result_payload_t element);
std::string to_short_string(npl_fabric_rx_fwd_error_handling_counter_table_update_result_payload_t element);

struct npl_fabric_rx_fwd_error_handling_counter_table_key_t
{
    uint64_t ser : 1;
    uint64_t error_code : 3;
    
    npl_fabric_rx_fwd_error_handling_counter_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_fabric_rx_fwd_error_handling_counter_table_key_t element);
std::string to_short_string(struct npl_fabric_rx_fwd_error_handling_counter_table_key_t element);

struct npl_fabric_rx_fwd_error_handling_counter_table_value_t
{
    npl_fabric_rx_fwd_error_handling_counter_table_action_e action;
    union npl_fabric_rx_fwd_error_handling_counter_table_payloads_t {
        npl_fabric_rx_fwd_error_handling_counter_table_update_result_payload_t update_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_fabric_rx_fwd_error_handling_counter_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_FABRIC_RX_FWD_ERROR_HANDLING_COUNTER_TABLE_ACTION_UPDATE_RESULT:
            {
                return "NPL_FABRIC_RX_FWD_ERROR_HANDLING_COUNTER_TABLE_ACTION_UPDATE_RESULT(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_fabric_rx_fwd_error_handling_counter_table_action_e");
        }
        return "";
    }
    npl_fabric_rx_fwd_error_handling_counter_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_fabric_rx_fwd_error_handling_counter_table_value_t element);
std::string to_short_string(struct npl_fabric_rx_fwd_error_handling_counter_table_value_t element);

/// API-s for table: fabric_rx_fwd_error_handling_destination_table

typedef enum
{
    NPL_FABRIC_RX_FWD_ERROR_HANDLING_DESTINATION_TABLE_ACTION_UPDATE_RESULT = 0x0
} npl_fabric_rx_fwd_error_handling_destination_table_action_e;

struct npl_fabric_rx_fwd_error_handling_destination_table_update_result_payload_t
{
    uint64_t destination : 20;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_fabric_rx_fwd_error_handling_destination_table_update_result_payload_t element);
std::string to_short_string(npl_fabric_rx_fwd_error_handling_destination_table_update_result_payload_t element);

struct npl_fabric_rx_fwd_error_handling_destination_table_key_t
{
    uint64_t ser : 1;
    uint64_t error_code : 3;
    
    npl_fabric_rx_fwd_error_handling_destination_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_fabric_rx_fwd_error_handling_destination_table_key_t element);
std::string to_short_string(struct npl_fabric_rx_fwd_error_handling_destination_table_key_t element);

struct npl_fabric_rx_fwd_error_handling_destination_table_value_t
{
    npl_fabric_rx_fwd_error_handling_destination_table_action_e action;
    union npl_fabric_rx_fwd_error_handling_destination_table_payloads_t {
        npl_fabric_rx_fwd_error_handling_destination_table_update_result_payload_t update_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_fabric_rx_fwd_error_handling_destination_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_FABRIC_RX_FWD_ERROR_HANDLING_DESTINATION_TABLE_ACTION_UPDATE_RESULT:
            {
                return "NPL_FABRIC_RX_FWD_ERROR_HANDLING_DESTINATION_TABLE_ACTION_UPDATE_RESULT(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_fabric_rx_fwd_error_handling_destination_table_action_e");
        }
        return "";
    }
    npl_fabric_rx_fwd_error_handling_destination_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_fabric_rx_fwd_error_handling_destination_table_value_t element);
std::string to_short_string(struct npl_fabric_rx_fwd_error_handling_destination_table_value_t element);

/// API-s for table: fabric_rx_term_error_handling_counter_table

typedef enum
{
    NPL_FABRIC_RX_TERM_ERROR_HANDLING_COUNTER_TABLE_ACTION_UPDATE_RESULT = 0x0
} npl_fabric_rx_term_error_handling_counter_table_action_e;

struct npl_fabric_rx_term_error_handling_counter_table_update_result_payload_t
{
    npl_counter_ptr_t counter;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_fabric_rx_term_error_handling_counter_table_update_result_payload_t element);
std::string to_short_string(npl_fabric_rx_term_error_handling_counter_table_update_result_payload_t element);

struct npl_fabric_rx_term_error_handling_counter_table_key_t
{
    uint64_t ser : 1;
    
    npl_fabric_rx_term_error_handling_counter_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_fabric_rx_term_error_handling_counter_table_key_t element);
std::string to_short_string(struct npl_fabric_rx_term_error_handling_counter_table_key_t element);

struct npl_fabric_rx_term_error_handling_counter_table_value_t
{
    npl_fabric_rx_term_error_handling_counter_table_action_e action;
    union npl_fabric_rx_term_error_handling_counter_table_payloads_t {
        npl_fabric_rx_term_error_handling_counter_table_update_result_payload_t update_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_fabric_rx_term_error_handling_counter_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_FABRIC_RX_TERM_ERROR_HANDLING_COUNTER_TABLE_ACTION_UPDATE_RESULT:
            {
                return "NPL_FABRIC_RX_TERM_ERROR_HANDLING_COUNTER_TABLE_ACTION_UPDATE_RESULT(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_fabric_rx_term_error_handling_counter_table_action_e");
        }
        return "";
    }
    npl_fabric_rx_term_error_handling_counter_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_fabric_rx_term_error_handling_counter_table_value_t element);
std::string to_short_string(struct npl_fabric_rx_term_error_handling_counter_table_value_t element);

/// API-s for table: fabric_rx_term_error_handling_destination_table

typedef enum
{
    NPL_FABRIC_RX_TERM_ERROR_HANDLING_DESTINATION_TABLE_ACTION_UPDATE_RESULT = 0x0
} npl_fabric_rx_term_error_handling_destination_table_action_e;

struct npl_fabric_rx_term_error_handling_destination_table_update_result_payload_t
{
    uint64_t destination : 20;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_fabric_rx_term_error_handling_destination_table_update_result_payload_t element);
std::string to_short_string(npl_fabric_rx_term_error_handling_destination_table_update_result_payload_t element);

struct npl_fabric_rx_term_error_handling_destination_table_key_t
{
    uint64_t ser : 1;
    
    npl_fabric_rx_term_error_handling_destination_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_fabric_rx_term_error_handling_destination_table_key_t element);
std::string to_short_string(struct npl_fabric_rx_term_error_handling_destination_table_key_t element);

struct npl_fabric_rx_term_error_handling_destination_table_value_t
{
    npl_fabric_rx_term_error_handling_destination_table_action_e action;
    union npl_fabric_rx_term_error_handling_destination_table_payloads_t {
        npl_fabric_rx_term_error_handling_destination_table_update_result_payload_t update_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_fabric_rx_term_error_handling_destination_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_FABRIC_RX_TERM_ERROR_HANDLING_DESTINATION_TABLE_ACTION_UPDATE_RESULT:
            {
                return "NPL_FABRIC_RX_TERM_ERROR_HANDLING_DESTINATION_TABLE_ACTION_UPDATE_RESULT(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_fabric_rx_term_error_handling_destination_table_action_e");
        }
        return "";
    }
    npl_fabric_rx_term_error_handling_destination_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_fabric_rx_term_error_handling_destination_table_value_t element);
std::string to_short_string(struct npl_fabric_rx_term_error_handling_destination_table_value_t element);

/// API-s for table: fabric_scaled_mc_map_to_netork_slice_static_table

typedef enum
{
    NPL_FABRIC_SCALED_MC_MAP_TO_NETORK_SLICE_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_fabric_scaled_mc_map_to_netork_slice_static_table_action_e;

struct npl_fabric_scaled_mc_map_to_netork_slice_static_table_key_t
{
    uint64_t smcid_lsb : 4;
    
    npl_fabric_scaled_mc_map_to_netork_slice_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_fabric_scaled_mc_map_to_netork_slice_static_table_key_t element);
std::string to_short_string(struct npl_fabric_scaled_mc_map_to_netork_slice_static_table_key_t element);

struct npl_fabric_scaled_mc_map_to_netork_slice_static_table_value_t
{
    npl_fabric_scaled_mc_map_to_netork_slice_static_table_action_e action;
    union npl_fabric_scaled_mc_map_to_netork_slice_static_table_payloads_t {
        npl_destination_t network_slice_mcid;
    } payloads;
    std::string npl_action_enum_to_string(const npl_fabric_scaled_mc_map_to_netork_slice_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_FABRIC_SCALED_MC_MAP_TO_NETORK_SLICE_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_FABRIC_SCALED_MC_MAP_TO_NETORK_SLICE_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_fabric_scaled_mc_map_to_netork_slice_static_table_action_e");
        }
        return "";
    }
    npl_fabric_scaled_mc_map_to_netork_slice_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_fabric_scaled_mc_map_to_netork_slice_static_table_value_t element);
std::string to_short_string(struct npl_fabric_scaled_mc_map_to_netork_slice_static_table_value_t element);

/// API-s for table: fabric_smcid_threshold_table

typedef enum
{
    NPL_FABRIC_SMCID_THRESHOLD_TABLE_ACTION_WRITE = 0x0
} npl_fabric_smcid_threshold_table_action_e;

struct npl_fabric_smcid_threshold_table_key_t
{
    uint64_t dummy : 1;
    
    npl_fabric_smcid_threshold_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_fabric_smcid_threshold_table_key_t element);
std::string to_short_string(struct npl_fabric_smcid_threshold_table_key_t element);

struct npl_fabric_smcid_threshold_table_value_t
{
    npl_fabric_smcid_threshold_table_action_e action;
    union npl_fabric_smcid_threshold_table_payloads_t {
        npl_mcid_t smcid_threshold;
    } payloads;
    std::string npl_action_enum_to_string(const npl_fabric_smcid_threshold_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_FABRIC_SMCID_THRESHOLD_TABLE_ACTION_WRITE:
            {
                return "NPL_FABRIC_SMCID_THRESHOLD_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_fabric_smcid_threshold_table_action_e");
        }
        return "";
    }
    npl_fabric_smcid_threshold_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_fabric_smcid_threshold_table_value_t element);
std::string to_short_string(struct npl_fabric_smcid_threshold_table_value_t element);

/// API-s for table: fabric_term_error_checker_static_table

typedef enum
{
    NPL_FABRIC_TERM_ERROR_CHECKER_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_fabric_term_error_checker_static_table_action_e;

struct npl_fabric_term_error_checker_static_table_key_t
{
    uint64_t is_keepalive : 1;
    npl_bool_t fabric_header_type_ok;
    npl_bool_t fabric_init_cfg_table_hit;
    npl_mismatch_indications_t mismatch_indications;
    
    npl_fabric_term_error_checker_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_fabric_term_error_checker_static_table_key_t element);
std::string to_short_string(struct npl_fabric_term_error_checker_static_table_key_t element);

struct npl_fabric_term_error_checker_static_table_value_t
{
    npl_fabric_term_error_checker_static_table_action_e action;
    union npl_fabric_term_error_checker_static_table_payloads_t {
        uint64_t pd_fabric_error_event_error_code : 3;
    } payloads;
    std::string npl_action_enum_to_string(const npl_fabric_term_error_checker_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_FABRIC_TERM_ERROR_CHECKER_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_FABRIC_TERM_ERROR_CHECKER_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_fabric_term_error_checker_static_table_action_e");
        }
        return "";
    }
    npl_fabric_term_error_checker_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_fabric_term_error_checker_static_table_value_t element);
std::string to_short_string(struct npl_fabric_term_error_checker_static_table_value_t element);

/// API-s for table: fabric_tm_headers_table

typedef enum
{
    NPL_FABRIC_TM_HEADERS_TABLE_ACTION_UPDATE_FABRIC_LOCAL_VARS = 0x0
} npl_fabric_tm_headers_table_action_e;

struct npl_fabric_tm_headers_table_update_fabric_local_vars_payload_t
{
    uint64_t ingress_multicast : 1;
    npl_tm_header_type_e tm_header_type;
    npl_fabric_header_type_e initial_fabric_header_type;
    npl_fabric_header_start_template_t_anonymous_union_ctrl_t ctrl;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_fabric_tm_headers_table_update_fabric_local_vars_payload_t element);
std::string to_short_string(npl_fabric_tm_headers_table_update_fabric_local_vars_payload_t element);

struct npl_fabric_tm_headers_table_key_t
{
    npl_fabric_oq_type_e fabric_oq_type;
    uint64_t tx_cud_prefix : 4;
    
    npl_fabric_tm_headers_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_fabric_tm_headers_table_key_t element);
std::string to_short_string(struct npl_fabric_tm_headers_table_key_t element);

struct npl_fabric_tm_headers_table_value_t
{
    npl_fabric_tm_headers_table_action_e action;
    union npl_fabric_tm_headers_table_payloads_t {
        npl_fabric_tm_headers_table_update_fabric_local_vars_payload_t update_fabric_local_vars;
    } payloads;
    std::string npl_action_enum_to_string(const npl_fabric_tm_headers_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_FABRIC_TM_HEADERS_TABLE_ACTION_UPDATE_FABRIC_LOCAL_VARS:
            {
                return "NPL_FABRIC_TM_HEADERS_TABLE_ACTION_UPDATE_FABRIC_LOCAL_VARS(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_fabric_tm_headers_table_action_e");
        }
        return "";
    }
    npl_fabric_tm_headers_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_fabric_tm_headers_table_value_t element);
std::string to_short_string(struct npl_fabric_tm_headers_table_value_t element);

/// API-s for table: fabric_transmit_error_checker_static_table

typedef enum
{
    NPL_FABRIC_TRANSMIT_ERROR_CHECKER_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_fabric_transmit_error_checker_static_table_action_e;

struct npl_fabric_transmit_error_checker_static_table_key_t
{
    uint64_t npu_header : 4;
    npl_bool_t fabric_init_cfg_table_hit;
    uint64_t expected_issu : 1;
    uint64_t pkt_issu : 1;
    
    npl_fabric_transmit_error_checker_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_fabric_transmit_error_checker_static_table_key_t element);
std::string to_short_string(struct npl_fabric_transmit_error_checker_static_table_key_t element);

struct npl_fabric_transmit_error_checker_static_table_value_t
{
    npl_fabric_transmit_error_checker_static_table_action_e action;
    union npl_fabric_transmit_error_checker_static_table_payloads_t {
        uint64_t fabric_error_event_error_code : 3;
    } payloads;
    std::string npl_action_enum_to_string(const npl_fabric_transmit_error_checker_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_FABRIC_TRANSMIT_ERROR_CHECKER_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_FABRIC_TRANSMIT_ERROR_CHECKER_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_fabric_transmit_error_checker_static_table_action_e");
        }
        return "";
    }
    npl_fabric_transmit_error_checker_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_fabric_transmit_error_checker_static_table_value_t element);
std::string to_short_string(struct npl_fabric_transmit_error_checker_static_table_value_t element);

/// API-s for table: fb_link_2_link_bundle_table

typedef enum
{
    NPL_FB_LINK_2_LINK_BUNDLE_TABLE_ACTION_WRITE = 0x0
} npl_fb_link_2_link_bundle_table_action_e;

struct npl_fb_link_2_link_bundle_table_key_t
{
    npl_fe_uc_random_fb_link_t fe_uc_random_fb_link;
    
    npl_fb_link_2_link_bundle_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_fb_link_2_link_bundle_table_key_t element);
std::string to_short_string(struct npl_fb_link_2_link_bundle_table_key_t element);

struct npl_fb_link_2_link_bundle_table_value_t
{
    npl_fb_link_2_link_bundle_table_action_e action;
    union npl_fb_link_2_link_bundle_table_payloads_t {
        npl_fb_link_2_link_bundle_table_result_t fb_link_2_link_bundle_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_fb_link_2_link_bundle_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_FB_LINK_2_LINK_BUNDLE_TABLE_ACTION_WRITE:
            {
                return "NPL_FB_LINK_2_LINK_BUNDLE_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_fb_link_2_link_bundle_table_action_e");
        }
        return "";
    }
    npl_fb_link_2_link_bundle_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_fb_link_2_link_bundle_table_value_t element);
std::string to_short_string(struct npl_fb_link_2_link_bundle_table_value_t element);

/// API-s for table: fe_broadcast_bmp_table

typedef enum
{
    NPL_FE_BROADCAST_BMP_TABLE_ACTION_WRITE = 0x0
} npl_fe_broadcast_bmp_table_action_e;

struct npl_fe_broadcast_bmp_table_key_t
{
    npl_random_bc_bmp_entry_t random_bc_bmp_entry;
    
    npl_fe_broadcast_bmp_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_fe_broadcast_bmp_table_key_t element);
std::string to_short_string(struct npl_fe_broadcast_bmp_table_key_t element);

struct npl_fe_broadcast_bmp_table_value_t
{
    npl_fe_broadcast_bmp_table_action_e action;
    union npl_fe_broadcast_bmp_table_payloads_t {
        npl_fe_broadcast_bmp_table_result_t fe_broadcast_bmp_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_fe_broadcast_bmp_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_FE_BROADCAST_BMP_TABLE_ACTION_WRITE:
            {
                return "NPL_FE_BROADCAST_BMP_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_fe_broadcast_bmp_table_action_e");
        }
        return "";
    }
    npl_fe_broadcast_bmp_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_fe_broadcast_bmp_table_value_t element);
std::string to_short_string(struct npl_fe_broadcast_bmp_table_value_t element);

/// API-s for table: fe_rlb_uc_tx_fb_link_to_oq_map_table

typedef enum
{
    NPL_FE_RLB_UC_TX_FB_LINK_TO_OQ_MAP_TABLE_ACTION_WRITE = 0x0
} npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_action_e;

struct npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_key_t
{
    npl_fe_uc_bundle_selected_link_t fe_uc_bundle_selected_link;
    
    npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_key_t element);
std::string to_short_string(struct npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_key_t element);

struct npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_value_t
{
    npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_action_e action;
    union npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_payloads_t {
        npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_result_t fe_rlb_uc_tx_fb_link_to_oq_map_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_FE_RLB_UC_TX_FB_LINK_TO_OQ_MAP_TABLE_ACTION_WRITE:
            {
                return "NPL_FE_RLB_UC_TX_FB_LINK_TO_OQ_MAP_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_action_e");
        }
        return "";
    }
    npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_value_t element);
std::string to_short_string(struct npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_value_t element);

/// API-s for table: fe_smcid_threshold_table

typedef enum
{
    NPL_FE_SMCID_THRESHOLD_TABLE_ACTION_WRITE = 0x0
} npl_fe_smcid_threshold_table_action_e;

struct npl_fe_smcid_threshold_table_key_t
{
    uint64_t dummy : 1;
    
    npl_fe_smcid_threshold_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_fe_smcid_threshold_table_key_t element);
std::string to_short_string(struct npl_fe_smcid_threshold_table_key_t element);

struct npl_fe_smcid_threshold_table_value_t
{
    npl_fe_smcid_threshold_table_action_e action;
    union npl_fe_smcid_threshold_table_payloads_t {
        npl_mcid_t smcid_threshold;
    } payloads;
    std::string npl_action_enum_to_string(const npl_fe_smcid_threshold_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_FE_SMCID_THRESHOLD_TABLE_ACTION_WRITE:
            {
                return "NPL_FE_SMCID_THRESHOLD_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_fe_smcid_threshold_table_action_e");
        }
        return "";
    }
    npl_fe_smcid_threshold_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_fe_smcid_threshold_table_value_t element);
std::string to_short_string(struct npl_fe_smcid_threshold_table_value_t element);

/// API-s for table: fe_smcid_to_mcid_table

typedef enum
{
    NPL_FE_SMCID_TO_MCID_TABLE_ACTION_WRITE = 0x0
} npl_fe_smcid_to_mcid_table_action_e;

struct npl_fe_smcid_to_mcid_table_key_t
{
    uint64_t system_mcid_17_3 : 15;
    
    npl_fe_smcid_to_mcid_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_fe_smcid_to_mcid_table_key_t element);
std::string to_short_string(struct npl_fe_smcid_to_mcid_table_key_t element);

struct npl_fe_smcid_to_mcid_table_value_t
{
    npl_fe_smcid_to_mcid_table_action_e action;
    union npl_fe_smcid_to_mcid_table_payloads_t {
        npl_mcid_array_t mcid_array;
    } payloads;
    std::string npl_action_enum_to_string(const npl_fe_smcid_to_mcid_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_FE_SMCID_TO_MCID_TABLE_ACTION_WRITE:
            {
                return "NPL_FE_SMCID_TO_MCID_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_fe_smcid_to_mcid_table_action_e");
        }
        return "";
    }
    npl_fe_smcid_to_mcid_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_fe_smcid_to_mcid_table_value_t element);
std::string to_short_string(struct npl_fe_smcid_to_mcid_table_value_t element);

/// API-s for table: fe_uc_link_bundle_desc_table

typedef enum
{
    NPL_FE_UC_LINK_BUNDLE_DESC_TABLE_ACTION_WRITE = 0x0
} npl_fe_uc_link_bundle_desc_table_action_e;

struct npl_fe_uc_link_bundle_desc_table_key_t
{
    uint64_t fb_link_2_link_bundle_table_result_bundle_num : 6;
    
    npl_fe_uc_link_bundle_desc_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_fe_uc_link_bundle_desc_table_key_t element);
std::string to_short_string(struct npl_fe_uc_link_bundle_desc_table_key_t element);

struct npl_fe_uc_link_bundle_desc_table_value_t
{
    npl_fe_uc_link_bundle_desc_table_action_e action;
    union npl_fe_uc_link_bundle_desc_table_payloads_t {
        npl_fe_uc_link_bundle_desc_table_result_t fe_uc_link_bundle_desc_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_fe_uc_link_bundle_desc_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_FE_UC_LINK_BUNDLE_DESC_TABLE_ACTION_WRITE:
            {
                return "NPL_FE_UC_LINK_BUNDLE_DESC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_fe_uc_link_bundle_desc_table_action_e");
        }
        return "";
    }
    npl_fe_uc_link_bundle_desc_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_fe_uc_link_bundle_desc_table_value_t element);
std::string to_short_string(struct npl_fe_uc_link_bundle_desc_table_value_t element);

/// API-s for table: fi_core_tcam_table

typedef enum
{
    NPL_FI_CORE_TCAM_TABLE_ACTION_WRITE = 0x0
} npl_fi_core_tcam_table_action_e;

struct npl_fi_core_tcam_table_key_t
{
    uint64_t fi_macro : 6;
    uint64_t header_data : 34;
    
    npl_fi_core_tcam_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_fi_core_tcam_table_key_t element);
std::string to_short_string(struct npl_fi_core_tcam_table_key_t element);

struct npl_fi_core_tcam_table_value_t
{
    npl_fi_core_tcam_table_action_e action;
    union npl_fi_core_tcam_table_payloads_t {
        npl_fi_core_tcam_assoc_data_t fi_core_tcam_assoc_data;
    } payloads;
    std::string npl_action_enum_to_string(const npl_fi_core_tcam_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_FI_CORE_TCAM_TABLE_ACTION_WRITE:
            {
                return "NPL_FI_CORE_TCAM_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_fi_core_tcam_table_action_e");
        }
        return "";
    }
    npl_fi_core_tcam_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_fi_core_tcam_table_value_t element);
std::string to_short_string(struct npl_fi_core_tcam_table_value_t element);

/// API-s for table: fi_macro_config_table

typedef enum
{
    NPL_FI_MACRO_CONFIG_TABLE_ACTION_WRITE = 0x0
} npl_fi_macro_config_table_action_e;

struct npl_fi_macro_config_table_key_t
{
    uint64_t fi_macro : 6;
    
    npl_fi_macro_config_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_fi_macro_config_table_key_t element);
std::string to_short_string(struct npl_fi_macro_config_table_key_t element);

struct npl_fi_macro_config_table_value_t
{
    npl_fi_macro_config_table_action_e action;
    union npl_fi_macro_config_table_payloads_t {
        npl_fi_macro_config_data_t fi_macro_config_data;
    } payloads;
    std::string npl_action_enum_to_string(const npl_fi_macro_config_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_FI_MACRO_CONFIG_TABLE_ACTION_WRITE:
            {
                return "NPL_FI_MACRO_CONFIG_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_fi_macro_config_table_action_e");
        }
        return "";
    }
    npl_fi_macro_config_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_fi_macro_config_table_value_t element);
std::string to_short_string(struct npl_fi_macro_config_table_value_t element);

/// API-s for table: filb_voq_mapping

typedef enum
{
    NPL_FILB_VOQ_MAPPING_ACTION_WRITE = 0x0
} npl_filb_voq_mapping_action_e;

struct npl_filb_voq_mapping_key_t
{
    uint64_t rxpdr_output_voq_nr : 16;
    
    npl_filb_voq_mapping_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_filb_voq_mapping_key_t element);
std::string to_short_string(struct npl_filb_voq_mapping_key_t element);

struct npl_filb_voq_mapping_value_t
{
    npl_filb_voq_mapping_action_e action;
    union npl_filb_voq_mapping_payloads_t {
        npl_filb_voq_mapping_result_t filb_voq_mapping_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_filb_voq_mapping_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_FILB_VOQ_MAPPING_ACTION_WRITE:
            {
                return "NPL_FILB_VOQ_MAPPING_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_filb_voq_mapping_action_e");
        }
        return "";
    }
    npl_filb_voq_mapping_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_filb_voq_mapping_value_t element);
std::string to_short_string(struct npl_filb_voq_mapping_value_t element);

/// API-s for table: first_ene_static_table

typedef enum
{
    NPL_FIRST_ENE_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_first_ene_static_table_action_e;

struct npl_first_ene_static_table_key_t
{
    npl_qos_first_macro_code_e first_macro_code;
    
    npl_first_ene_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_first_ene_static_table_key_t element);
std::string to_short_string(struct npl_first_ene_static_table_key_t element);

struct npl_first_ene_static_table_value_t
{
    npl_first_ene_static_table_action_e action;
    union npl_first_ene_static_table_payloads_t {
        npl_ene_macro_id_t first_ene_macro;
    } payloads;
    std::string npl_action_enum_to_string(const npl_first_ene_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_FIRST_ENE_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_FIRST_ENE_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_first_ene_static_table_action_e");
        }
        return "";
    }
    npl_first_ene_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_first_ene_static_table_value_t element);
std::string to_short_string(struct npl_first_ene_static_table_value_t element);

/// API-s for table: frm_db_fabric_routing_table

typedef enum
{
    NPL_FRM_DB_FABRIC_ROUTING_TABLE_ACTION_WRITE = 0x0
} npl_frm_db_fabric_routing_table_action_e;

struct npl_frm_db_fabric_routing_table_key_t
{
    uint64_t egress_device_id : 9;
    
    npl_frm_db_fabric_routing_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_frm_db_fabric_routing_table_key_t element);
std::string to_short_string(struct npl_frm_db_fabric_routing_table_key_t element);

struct npl_frm_db_fabric_routing_table_value_t
{
    npl_frm_db_fabric_routing_table_action_e action;
    union npl_frm_db_fabric_routing_table_payloads_t {
        npl_frm_db_fabric_routing_table_result_t frm_db_fabric_routing_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_frm_db_fabric_routing_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_FRM_DB_FABRIC_ROUTING_TABLE_ACTION_WRITE:
            {
                return "NPL_FRM_DB_FABRIC_ROUTING_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_frm_db_fabric_routing_table_action_e");
        }
        return "";
    }
    npl_frm_db_fabric_routing_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_frm_db_fabric_routing_table_value_t element);
std::string to_short_string(struct npl_frm_db_fabric_routing_table_value_t element);

/// API-s for table: fwd_destination_to_tm_result_data

typedef enum
{
    NPL_FWD_DESTINATION_TO_TM_RESULT_DATA_ACTION_FOUND = 0x0
} npl_fwd_destination_to_tm_result_data_action_e;

struct npl_fwd_destination_to_tm_result_data_found_payload_t
{
    uint64_t tx_cud : 24;
    uint64_t dest_slice_id : 3;
    uint64_t dest_pif : 5;
    uint64_t dest_ifg : 1;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_fwd_destination_to_tm_result_data_found_payload_t element);
std::string to_short_string(npl_fwd_destination_to_tm_result_data_found_payload_t element);

struct npl_fwd_destination_to_tm_result_data_key_t
{
    uint64_t rxpp_pd_fwd_destination_raw : 20;
    
    npl_fwd_destination_to_tm_result_data_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_fwd_destination_to_tm_result_data_key_t element);
std::string to_short_string(struct npl_fwd_destination_to_tm_result_data_key_t element);

struct npl_fwd_destination_to_tm_result_data_value_t
{
    npl_fwd_destination_to_tm_result_data_action_e action;
    union npl_fwd_destination_to_tm_result_data_payloads_t {
        npl_fwd_destination_to_tm_result_data_found_payload_t found;
    } payloads;
    std::string npl_action_enum_to_string(const npl_fwd_destination_to_tm_result_data_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_FWD_DESTINATION_TO_TM_RESULT_DATA_ACTION_FOUND:
            {
                return "NPL_FWD_DESTINATION_TO_TM_RESULT_DATA_ACTION_FOUND(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_fwd_destination_to_tm_result_data_action_e");
        }
        return "";
    }
    npl_fwd_destination_to_tm_result_data_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_fwd_destination_to_tm_result_data_value_t element);
std::string to_short_string(struct npl_fwd_destination_to_tm_result_data_value_t element);

/// API-s for table: fwd_type_to_ive_enable_table

typedef enum
{
    NPL_FWD_TYPE_TO_IVE_ENABLE_TABLE_ACTION_WRITE = 0x0
} npl_fwd_type_to_ive_enable_table_action_e;

struct npl_fwd_type_to_ive_enable_table_key_t
{
    npl_fwd_header_type_e txpp_npe_to_npe_metadata_fwd_header_type;
    
    npl_fwd_type_to_ive_enable_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_fwd_type_to_ive_enable_table_key_t element);
std::string to_short_string(struct npl_fwd_type_to_ive_enable_table_key_t element);

struct npl_fwd_type_to_ive_enable_table_value_t
{
    npl_fwd_type_to_ive_enable_table_action_e action;
    union npl_fwd_type_to_ive_enable_table_payloads_t {
        npl_ive_enable_t fwd_type_to_ive_enable;
    } payloads;
    std::string npl_action_enum_to_string(const npl_fwd_type_to_ive_enable_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_FWD_TYPE_TO_IVE_ENABLE_TABLE_ACTION_WRITE:
            {
                return "NPL_FWD_TYPE_TO_IVE_ENABLE_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_fwd_type_to_ive_enable_table_action_e");
        }
        return "";
    }
    npl_fwd_type_to_ive_enable_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_fwd_type_to_ive_enable_table_value_t element);
std::string to_short_string(struct npl_fwd_type_to_ive_enable_table_value_t element);

/// API-s for table: get_ecm_meter_ptr_table

typedef enum
{
    NPL_GET_ECM_METER_PTR_TABLE_ACTION_WRITE = 0x0
} npl_get_ecm_meter_ptr_table_action_e;

struct npl_get_ecm_meter_ptr_table_key_t
{
    uint64_t tm_h_ecn : 1;
    uint64_t tm_h_dp_0 : 1;
    
    npl_get_ecm_meter_ptr_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_get_ecm_meter_ptr_table_key_t element);
std::string to_short_string(struct npl_get_ecm_meter_ptr_table_key_t element);

struct npl_get_ecm_meter_ptr_table_value_t
{
    npl_get_ecm_meter_ptr_table_action_e action;
    union npl_get_ecm_meter_ptr_table_payloads_t {
        npl_counter_ptr_t stat_meter_ptr;
    } payloads;
    std::string npl_action_enum_to_string(const npl_get_ecm_meter_ptr_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_GET_ECM_METER_PTR_TABLE_ACTION_WRITE:
            {
                return "NPL_GET_ECM_METER_PTR_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_get_ecm_meter_ptr_table_action_e");
        }
        return "";
    }
    npl_get_ecm_meter_ptr_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_get_ecm_meter_ptr_table_value_t element);
std::string to_short_string(struct npl_get_ecm_meter_ptr_table_value_t element);

/// API-s for table: get_ingress_ptp_info_and_is_slp_dm_static_table

typedef enum
{
    NPL_GET_INGRESS_PTP_INFO_AND_IS_SLP_DM_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_get_ingress_ptp_info_and_is_slp_dm_static_table_action_e;

struct npl_get_ingress_ptp_info_and_is_slp_dm_static_table_key_t
{
    uint64_t enable_sr_dm_accounting : 1;
    uint64_t enable_transparent_ptp : 1;
    
    npl_get_ingress_ptp_info_and_is_slp_dm_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_get_ingress_ptp_info_and_is_slp_dm_static_table_key_t element);
std::string to_short_string(struct npl_get_ingress_ptp_info_and_is_slp_dm_static_table_key_t element);

struct npl_get_ingress_ptp_info_and_is_slp_dm_static_table_value_t
{
    npl_get_ingress_ptp_info_and_is_slp_dm_static_table_action_e action;
    union npl_get_ingress_ptp_info_and_is_slp_dm_static_table_payloads_t {
        npl_ingress_ptp_info_and_is_slp_dm_cmpressed_fields_t ingress_ptp_info_and_is_slp_dm_cmpressed_fields;
    } payloads;
    std::string npl_action_enum_to_string(const npl_get_ingress_ptp_info_and_is_slp_dm_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_GET_INGRESS_PTP_INFO_AND_IS_SLP_DM_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_GET_INGRESS_PTP_INFO_AND_IS_SLP_DM_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_get_ingress_ptp_info_and_is_slp_dm_static_table_action_e");
        }
        return "";
    }
    npl_get_ingress_ptp_info_and_is_slp_dm_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_get_ingress_ptp_info_and_is_slp_dm_static_table_value_t element);
std::string to_short_string(struct npl_get_ingress_ptp_info_and_is_slp_dm_static_table_value_t element);

/// API-s for table: get_l2_rtf_conf_set_and_init_stages

typedef enum
{
    NPL_GET_L2_RTF_CONF_SET_AND_INIT_STAGES_ACTION_WRITE = 0x0
} npl_get_l2_rtf_conf_set_and_init_stages_action_e;

struct npl_get_l2_rtf_conf_set_and_init_stages_key_t
{
    uint64_t rtf_conf_set_ptr : 8;
    
    npl_get_l2_rtf_conf_set_and_init_stages_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_get_l2_rtf_conf_set_and_init_stages_key_t element);
std::string to_short_string(struct npl_get_l2_rtf_conf_set_and_init_stages_key_t element);

struct npl_get_l2_rtf_conf_set_and_init_stages_value_t
{
    npl_get_l2_rtf_conf_set_and_init_stages_action_e action;
    union npl_get_l2_rtf_conf_set_and_init_stages_payloads_t {
        npl_l2_rtf_conf_set_and_init_stages_t l2_rtf_conf_set_and_init_stages;
    } payloads;
    std::string npl_action_enum_to_string(const npl_get_l2_rtf_conf_set_and_init_stages_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_GET_L2_RTF_CONF_SET_AND_INIT_STAGES_ACTION_WRITE:
            {
                return "NPL_GET_L2_RTF_CONF_SET_AND_INIT_STAGES_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_get_l2_rtf_conf_set_and_init_stages_action_e");
        }
        return "";
    }
    npl_get_l2_rtf_conf_set_and_init_stages_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_get_l2_rtf_conf_set_and_init_stages_value_t element);
std::string to_short_string(struct npl_get_l2_rtf_conf_set_and_init_stages_value_t element);

/// API-s for table: get_non_comp_mc_value_static_table

typedef enum
{
    NPL_GET_NON_COMP_MC_VALUE_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_get_non_comp_mc_value_static_table_action_e;

struct npl_get_non_comp_mc_value_static_table_key_t
{
    uint64_t packet_type_bit0 : 1;
    uint64_t not_comp_single_src : 1;
    
    npl_get_non_comp_mc_value_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_get_non_comp_mc_value_static_table_key_t element);
std::string to_short_string(struct npl_get_non_comp_mc_value_static_table_key_t element);

struct npl_get_non_comp_mc_value_static_table_value_t
{
    npl_get_non_comp_mc_value_static_table_action_e action;
    union npl_get_non_comp_mc_value_static_table_payloads_t {
        uint64_t non_comp_mc_trap : 1;
    } payloads;
    std::string npl_action_enum_to_string(const npl_get_non_comp_mc_value_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_GET_NON_COMP_MC_VALUE_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_GET_NON_COMP_MC_VALUE_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_get_non_comp_mc_value_static_table_action_e");
        }
        return "";
    }
    npl_get_non_comp_mc_value_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_get_non_comp_mc_value_static_table_value_t element);
std::string to_short_string(struct npl_get_non_comp_mc_value_static_table_value_t element);

/// API-s for table: gre_proto_static_table

typedef enum
{
    NPL_GRE_PROTO_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_gre_proto_static_table_action_e;

struct npl_gre_proto_static_table_key_t
{
    uint64_t proto : 1;
    uint64_t label_present : 1;
    
    npl_gre_proto_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_gre_proto_static_table_key_t element);
std::string to_short_string(struct npl_gre_proto_static_table_key_t element);

struct npl_gre_proto_static_table_value_t
{
    npl_gre_proto_static_table_action_e action;
    union npl_gre_proto_static_table_payloads_t {
        uint64_t gre_proto : 24;
    } payloads;
    std::string npl_action_enum_to_string(const npl_gre_proto_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_GRE_PROTO_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_GRE_PROTO_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_gre_proto_static_table_action_e");
        }
        return "";
    }
    npl_gre_proto_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_gre_proto_static_table_value_t element);
std::string to_short_string(struct npl_gre_proto_static_table_value_t element);

/// API-s for table: hmc_cgm_cgm_lut_table

typedef enum
{
    NPL_HMC_CGM_CGM_LUT_TABLE_ACTION_WRITE = 0x0
} npl_hmc_cgm_cgm_lut_table_action_e;

struct npl_hmc_cgm_cgm_lut_table_key_t
{
    npl_voq_profile_len profile_id;
    uint64_t queue_size_level : 4;
    uint64_t shared_pool_th_level : 3;
    
    npl_hmc_cgm_cgm_lut_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_hmc_cgm_cgm_lut_table_key_t element);
std::string to_short_string(struct npl_hmc_cgm_cgm_lut_table_key_t element);

struct npl_hmc_cgm_cgm_lut_table_value_t
{
    npl_hmc_cgm_cgm_lut_table_action_e action;
    union npl_hmc_cgm_cgm_lut_table_payloads_t {
        npl_hmc_cgm_cgm_lut_results_t hmc_cgm_cgm_lut_results;
    } payloads;
    std::string npl_action_enum_to_string(const npl_hmc_cgm_cgm_lut_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_HMC_CGM_CGM_LUT_TABLE_ACTION_WRITE:
            {
                return "NPL_HMC_CGM_CGM_LUT_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_hmc_cgm_cgm_lut_table_action_e");
        }
        return "";
    }
    npl_hmc_cgm_cgm_lut_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_hmc_cgm_cgm_lut_table_value_t element);
std::string to_short_string(struct npl_hmc_cgm_cgm_lut_table_value_t element);

/// API-s for table: hmc_cgm_profile_global_table

typedef enum
{
    NPL_HMC_CGM_PROFILE_GLOBAL_TABLE_ACTION_WRITE = 0x0
} npl_hmc_cgm_profile_global_table_action_e;

struct npl_hmc_cgm_profile_global_table_key_t
{
    npl_voq_profile_len profile_id;
    
    npl_hmc_cgm_profile_global_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_hmc_cgm_profile_global_table_key_t element);
std::string to_short_string(struct npl_hmc_cgm_profile_global_table_key_t element);

struct npl_hmc_cgm_profile_global_table_value_t
{
    npl_hmc_cgm_profile_global_table_action_e action;
    union npl_hmc_cgm_profile_global_table_payloads_t {
        npl_hmc_cgm_profile_global_results_t hmc_cgm_profile_global_results;
    } payloads;
    std::string npl_action_enum_to_string(const npl_hmc_cgm_profile_global_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_HMC_CGM_PROFILE_GLOBAL_TABLE_ACTION_WRITE:
            {
                return "NPL_HMC_CGM_PROFILE_GLOBAL_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_hmc_cgm_profile_global_table_action_e");
        }
        return "";
    }
    npl_hmc_cgm_profile_global_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector384_t pack(void) const;
    void unpack(bit_vector384_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_hmc_cgm_profile_global_table_value_t element);
std::string to_short_string(struct npl_hmc_cgm_profile_global_table_value_t element);

/// API-s for table: ibm_cmd_table

typedef enum
{
    NPL_IBM_CMD_TABLE_ACTION_WRITE = 0x0
} npl_ibm_cmd_table_action_e;

struct npl_ibm_cmd_table_key_t
{
    uint64_t rxpp_to_txpp_local_vars_mirror_command : 5;
    
    npl_ibm_cmd_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ibm_cmd_table_key_t element);
std::string to_short_string(struct npl_ibm_cmd_table_key_t element);

struct npl_ibm_cmd_table_value_t
{
    npl_ibm_cmd_table_action_e action;
    union npl_ibm_cmd_table_payloads_t {
        npl_ibm_cmd_table_result_t ibm_cmd_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ibm_cmd_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IBM_CMD_TABLE_ACTION_WRITE:
            {
                return "NPL_IBM_CMD_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ibm_cmd_table_action_e");
        }
        return "";
    }
    npl_ibm_cmd_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ibm_cmd_table_value_t element);
std::string to_short_string(struct npl_ibm_cmd_table_value_t element);

/// API-s for table: ibm_mc_cmd_to_encap_data_table

typedef enum
{
    NPL_IBM_MC_CMD_TO_ENCAP_DATA_TABLE_ACTION_WRITE = 0x0
} npl_ibm_mc_cmd_to_encap_data_table_action_e;

struct npl_ibm_mc_cmd_to_encap_data_table_key_t
{
    uint64_t tx_fabric_tx_cud_20_16_ : 5;
    
    npl_ibm_mc_cmd_to_encap_data_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ibm_mc_cmd_to_encap_data_table_key_t element);
std::string to_short_string(struct npl_ibm_mc_cmd_to_encap_data_table_key_t element);

struct npl_ibm_mc_cmd_to_encap_data_table_value_t
{
    npl_ibm_mc_cmd_to_encap_data_table_action_e action;
    union npl_ibm_mc_cmd_to_encap_data_table_payloads_t {
        npl_ingress_punt_mc_expand_encap_t ibm_mc_fabric_encap_msb;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ibm_mc_cmd_to_encap_data_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IBM_MC_CMD_TO_ENCAP_DATA_TABLE_ACTION_WRITE:
            {
                return "NPL_IBM_MC_CMD_TO_ENCAP_DATA_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ibm_mc_cmd_to_encap_data_table_action_e");
        }
        return "";
    }
    npl_ibm_mc_cmd_to_encap_data_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ibm_mc_cmd_to_encap_data_table_value_t element);
std::string to_short_string(struct npl_ibm_mc_cmd_to_encap_data_table_value_t element);

/// API-s for table: ibm_uc_cmd_to_encap_data_table

typedef enum
{
    NPL_IBM_UC_CMD_TO_ENCAP_DATA_TABLE_ACTION_WRITE = 0x0
} npl_ibm_uc_cmd_to_encap_data_table_action_e;

struct npl_ibm_uc_cmd_to_encap_data_table_key_t
{
    uint64_t tx_fabric_tx_cud_4_0_ : 5;
    
    npl_ibm_uc_cmd_to_encap_data_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ibm_uc_cmd_to_encap_data_table_key_t element);
std::string to_short_string(struct npl_ibm_uc_cmd_to_encap_data_table_key_t element);

struct npl_ibm_uc_cmd_to_encap_data_table_value_t
{
    npl_ibm_uc_cmd_to_encap_data_table_action_e action;
    union npl_ibm_uc_cmd_to_encap_data_table_payloads_t {
        npl_punt_app_encap_t ibm_uc_fabric_encap;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ibm_uc_cmd_to_encap_data_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IBM_UC_CMD_TO_ENCAP_DATA_TABLE_ACTION_WRITE:
            {
                return "NPL_IBM_UC_CMD_TO_ENCAP_DATA_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ibm_uc_cmd_to_encap_data_table_action_e");
        }
        return "";
    }
    npl_ibm_uc_cmd_to_encap_data_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ibm_uc_cmd_to_encap_data_table_value_t element);
std::string to_short_string(struct npl_ibm_uc_cmd_to_encap_data_table_value_t element);

/// API-s for table: ifgb_tc_lut_table

typedef enum
{
    NPL_IFGB_TC_LUT_TABLE_ACTION_WRITE = 0x0
} npl_ifgb_tc_lut_table_action_e;

struct npl_ifgb_tc_lut_table_key_t
{
    uint64_t ifg : 1;
    uint64_t serdes_pair : 4;
    uint64_t port : 1;
    uint64_t protocol : 3;
    uint64_t tpid : 2;
    
    npl_ifgb_tc_lut_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ifgb_tc_lut_table_key_t element);
std::string to_short_string(struct npl_ifgb_tc_lut_table_key_t element);

struct npl_ifgb_tc_lut_table_value_t
{
    npl_ifgb_tc_lut_table_action_e action;
    union npl_ifgb_tc_lut_table_payloads_t {
        npl_ifgb_tc_lut_results_t ifgb_tc_lut_results;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ifgb_tc_lut_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IFGB_TC_LUT_TABLE_ACTION_WRITE:
            {
                return "NPL_IFGB_TC_LUT_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ifgb_tc_lut_table_action_e");
        }
        return "";
    }
    npl_ifgb_tc_lut_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ifgb_tc_lut_table_value_t element);
std::string to_short_string(struct npl_ifgb_tc_lut_table_value_t element);

/// API-s for table: ingress_ip_qos_mapping_table

typedef enum
{
    NPL_INGRESS_IP_QOS_MAPPING_TABLE_ACTION_WRITE = 0x0
} npl_ingress_ip_qos_mapping_table_action_e;

struct npl_ingress_ip_qos_mapping_table_key_t
{
    uint64_t l3_qos_mapping_key : 7;
    uint64_t qos_id : 4;
    
    npl_ingress_ip_qos_mapping_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ingress_ip_qos_mapping_table_key_t element);
std::string to_short_string(struct npl_ingress_ip_qos_mapping_table_key_t element);

struct npl_ingress_ip_qos_mapping_table_value_t
{
    npl_ingress_ip_qos_mapping_table_action_e action;
    union npl_ingress_ip_qos_mapping_table_payloads_t {
        npl_ingress_qos_result_t ip_qos_mapping_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ingress_ip_qos_mapping_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_INGRESS_IP_QOS_MAPPING_TABLE_ACTION_WRITE:
            {
                return "NPL_INGRESS_IP_QOS_MAPPING_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ingress_ip_qos_mapping_table_action_e");
        }
        return "";
    }
    npl_ingress_ip_qos_mapping_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ingress_ip_qos_mapping_table_value_t element);
std::string to_short_string(struct npl_ingress_ip_qos_mapping_table_value_t element);

/// API-s for table: ingress_rtf_eth_db1_160_f0_table

typedef enum
{
    NPL_INGRESS_RTF_ETH_DB1_160_F0_TABLE_ACTION_WRITE = 0x0
} npl_ingress_rtf_eth_db1_160_f0_table_action_e;

struct npl_ingress_rtf_eth_db1_160_f0_table_key_t
{
    npl_ud_key_t ud_key;
    
    npl_ingress_rtf_eth_db1_160_f0_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector pack(void) const;
    void unpack(bit_vector bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ingress_rtf_eth_db1_160_f0_table_key_t element);
std::string to_short_string(struct npl_ingress_rtf_eth_db1_160_f0_table_key_t element);

struct npl_ingress_rtf_eth_db1_160_f0_table_value_t
{
    npl_ingress_rtf_eth_db1_160_f0_table_action_e action;
    union npl_ingress_rtf_eth_db1_160_f0_table_payloads_t {
        npl_rtf_payload_t rtf_payload;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ingress_rtf_eth_db1_160_f0_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_INGRESS_RTF_ETH_DB1_160_F0_TABLE_ACTION_WRITE:
            {
                return "NPL_INGRESS_RTF_ETH_DB1_160_F0_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ingress_rtf_eth_db1_160_f0_table_action_e");
        }
        return "";
    }
    npl_ingress_rtf_eth_db1_160_f0_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ingress_rtf_eth_db1_160_f0_table_value_t element);
std::string to_short_string(struct npl_ingress_rtf_eth_db1_160_f0_table_value_t element);

/// API-s for table: ingress_rtf_eth_db2_160_f0_table

typedef enum
{
    NPL_INGRESS_RTF_ETH_DB2_160_F0_TABLE_ACTION_WRITE = 0x0
} npl_ingress_rtf_eth_db2_160_f0_table_action_e;

struct npl_ingress_rtf_eth_db2_160_f0_table_key_t
{
    npl_ud_key_t ud_key;
    
    npl_ingress_rtf_eth_db2_160_f0_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector pack(void) const;
    void unpack(bit_vector bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ingress_rtf_eth_db2_160_f0_table_key_t element);
std::string to_short_string(struct npl_ingress_rtf_eth_db2_160_f0_table_key_t element);

struct npl_ingress_rtf_eth_db2_160_f0_table_value_t
{
    npl_ingress_rtf_eth_db2_160_f0_table_action_e action;
    union npl_ingress_rtf_eth_db2_160_f0_table_payloads_t {
        npl_rtf_payload_t rtf_payload;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ingress_rtf_eth_db2_160_f0_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_INGRESS_RTF_ETH_DB2_160_F0_TABLE_ACTION_WRITE:
            {
                return "NPL_INGRESS_RTF_ETH_DB2_160_F0_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ingress_rtf_eth_db2_160_f0_table_action_e");
        }
        return "";
    }
    npl_ingress_rtf_eth_db2_160_f0_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ingress_rtf_eth_db2_160_f0_table_value_t element);
std::string to_short_string(struct npl_ingress_rtf_eth_db2_160_f0_table_value_t element);

/// API-s for table: ingress_rtf_ipv4_db1_160_f0_table

typedef enum
{
    NPL_INGRESS_RTF_IPV4_DB1_160_F0_TABLE_ACTION_WRITE = 0x0
} npl_ingress_rtf_ipv4_db1_160_f0_table_action_e;

struct npl_ingress_rtf_ipv4_db1_160_f0_table_key_t
{
    npl_ud_key_t ud_key;
    
    npl_ingress_rtf_ipv4_db1_160_f0_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector pack(void) const;
    void unpack(bit_vector bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ingress_rtf_ipv4_db1_160_f0_table_key_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv4_db1_160_f0_table_key_t element);

struct npl_ingress_rtf_ipv4_db1_160_f0_table_value_t
{
    npl_ingress_rtf_ipv4_db1_160_f0_table_action_e action;
    union npl_ingress_rtf_ipv4_db1_160_f0_table_payloads_t {
        npl_rtf_payload_t rtf_payload;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ingress_rtf_ipv4_db1_160_f0_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_INGRESS_RTF_IPV4_DB1_160_F0_TABLE_ACTION_WRITE:
            {
                return "NPL_INGRESS_RTF_IPV4_DB1_160_F0_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ingress_rtf_ipv4_db1_160_f0_table_action_e");
        }
        return "";
    }
    npl_ingress_rtf_ipv4_db1_160_f0_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ingress_rtf_ipv4_db1_160_f0_table_value_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv4_db1_160_f0_table_value_t element);

/// API-s for table: ingress_rtf_ipv4_db1_160_f1_table

typedef enum
{
    NPL_INGRESS_RTF_IPV4_DB1_160_F1_TABLE_ACTION_WRITE = 0x0
} npl_ingress_rtf_ipv4_db1_160_f1_table_action_e;

struct npl_ingress_rtf_ipv4_db1_160_f1_table_key_t
{
    npl_ud_key_t ud_key;
    
    npl_ingress_rtf_ipv4_db1_160_f1_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector pack(void) const;
    void unpack(bit_vector bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ingress_rtf_ipv4_db1_160_f1_table_key_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv4_db1_160_f1_table_key_t element);

struct npl_ingress_rtf_ipv4_db1_160_f1_table_value_t
{
    npl_ingress_rtf_ipv4_db1_160_f1_table_action_e action;
    union npl_ingress_rtf_ipv4_db1_160_f1_table_payloads_t {
        npl_rtf_payload_t rtf_payload_f1;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ingress_rtf_ipv4_db1_160_f1_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_INGRESS_RTF_IPV4_DB1_160_F1_TABLE_ACTION_WRITE:
            {
                return "NPL_INGRESS_RTF_IPV4_DB1_160_F1_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ingress_rtf_ipv4_db1_160_f1_table_action_e");
        }
        return "";
    }
    npl_ingress_rtf_ipv4_db1_160_f1_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ingress_rtf_ipv4_db1_160_f1_table_value_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv4_db1_160_f1_table_value_t element);

/// API-s for table: ingress_rtf_ipv4_db1_320_f0_table

typedef enum
{
    NPL_INGRESS_RTF_IPV4_DB1_320_F0_TABLE_ACTION_WRITE = 0x0
} npl_ingress_rtf_ipv4_db1_320_f0_table_action_e;

struct npl_ingress_rtf_ipv4_db1_320_f0_table_key_t
{
    npl_ud_key_t ud_key;
    
    npl_ingress_rtf_ipv4_db1_320_f0_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector pack(void) const;
    void unpack(bit_vector bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ingress_rtf_ipv4_db1_320_f0_table_key_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv4_db1_320_f0_table_key_t element);

struct npl_ingress_rtf_ipv4_db1_320_f0_table_value_t
{
    npl_ingress_rtf_ipv4_db1_320_f0_table_action_e action;
    union npl_ingress_rtf_ipv4_db1_320_f0_table_payloads_t {
        npl_rtf_payload_t rtf_payload;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ingress_rtf_ipv4_db1_320_f0_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_INGRESS_RTF_IPV4_DB1_320_F0_TABLE_ACTION_WRITE:
            {
                return "NPL_INGRESS_RTF_IPV4_DB1_320_F0_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ingress_rtf_ipv4_db1_320_f0_table_action_e");
        }
        return "";
    }
    npl_ingress_rtf_ipv4_db1_320_f0_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ingress_rtf_ipv4_db1_320_f0_table_value_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv4_db1_320_f0_table_value_t element);

/// API-s for table: ingress_rtf_ipv4_db2_160_f0_table

typedef enum
{
    NPL_INGRESS_RTF_IPV4_DB2_160_F0_TABLE_ACTION_WRITE = 0x0
} npl_ingress_rtf_ipv4_db2_160_f0_table_action_e;

struct npl_ingress_rtf_ipv4_db2_160_f0_table_key_t
{
    npl_ud_key_t ud_key;
    
    npl_ingress_rtf_ipv4_db2_160_f0_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector pack(void) const;
    void unpack(bit_vector bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ingress_rtf_ipv4_db2_160_f0_table_key_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv4_db2_160_f0_table_key_t element);

struct npl_ingress_rtf_ipv4_db2_160_f0_table_value_t
{
    npl_ingress_rtf_ipv4_db2_160_f0_table_action_e action;
    union npl_ingress_rtf_ipv4_db2_160_f0_table_payloads_t {
        npl_rtf_payload_t rtf_payload;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ingress_rtf_ipv4_db2_160_f0_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_INGRESS_RTF_IPV4_DB2_160_F0_TABLE_ACTION_WRITE:
            {
                return "NPL_INGRESS_RTF_IPV4_DB2_160_F0_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ingress_rtf_ipv4_db2_160_f0_table_action_e");
        }
        return "";
    }
    npl_ingress_rtf_ipv4_db2_160_f0_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ingress_rtf_ipv4_db2_160_f0_table_value_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv4_db2_160_f0_table_value_t element);

/// API-s for table: ingress_rtf_ipv4_db2_160_f1_table

typedef enum
{
    NPL_INGRESS_RTF_IPV4_DB2_160_F1_TABLE_ACTION_WRITE = 0x0
} npl_ingress_rtf_ipv4_db2_160_f1_table_action_e;

struct npl_ingress_rtf_ipv4_db2_160_f1_table_key_t
{
    npl_ud_key_t ud_key;
    
    npl_ingress_rtf_ipv4_db2_160_f1_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector pack(void) const;
    void unpack(bit_vector bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ingress_rtf_ipv4_db2_160_f1_table_key_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv4_db2_160_f1_table_key_t element);

struct npl_ingress_rtf_ipv4_db2_160_f1_table_value_t
{
    npl_ingress_rtf_ipv4_db2_160_f1_table_action_e action;
    union npl_ingress_rtf_ipv4_db2_160_f1_table_payloads_t {
        npl_rtf_payload_t rtf_payload_f1;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ingress_rtf_ipv4_db2_160_f1_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_INGRESS_RTF_IPV4_DB2_160_F1_TABLE_ACTION_WRITE:
            {
                return "NPL_INGRESS_RTF_IPV4_DB2_160_F1_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ingress_rtf_ipv4_db2_160_f1_table_action_e");
        }
        return "";
    }
    npl_ingress_rtf_ipv4_db2_160_f1_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ingress_rtf_ipv4_db2_160_f1_table_value_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv4_db2_160_f1_table_value_t element);

/// API-s for table: ingress_rtf_ipv4_db2_320_f0_table

typedef enum
{
    NPL_INGRESS_RTF_IPV4_DB2_320_F0_TABLE_ACTION_WRITE = 0x0
} npl_ingress_rtf_ipv4_db2_320_f0_table_action_e;

struct npl_ingress_rtf_ipv4_db2_320_f0_table_key_t
{
    npl_ud_key_t ud_key;
    
    npl_ingress_rtf_ipv4_db2_320_f0_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector pack(void) const;
    void unpack(bit_vector bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ingress_rtf_ipv4_db2_320_f0_table_key_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv4_db2_320_f0_table_key_t element);

struct npl_ingress_rtf_ipv4_db2_320_f0_table_value_t
{
    npl_ingress_rtf_ipv4_db2_320_f0_table_action_e action;
    union npl_ingress_rtf_ipv4_db2_320_f0_table_payloads_t {
        npl_rtf_payload_t rtf_payload;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ingress_rtf_ipv4_db2_320_f0_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_INGRESS_RTF_IPV4_DB2_320_F0_TABLE_ACTION_WRITE:
            {
                return "NPL_INGRESS_RTF_IPV4_DB2_320_F0_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ingress_rtf_ipv4_db2_320_f0_table_action_e");
        }
        return "";
    }
    npl_ingress_rtf_ipv4_db2_320_f0_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ingress_rtf_ipv4_db2_320_f0_table_value_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv4_db2_320_f0_table_value_t element);

/// API-s for table: ingress_rtf_ipv4_db3_160_f0_table

typedef enum
{
    NPL_INGRESS_RTF_IPV4_DB3_160_F0_TABLE_ACTION_WRITE = 0x0
} npl_ingress_rtf_ipv4_db3_160_f0_table_action_e;

struct npl_ingress_rtf_ipv4_db3_160_f0_table_key_t
{
    npl_ud_key_t ud_key;
    
    npl_ingress_rtf_ipv4_db3_160_f0_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector pack(void) const;
    void unpack(bit_vector bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ingress_rtf_ipv4_db3_160_f0_table_key_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv4_db3_160_f0_table_key_t element);

struct npl_ingress_rtf_ipv4_db3_160_f0_table_value_t
{
    npl_ingress_rtf_ipv4_db3_160_f0_table_action_e action;
    union npl_ingress_rtf_ipv4_db3_160_f0_table_payloads_t {
        npl_rtf_payload_t rtf_payload;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ingress_rtf_ipv4_db3_160_f0_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_INGRESS_RTF_IPV4_DB3_160_F0_TABLE_ACTION_WRITE:
            {
                return "NPL_INGRESS_RTF_IPV4_DB3_160_F0_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ingress_rtf_ipv4_db3_160_f0_table_action_e");
        }
        return "";
    }
    npl_ingress_rtf_ipv4_db3_160_f0_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ingress_rtf_ipv4_db3_160_f0_table_value_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv4_db3_160_f0_table_value_t element);

/// API-s for table: ingress_rtf_ipv4_db3_160_f1_table

typedef enum
{
    NPL_INGRESS_RTF_IPV4_DB3_160_F1_TABLE_ACTION_WRITE = 0x0
} npl_ingress_rtf_ipv4_db3_160_f1_table_action_e;

struct npl_ingress_rtf_ipv4_db3_160_f1_table_key_t
{
    npl_ud_key_t ud_key;
    
    npl_ingress_rtf_ipv4_db3_160_f1_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector pack(void) const;
    void unpack(bit_vector bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ingress_rtf_ipv4_db3_160_f1_table_key_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv4_db3_160_f1_table_key_t element);

struct npl_ingress_rtf_ipv4_db3_160_f1_table_value_t
{
    npl_ingress_rtf_ipv4_db3_160_f1_table_action_e action;
    union npl_ingress_rtf_ipv4_db3_160_f1_table_payloads_t {
        npl_rtf_payload_t rtf_payload_f1;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ingress_rtf_ipv4_db3_160_f1_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_INGRESS_RTF_IPV4_DB3_160_F1_TABLE_ACTION_WRITE:
            {
                return "NPL_INGRESS_RTF_IPV4_DB3_160_F1_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ingress_rtf_ipv4_db3_160_f1_table_action_e");
        }
        return "";
    }
    npl_ingress_rtf_ipv4_db3_160_f1_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ingress_rtf_ipv4_db3_160_f1_table_value_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv4_db3_160_f1_table_value_t element);

/// API-s for table: ingress_rtf_ipv4_db3_320_f0_table

typedef enum
{
    NPL_INGRESS_RTF_IPV4_DB3_320_F0_TABLE_ACTION_WRITE = 0x0
} npl_ingress_rtf_ipv4_db3_320_f0_table_action_e;

struct npl_ingress_rtf_ipv4_db3_320_f0_table_key_t
{
    npl_ud_key_t ud_key;
    
    npl_ingress_rtf_ipv4_db3_320_f0_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector pack(void) const;
    void unpack(bit_vector bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ingress_rtf_ipv4_db3_320_f0_table_key_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv4_db3_320_f0_table_key_t element);

struct npl_ingress_rtf_ipv4_db3_320_f0_table_value_t
{
    npl_ingress_rtf_ipv4_db3_320_f0_table_action_e action;
    union npl_ingress_rtf_ipv4_db3_320_f0_table_payloads_t {
        npl_rtf_payload_t rtf_payload;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ingress_rtf_ipv4_db3_320_f0_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_INGRESS_RTF_IPV4_DB3_320_F0_TABLE_ACTION_WRITE:
            {
                return "NPL_INGRESS_RTF_IPV4_DB3_320_F0_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ingress_rtf_ipv4_db3_320_f0_table_action_e");
        }
        return "";
    }
    npl_ingress_rtf_ipv4_db3_320_f0_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ingress_rtf_ipv4_db3_320_f0_table_value_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv4_db3_320_f0_table_value_t element);

/// API-s for table: ingress_rtf_ipv4_db4_160_f0_table

typedef enum
{
    NPL_INGRESS_RTF_IPV4_DB4_160_F0_TABLE_ACTION_WRITE = 0x0
} npl_ingress_rtf_ipv4_db4_160_f0_table_action_e;

struct npl_ingress_rtf_ipv4_db4_160_f0_table_key_t
{
    npl_ud_key_t ud_key;
    
    npl_ingress_rtf_ipv4_db4_160_f0_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector pack(void) const;
    void unpack(bit_vector bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ingress_rtf_ipv4_db4_160_f0_table_key_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv4_db4_160_f0_table_key_t element);

struct npl_ingress_rtf_ipv4_db4_160_f0_table_value_t
{
    npl_ingress_rtf_ipv4_db4_160_f0_table_action_e action;
    union npl_ingress_rtf_ipv4_db4_160_f0_table_payloads_t {
        npl_rtf_payload_t rtf_payload;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ingress_rtf_ipv4_db4_160_f0_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_INGRESS_RTF_IPV4_DB4_160_F0_TABLE_ACTION_WRITE:
            {
                return "NPL_INGRESS_RTF_IPV4_DB4_160_F0_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ingress_rtf_ipv4_db4_160_f0_table_action_e");
        }
        return "";
    }
    npl_ingress_rtf_ipv4_db4_160_f0_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ingress_rtf_ipv4_db4_160_f0_table_value_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv4_db4_160_f0_table_value_t element);

/// API-s for table: ingress_rtf_ipv4_db4_160_f1_table

typedef enum
{
    NPL_INGRESS_RTF_IPV4_DB4_160_F1_TABLE_ACTION_WRITE = 0x0
} npl_ingress_rtf_ipv4_db4_160_f1_table_action_e;

struct npl_ingress_rtf_ipv4_db4_160_f1_table_key_t
{
    npl_ud_key_t ud_key;
    
    npl_ingress_rtf_ipv4_db4_160_f1_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector pack(void) const;
    void unpack(bit_vector bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ingress_rtf_ipv4_db4_160_f1_table_key_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv4_db4_160_f1_table_key_t element);

struct npl_ingress_rtf_ipv4_db4_160_f1_table_value_t
{
    npl_ingress_rtf_ipv4_db4_160_f1_table_action_e action;
    union npl_ingress_rtf_ipv4_db4_160_f1_table_payloads_t {
        npl_rtf_payload_t rtf_payload_f1;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ingress_rtf_ipv4_db4_160_f1_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_INGRESS_RTF_IPV4_DB4_160_F1_TABLE_ACTION_WRITE:
            {
                return "NPL_INGRESS_RTF_IPV4_DB4_160_F1_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ingress_rtf_ipv4_db4_160_f1_table_action_e");
        }
        return "";
    }
    npl_ingress_rtf_ipv4_db4_160_f1_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ingress_rtf_ipv4_db4_160_f1_table_value_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv4_db4_160_f1_table_value_t element);

/// API-s for table: ingress_rtf_ipv4_db4_320_f0_table

typedef enum
{
    NPL_INGRESS_RTF_IPV4_DB4_320_F0_TABLE_ACTION_WRITE = 0x0
} npl_ingress_rtf_ipv4_db4_320_f0_table_action_e;

struct npl_ingress_rtf_ipv4_db4_320_f0_table_key_t
{
    npl_ud_key_t ud_key;
    
    npl_ingress_rtf_ipv4_db4_320_f0_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector pack(void) const;
    void unpack(bit_vector bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ingress_rtf_ipv4_db4_320_f0_table_key_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv4_db4_320_f0_table_key_t element);

struct npl_ingress_rtf_ipv4_db4_320_f0_table_value_t
{
    npl_ingress_rtf_ipv4_db4_320_f0_table_action_e action;
    union npl_ingress_rtf_ipv4_db4_320_f0_table_payloads_t {
        npl_rtf_payload_t rtf_payload;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ingress_rtf_ipv4_db4_320_f0_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_INGRESS_RTF_IPV4_DB4_320_F0_TABLE_ACTION_WRITE:
            {
                return "NPL_INGRESS_RTF_IPV4_DB4_320_F0_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ingress_rtf_ipv4_db4_320_f0_table_action_e");
        }
        return "";
    }
    npl_ingress_rtf_ipv4_db4_320_f0_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ingress_rtf_ipv4_db4_320_f0_table_value_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv4_db4_320_f0_table_value_t element);

/// API-s for table: ingress_rtf_ipv6_db1_160_f0_table

typedef enum
{
    NPL_INGRESS_RTF_IPV6_DB1_160_F0_TABLE_ACTION_WRITE = 0x0
} npl_ingress_rtf_ipv6_db1_160_f0_table_action_e;

struct npl_ingress_rtf_ipv6_db1_160_f0_table_key_t
{
    npl_ud_key_t ud_key;
    
    npl_ingress_rtf_ipv6_db1_160_f0_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector pack(void) const;
    void unpack(bit_vector bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ingress_rtf_ipv6_db1_160_f0_table_key_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv6_db1_160_f0_table_key_t element);

struct npl_ingress_rtf_ipv6_db1_160_f0_table_value_t
{
    npl_ingress_rtf_ipv6_db1_160_f0_table_action_e action;
    union npl_ingress_rtf_ipv6_db1_160_f0_table_payloads_t {
        npl_rtf_payload_t rtf_payload;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ingress_rtf_ipv6_db1_160_f0_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_INGRESS_RTF_IPV6_DB1_160_F0_TABLE_ACTION_WRITE:
            {
                return "NPL_INGRESS_RTF_IPV6_DB1_160_F0_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ingress_rtf_ipv6_db1_160_f0_table_action_e");
        }
        return "";
    }
    npl_ingress_rtf_ipv6_db1_160_f0_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ingress_rtf_ipv6_db1_160_f0_table_value_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv6_db1_160_f0_table_value_t element);

/// API-s for table: ingress_rtf_ipv6_db1_160_f1_table

typedef enum
{
    NPL_INGRESS_RTF_IPV6_DB1_160_F1_TABLE_ACTION_WRITE = 0x0
} npl_ingress_rtf_ipv6_db1_160_f1_table_action_e;

struct npl_ingress_rtf_ipv6_db1_160_f1_table_key_t
{
    npl_ud_key_t ud_key;
    
    npl_ingress_rtf_ipv6_db1_160_f1_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector pack(void) const;
    void unpack(bit_vector bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ingress_rtf_ipv6_db1_160_f1_table_key_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv6_db1_160_f1_table_key_t element);

struct npl_ingress_rtf_ipv6_db1_160_f1_table_value_t
{
    npl_ingress_rtf_ipv6_db1_160_f1_table_action_e action;
    union npl_ingress_rtf_ipv6_db1_160_f1_table_payloads_t {
        npl_rtf_payload_t rtf_payload_f1;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ingress_rtf_ipv6_db1_160_f1_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_INGRESS_RTF_IPV6_DB1_160_F1_TABLE_ACTION_WRITE:
            {
                return "NPL_INGRESS_RTF_IPV6_DB1_160_F1_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ingress_rtf_ipv6_db1_160_f1_table_action_e");
        }
        return "";
    }
    npl_ingress_rtf_ipv6_db1_160_f1_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ingress_rtf_ipv6_db1_160_f1_table_value_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv6_db1_160_f1_table_value_t element);

/// API-s for table: ingress_rtf_ipv6_db1_320_f0_table

typedef enum
{
    NPL_INGRESS_RTF_IPV6_DB1_320_F0_TABLE_ACTION_WRITE = 0x0
} npl_ingress_rtf_ipv6_db1_320_f0_table_action_e;

struct npl_ingress_rtf_ipv6_db1_320_f0_table_key_t
{
    npl_ud_key_t ud_key;
    
    npl_ingress_rtf_ipv6_db1_320_f0_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector pack(void) const;
    void unpack(bit_vector bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ingress_rtf_ipv6_db1_320_f0_table_key_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv6_db1_320_f0_table_key_t element);

struct npl_ingress_rtf_ipv6_db1_320_f0_table_value_t
{
    npl_ingress_rtf_ipv6_db1_320_f0_table_action_e action;
    union npl_ingress_rtf_ipv6_db1_320_f0_table_payloads_t {
        npl_rtf_payload_t rtf_payload;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ingress_rtf_ipv6_db1_320_f0_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_INGRESS_RTF_IPV6_DB1_320_F0_TABLE_ACTION_WRITE:
            {
                return "NPL_INGRESS_RTF_IPV6_DB1_320_F0_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ingress_rtf_ipv6_db1_320_f0_table_action_e");
        }
        return "";
    }
    npl_ingress_rtf_ipv6_db1_320_f0_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ingress_rtf_ipv6_db1_320_f0_table_value_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv6_db1_320_f0_table_value_t element);

/// API-s for table: ingress_rtf_ipv6_db2_160_f0_table

typedef enum
{
    NPL_INGRESS_RTF_IPV6_DB2_160_F0_TABLE_ACTION_WRITE = 0x0
} npl_ingress_rtf_ipv6_db2_160_f0_table_action_e;

struct npl_ingress_rtf_ipv6_db2_160_f0_table_key_t
{
    npl_ud_key_t ud_key;
    
    npl_ingress_rtf_ipv6_db2_160_f0_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector pack(void) const;
    void unpack(bit_vector bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ingress_rtf_ipv6_db2_160_f0_table_key_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv6_db2_160_f0_table_key_t element);

struct npl_ingress_rtf_ipv6_db2_160_f0_table_value_t
{
    npl_ingress_rtf_ipv6_db2_160_f0_table_action_e action;
    union npl_ingress_rtf_ipv6_db2_160_f0_table_payloads_t {
        npl_rtf_payload_t rtf_payload;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ingress_rtf_ipv6_db2_160_f0_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_INGRESS_RTF_IPV6_DB2_160_F0_TABLE_ACTION_WRITE:
            {
                return "NPL_INGRESS_RTF_IPV6_DB2_160_F0_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ingress_rtf_ipv6_db2_160_f0_table_action_e");
        }
        return "";
    }
    npl_ingress_rtf_ipv6_db2_160_f0_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ingress_rtf_ipv6_db2_160_f0_table_value_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv6_db2_160_f0_table_value_t element);

/// API-s for table: ingress_rtf_ipv6_db2_160_f1_table

typedef enum
{
    NPL_INGRESS_RTF_IPV6_DB2_160_F1_TABLE_ACTION_WRITE = 0x0
} npl_ingress_rtf_ipv6_db2_160_f1_table_action_e;

struct npl_ingress_rtf_ipv6_db2_160_f1_table_key_t
{
    npl_ud_key_t ud_key;
    
    npl_ingress_rtf_ipv6_db2_160_f1_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector pack(void) const;
    void unpack(bit_vector bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ingress_rtf_ipv6_db2_160_f1_table_key_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv6_db2_160_f1_table_key_t element);

struct npl_ingress_rtf_ipv6_db2_160_f1_table_value_t
{
    npl_ingress_rtf_ipv6_db2_160_f1_table_action_e action;
    union npl_ingress_rtf_ipv6_db2_160_f1_table_payloads_t {
        npl_rtf_payload_t rtf_payload_f1;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ingress_rtf_ipv6_db2_160_f1_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_INGRESS_RTF_IPV6_DB2_160_F1_TABLE_ACTION_WRITE:
            {
                return "NPL_INGRESS_RTF_IPV6_DB2_160_F1_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ingress_rtf_ipv6_db2_160_f1_table_action_e");
        }
        return "";
    }
    npl_ingress_rtf_ipv6_db2_160_f1_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ingress_rtf_ipv6_db2_160_f1_table_value_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv6_db2_160_f1_table_value_t element);

/// API-s for table: ingress_rtf_ipv6_db2_320_f0_table

typedef enum
{
    NPL_INGRESS_RTF_IPV6_DB2_320_F0_TABLE_ACTION_WRITE = 0x0
} npl_ingress_rtf_ipv6_db2_320_f0_table_action_e;

struct npl_ingress_rtf_ipv6_db2_320_f0_table_key_t
{
    npl_ud_key_t ud_key;
    
    npl_ingress_rtf_ipv6_db2_320_f0_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector pack(void) const;
    void unpack(bit_vector bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ingress_rtf_ipv6_db2_320_f0_table_key_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv6_db2_320_f0_table_key_t element);

struct npl_ingress_rtf_ipv6_db2_320_f0_table_value_t
{
    npl_ingress_rtf_ipv6_db2_320_f0_table_action_e action;
    union npl_ingress_rtf_ipv6_db2_320_f0_table_payloads_t {
        npl_rtf_payload_t rtf_payload;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ingress_rtf_ipv6_db2_320_f0_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_INGRESS_RTF_IPV6_DB2_320_F0_TABLE_ACTION_WRITE:
            {
                return "NPL_INGRESS_RTF_IPV6_DB2_320_F0_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ingress_rtf_ipv6_db2_320_f0_table_action_e");
        }
        return "";
    }
    npl_ingress_rtf_ipv6_db2_320_f0_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ingress_rtf_ipv6_db2_320_f0_table_value_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv6_db2_320_f0_table_value_t element);

/// API-s for table: ingress_rtf_ipv6_db3_160_f0_table

typedef enum
{
    NPL_INGRESS_RTF_IPV6_DB3_160_F0_TABLE_ACTION_WRITE = 0x0
} npl_ingress_rtf_ipv6_db3_160_f0_table_action_e;

struct npl_ingress_rtf_ipv6_db3_160_f0_table_key_t
{
    npl_ud_key_t ud_key;
    
    npl_ingress_rtf_ipv6_db3_160_f0_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector pack(void) const;
    void unpack(bit_vector bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ingress_rtf_ipv6_db3_160_f0_table_key_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv6_db3_160_f0_table_key_t element);

struct npl_ingress_rtf_ipv6_db3_160_f0_table_value_t
{
    npl_ingress_rtf_ipv6_db3_160_f0_table_action_e action;
    union npl_ingress_rtf_ipv6_db3_160_f0_table_payloads_t {
        npl_rtf_payload_t rtf_payload;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ingress_rtf_ipv6_db3_160_f0_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_INGRESS_RTF_IPV6_DB3_160_F0_TABLE_ACTION_WRITE:
            {
                return "NPL_INGRESS_RTF_IPV6_DB3_160_F0_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ingress_rtf_ipv6_db3_160_f0_table_action_e");
        }
        return "";
    }
    npl_ingress_rtf_ipv6_db3_160_f0_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ingress_rtf_ipv6_db3_160_f0_table_value_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv6_db3_160_f0_table_value_t element);

/// API-s for table: ingress_rtf_ipv6_db3_160_f1_table

typedef enum
{
    NPL_INGRESS_RTF_IPV6_DB3_160_F1_TABLE_ACTION_WRITE = 0x0
} npl_ingress_rtf_ipv6_db3_160_f1_table_action_e;

struct npl_ingress_rtf_ipv6_db3_160_f1_table_key_t
{
    npl_ud_key_t ud_key;
    
    npl_ingress_rtf_ipv6_db3_160_f1_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector pack(void) const;
    void unpack(bit_vector bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ingress_rtf_ipv6_db3_160_f1_table_key_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv6_db3_160_f1_table_key_t element);

struct npl_ingress_rtf_ipv6_db3_160_f1_table_value_t
{
    npl_ingress_rtf_ipv6_db3_160_f1_table_action_e action;
    union npl_ingress_rtf_ipv6_db3_160_f1_table_payloads_t {
        npl_rtf_payload_t rtf_payload_f1;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ingress_rtf_ipv6_db3_160_f1_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_INGRESS_RTF_IPV6_DB3_160_F1_TABLE_ACTION_WRITE:
            {
                return "NPL_INGRESS_RTF_IPV6_DB3_160_F1_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ingress_rtf_ipv6_db3_160_f1_table_action_e");
        }
        return "";
    }
    npl_ingress_rtf_ipv6_db3_160_f1_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ingress_rtf_ipv6_db3_160_f1_table_value_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv6_db3_160_f1_table_value_t element);

/// API-s for table: ingress_rtf_ipv6_db3_320_f0_table

typedef enum
{
    NPL_INGRESS_RTF_IPV6_DB3_320_F0_TABLE_ACTION_WRITE = 0x0
} npl_ingress_rtf_ipv6_db3_320_f0_table_action_e;

struct npl_ingress_rtf_ipv6_db3_320_f0_table_key_t
{
    npl_ud_key_t ud_key;
    
    npl_ingress_rtf_ipv6_db3_320_f0_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector pack(void) const;
    void unpack(bit_vector bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ingress_rtf_ipv6_db3_320_f0_table_key_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv6_db3_320_f0_table_key_t element);

struct npl_ingress_rtf_ipv6_db3_320_f0_table_value_t
{
    npl_ingress_rtf_ipv6_db3_320_f0_table_action_e action;
    union npl_ingress_rtf_ipv6_db3_320_f0_table_payloads_t {
        npl_rtf_payload_t rtf_payload;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ingress_rtf_ipv6_db3_320_f0_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_INGRESS_RTF_IPV6_DB3_320_F0_TABLE_ACTION_WRITE:
            {
                return "NPL_INGRESS_RTF_IPV6_DB3_320_F0_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ingress_rtf_ipv6_db3_320_f0_table_action_e");
        }
        return "";
    }
    npl_ingress_rtf_ipv6_db3_320_f0_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ingress_rtf_ipv6_db3_320_f0_table_value_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv6_db3_320_f0_table_value_t element);

/// API-s for table: ingress_rtf_ipv6_db4_160_f0_table

typedef enum
{
    NPL_INGRESS_RTF_IPV6_DB4_160_F0_TABLE_ACTION_WRITE = 0x0
} npl_ingress_rtf_ipv6_db4_160_f0_table_action_e;

struct npl_ingress_rtf_ipv6_db4_160_f0_table_key_t
{
    npl_ud_key_t ud_key;
    
    npl_ingress_rtf_ipv6_db4_160_f0_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector pack(void) const;
    void unpack(bit_vector bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ingress_rtf_ipv6_db4_160_f0_table_key_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv6_db4_160_f0_table_key_t element);

struct npl_ingress_rtf_ipv6_db4_160_f0_table_value_t
{
    npl_ingress_rtf_ipv6_db4_160_f0_table_action_e action;
    union npl_ingress_rtf_ipv6_db4_160_f0_table_payloads_t {
        npl_rtf_payload_t rtf_payload;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ingress_rtf_ipv6_db4_160_f0_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_INGRESS_RTF_IPV6_DB4_160_F0_TABLE_ACTION_WRITE:
            {
                return "NPL_INGRESS_RTF_IPV6_DB4_160_F0_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ingress_rtf_ipv6_db4_160_f0_table_action_e");
        }
        return "";
    }
    npl_ingress_rtf_ipv6_db4_160_f0_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ingress_rtf_ipv6_db4_160_f0_table_value_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv6_db4_160_f0_table_value_t element);

/// API-s for table: ingress_rtf_ipv6_db4_160_f1_table

typedef enum
{
    NPL_INGRESS_RTF_IPV6_DB4_160_F1_TABLE_ACTION_WRITE = 0x0
} npl_ingress_rtf_ipv6_db4_160_f1_table_action_e;

struct npl_ingress_rtf_ipv6_db4_160_f1_table_key_t
{
    npl_ud_key_t ud_key;
    
    npl_ingress_rtf_ipv6_db4_160_f1_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector pack(void) const;
    void unpack(bit_vector bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ingress_rtf_ipv6_db4_160_f1_table_key_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv6_db4_160_f1_table_key_t element);

struct npl_ingress_rtf_ipv6_db4_160_f1_table_value_t
{
    npl_ingress_rtf_ipv6_db4_160_f1_table_action_e action;
    union npl_ingress_rtf_ipv6_db4_160_f1_table_payloads_t {
        npl_rtf_payload_t rtf_payload_f1;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ingress_rtf_ipv6_db4_160_f1_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_INGRESS_RTF_IPV6_DB4_160_F1_TABLE_ACTION_WRITE:
            {
                return "NPL_INGRESS_RTF_IPV6_DB4_160_F1_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ingress_rtf_ipv6_db4_160_f1_table_action_e");
        }
        return "";
    }
    npl_ingress_rtf_ipv6_db4_160_f1_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ingress_rtf_ipv6_db4_160_f1_table_value_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv6_db4_160_f1_table_value_t element);

/// API-s for table: ingress_rtf_ipv6_db4_320_f0_table

typedef enum
{
    NPL_INGRESS_RTF_IPV6_DB4_320_F0_TABLE_ACTION_WRITE = 0x0
} npl_ingress_rtf_ipv6_db4_320_f0_table_action_e;

struct npl_ingress_rtf_ipv6_db4_320_f0_table_key_t
{
    npl_ud_key_t ud_key;
    
    npl_ingress_rtf_ipv6_db4_320_f0_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector pack(void) const;
    void unpack(bit_vector bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ingress_rtf_ipv6_db4_320_f0_table_key_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv6_db4_320_f0_table_key_t element);

struct npl_ingress_rtf_ipv6_db4_320_f0_table_value_t
{
    npl_ingress_rtf_ipv6_db4_320_f0_table_action_e action;
    union npl_ingress_rtf_ipv6_db4_320_f0_table_payloads_t {
        npl_rtf_payload_t rtf_payload;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ingress_rtf_ipv6_db4_320_f0_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_INGRESS_RTF_IPV6_DB4_320_F0_TABLE_ACTION_WRITE:
            {
                return "NPL_INGRESS_RTF_IPV6_DB4_320_F0_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ingress_rtf_ipv6_db4_320_f0_table_action_e");
        }
        return "";
    }
    npl_ingress_rtf_ipv6_db4_320_f0_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ingress_rtf_ipv6_db4_320_f0_table_value_t element);
std::string to_short_string(struct npl_ingress_rtf_ipv6_db4_320_f0_table_value_t element);

/// API-s for table: inject_down_select_ene_static_table

typedef enum
{
    NPL_INJECT_DOWN_SELECT_ENE_STATIC_TABLE_ACTION_INJECT_DOWN_ENE = 0x0
} npl_inject_down_select_ene_static_table_action_e;

struct npl_inject_down_select_ene_static_table_inject_down_ene_payload_t
{
    npl_ene_macro_ids_e ene_macro_id;
    uint64_t dma_decap_header_type : 8;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_inject_down_select_ene_static_table_inject_down_ene_payload_t element);
std::string to_short_string(npl_inject_down_select_ene_static_table_inject_down_ene_payload_t element);

struct npl_inject_down_select_ene_static_table_key_t
{
    uint64_t dsp_is_dma : 1;
    npl_fwd_header_type_e fwd_header_type;
    npl_inject_down_encap_type_e inject_down_encap;
    uint64_t pkt_size_4lsb : 4;
    
    npl_inject_down_select_ene_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_inject_down_select_ene_static_table_key_t element);
std::string to_short_string(struct npl_inject_down_select_ene_static_table_key_t element);

struct npl_inject_down_select_ene_static_table_value_t
{
    npl_inject_down_select_ene_static_table_action_e action;
    union npl_inject_down_select_ene_static_table_payloads_t {
        npl_inject_down_select_ene_static_table_inject_down_ene_payload_t inject_down_ene;
    } payloads;
    std::string npl_action_enum_to_string(const npl_inject_down_select_ene_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_INJECT_DOWN_SELECT_ENE_STATIC_TABLE_ACTION_INJECT_DOWN_ENE:
            {
                return "NPL_INJECT_DOWN_SELECT_ENE_STATIC_TABLE_ACTION_INJECT_DOWN_ENE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_inject_down_select_ene_static_table_action_e");
        }
        return "";
    }
    npl_inject_down_select_ene_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_inject_down_select_ene_static_table_value_t element);
std::string to_short_string(struct npl_inject_down_select_ene_static_table_value_t element);

/// API-s for table: inject_down_tx_redirect_counter_table

typedef enum
{
    NPL_INJECT_DOWN_TX_REDIRECT_COUNTER_TABLE_ACTION_COUNTER_METER_FOUND = 0x0
} npl_inject_down_tx_redirect_counter_table_action_e;

struct npl_inject_down_tx_redirect_counter_table_counter_meter_found_payload_t
{
    npl_per_pif_trap_mode_e per_pif_trap_mode;
    npl_counter_ptr_t counter_ptr;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_inject_down_tx_redirect_counter_table_counter_meter_found_payload_t element);
std::string to_short_string(npl_inject_down_tx_redirect_counter_table_counter_meter_found_payload_t element);

struct npl_inject_down_tx_redirect_counter_table_key_t
{
    uint64_t tx_redirect_code : 8;
    
    npl_inject_down_tx_redirect_counter_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_inject_down_tx_redirect_counter_table_key_t element);
std::string to_short_string(struct npl_inject_down_tx_redirect_counter_table_key_t element);

struct npl_inject_down_tx_redirect_counter_table_value_t
{
    npl_inject_down_tx_redirect_counter_table_action_e action;
    union npl_inject_down_tx_redirect_counter_table_payloads_t {
        npl_inject_down_tx_redirect_counter_table_counter_meter_found_payload_t counter_meter_found;
    } payloads;
    std::string npl_action_enum_to_string(const npl_inject_down_tx_redirect_counter_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_INJECT_DOWN_TX_REDIRECT_COUNTER_TABLE_ACTION_COUNTER_METER_FOUND:
            {
                return "NPL_INJECT_DOWN_TX_REDIRECT_COUNTER_TABLE_ACTION_COUNTER_METER_FOUND(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_inject_down_tx_redirect_counter_table_action_e");
        }
        return "";
    }
    npl_inject_down_tx_redirect_counter_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_inject_down_tx_redirect_counter_table_value_t element);
std::string to_short_string(struct npl_inject_down_tx_redirect_counter_table_value_t element);

/// API-s for table: inject_mact_ldb_to_output_lr

typedef enum
{
    NPL_INJECT_MACT_LDB_TO_OUTPUT_LR_ACTION_WRITE = 0x0
} npl_inject_mact_ldb_to_output_lr_action_e;

struct npl_inject_mact_ldb_to_output_lr_key_t
{
    
    
    npl_inject_mact_ldb_to_output_lr_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_inject_mact_ldb_to_output_lr_key_t element);
std::string to_short_string(struct npl_inject_mact_ldb_to_output_lr_key_t element);

struct npl_inject_mact_ldb_to_output_lr_value_t
{
    npl_inject_mact_ldb_to_output_lr_action_e action;
    union npl_inject_mact_ldb_to_output_lr_payloads_t {
        uint64_t output_learn_record_mact_ldb : 4;
    } payloads;
    std::string npl_action_enum_to_string(const npl_inject_mact_ldb_to_output_lr_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_INJECT_MACT_LDB_TO_OUTPUT_LR_ACTION_WRITE:
            {
                return "NPL_INJECT_MACT_LDB_TO_OUTPUT_LR_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_inject_mact_ldb_to_output_lr_action_e");
        }
        return "";
    }
    npl_inject_mact_ldb_to_output_lr_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_inject_mact_ldb_to_output_lr_value_t element);
std::string to_short_string(struct npl_inject_mact_ldb_to_output_lr_value_t element);

/// API-s for table: inject_up_pif_ifg_init_data_table

typedef enum
{
    NPL_INJECT_UP_PIF_IFG_INIT_DATA_TABLE_ACTION_WRITE_INIT_DATA_FOR_PIF_IFG = 0x0
} npl_inject_up_pif_ifg_init_data_table_action_e;

struct npl_inject_up_pif_ifg_init_data_table_write_init_data_for_pif_ifg_payload_t
{
    npl_slice_and_source_if_t slice_and_source_if;
    npl_initial_pd_nw_rx_data_t init_data;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_inject_up_pif_ifg_init_data_table_write_init_data_for_pif_ifg_payload_t element);
std::string to_short_string(npl_inject_up_pif_ifg_init_data_table_write_init_data_for_pif_ifg_payload_t element);

struct npl_inject_up_pif_ifg_init_data_table_key_t
{
    uint64_t initial_slice_id : 3;
    npl_source_if_t source_if;
    
    npl_inject_up_pif_ifg_init_data_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_inject_up_pif_ifg_init_data_table_key_t element);
std::string to_short_string(struct npl_inject_up_pif_ifg_init_data_table_key_t element);

struct npl_inject_up_pif_ifg_init_data_table_value_t
{
    npl_inject_up_pif_ifg_init_data_table_action_e action;
    union npl_inject_up_pif_ifg_init_data_table_payloads_t {
        npl_inject_up_pif_ifg_init_data_table_write_init_data_for_pif_ifg_payload_t write_init_data_for_pif_ifg;
    } payloads;
    std::string npl_action_enum_to_string(const npl_inject_up_pif_ifg_init_data_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_INJECT_UP_PIF_IFG_INIT_DATA_TABLE_ACTION_WRITE_INIT_DATA_FOR_PIF_IFG:
            {
                return "NPL_INJECT_UP_PIF_IFG_INIT_DATA_TABLE_ACTION_WRITE_INIT_DATA_FOR_PIF_IFG(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_inject_up_pif_ifg_init_data_table_action_e");
        }
        return "";
    }
    npl_inject_up_pif_ifg_init_data_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_inject_up_pif_ifg_init_data_table_value_t element);
std::string to_short_string(struct npl_inject_up_pif_ifg_init_data_table_value_t element);

/// API-s for table: inject_up_ssp_init_data_table

typedef enum
{
    NPL_INJECT_UP_SSP_INIT_DATA_TABLE_ACTION_WRITE_INIT_DATA_FOR_SSP = 0x0
} npl_inject_up_ssp_init_data_table_action_e;

struct npl_inject_up_ssp_init_data_table_write_init_data_for_ssp_payload_t
{
    npl_initial_pd_nw_rx_data_t init_data;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_inject_up_ssp_init_data_table_write_init_data_for_ssp_payload_t element);
std::string to_short_string(npl_inject_up_ssp_init_data_table_write_init_data_for_ssp_payload_t element);

struct npl_inject_up_ssp_init_data_table_key_t
{
    uint64_t up_ssp : 12;
    
    npl_inject_up_ssp_init_data_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_inject_up_ssp_init_data_table_key_t element);
std::string to_short_string(struct npl_inject_up_ssp_init_data_table_key_t element);

struct npl_inject_up_ssp_init_data_table_value_t
{
    npl_inject_up_ssp_init_data_table_action_e action;
    union npl_inject_up_ssp_init_data_table_payloads_t {
        npl_inject_up_ssp_init_data_table_write_init_data_for_ssp_payload_t write_init_data_for_ssp;
    } payloads;
    std::string npl_action_enum_to_string(const npl_inject_up_ssp_init_data_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_INJECT_UP_SSP_INIT_DATA_TABLE_ACTION_WRITE_INIT_DATA_FOR_SSP:
            {
                return "NPL_INJECT_UP_SSP_INIT_DATA_TABLE_ACTION_WRITE_INIT_DATA_FOR_SSP(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_inject_up_ssp_init_data_table_action_e");
        }
        return "";
    }
    npl_inject_up_ssp_init_data_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_inject_up_ssp_init_data_table_value_t element);
std::string to_short_string(struct npl_inject_up_ssp_init_data_table_value_t element);

/// API-s for table: inner_tpid_table

typedef enum
{
    NPL_INNER_TPID_TABLE_ACTION_WRITE = 0x0
} npl_inner_tpid_table_action_e;

struct npl_inner_tpid_table_key_t
{
    uint64_t tpid_ptr : 4;
    
    npl_inner_tpid_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_inner_tpid_table_key_t element);
std::string to_short_string(struct npl_inner_tpid_table_key_t element);

struct npl_inner_tpid_table_value_t
{
    npl_inner_tpid_table_action_e action;
    union npl_inner_tpid_table_payloads_t {
        uint64_t tpid : 16;
    } payloads;
    std::string npl_action_enum_to_string(const npl_inner_tpid_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_INNER_TPID_TABLE_ACTION_WRITE:
            {
                return "NPL_INNER_TPID_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_inner_tpid_table_action_e");
        }
        return "";
    }
    npl_inner_tpid_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_inner_tpid_table_value_t element);
std::string to_short_string(struct npl_inner_tpid_table_value_t element);

/// API-s for table: ip_fwd_header_mapping_to_ethtype_static_table

typedef enum
{
    NPL_IP_FWD_HEADER_MAPPING_TO_ETHTYPE_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_ip_fwd_header_mapping_to_ethtype_static_table_action_e;

struct npl_ip_fwd_header_mapping_to_ethtype_static_table_key_t
{
    npl_fwd_header_type_e tx_npu_header_fwd_header_type;
    
    npl_ip_fwd_header_mapping_to_ethtype_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ip_fwd_header_mapping_to_ethtype_static_table_key_t element);
std::string to_short_string(struct npl_ip_fwd_header_mapping_to_ethtype_static_table_key_t element);

struct npl_ip_fwd_header_mapping_to_ethtype_static_table_value_t
{
    npl_ip_fwd_header_mapping_to_ethtype_static_table_action_e action;
    union npl_ip_fwd_header_mapping_to_ethtype_static_table_payloads_t {
        npl_local_tx_ip_mapping_t local_tx_ip_mapping;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ip_fwd_header_mapping_to_ethtype_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IP_FWD_HEADER_MAPPING_TO_ETHTYPE_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_IP_FWD_HEADER_MAPPING_TO_ETHTYPE_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ip_fwd_header_mapping_to_ethtype_static_table_action_e");
        }
        return "";
    }
    npl_ip_fwd_header_mapping_to_ethtype_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ip_fwd_header_mapping_to_ethtype_static_table_value_t element);
std::string to_short_string(struct npl_ip_fwd_header_mapping_to_ethtype_static_table_value_t element);

/// API-s for table: ip_ingress_cmp_mcid_static_table

typedef enum
{
    NPL_IP_INGRESS_CMP_MCID_STATIC_TABLE_ACTION_SET_VALUE = 0x0
} npl_ip_ingress_cmp_mcid_static_table_action_e;

struct npl_ip_ingress_cmp_mcid_static_table_set_value_payload_t
{
    uint64_t global_mcid_17_downto_16_is_zero : 1;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_ip_ingress_cmp_mcid_static_table_set_value_payload_t element);
std::string to_short_string(npl_ip_ingress_cmp_mcid_static_table_set_value_payload_t element);

struct npl_ip_ingress_cmp_mcid_static_table_key_t
{
    uint64_t global_mcid_17_downto_16 : 2;
    
    npl_ip_ingress_cmp_mcid_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ip_ingress_cmp_mcid_static_table_key_t element);
std::string to_short_string(struct npl_ip_ingress_cmp_mcid_static_table_key_t element);

struct npl_ip_ingress_cmp_mcid_static_table_value_t
{
    npl_ip_ingress_cmp_mcid_static_table_action_e action;
    union npl_ip_ingress_cmp_mcid_static_table_payloads_t {
        npl_ip_ingress_cmp_mcid_static_table_set_value_payload_t set_value;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ip_ingress_cmp_mcid_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IP_INGRESS_CMP_MCID_STATIC_TABLE_ACTION_SET_VALUE:
            {
                return "NPL_IP_INGRESS_CMP_MCID_STATIC_TABLE_ACTION_SET_VALUE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ip_ingress_cmp_mcid_static_table_action_e");
        }
        return "";
    }
    npl_ip_ingress_cmp_mcid_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ip_ingress_cmp_mcid_static_table_value_t element);
std::string to_short_string(struct npl_ip_ingress_cmp_mcid_static_table_value_t element);

/// API-s for table: ip_mc_local_inject_type_static_table

typedef enum
{
    NPL_IP_MC_LOCAL_INJECT_TYPE_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_ip_mc_local_inject_type_static_table_action_e;

struct npl_ip_mc_local_inject_type_static_table_key_t
{
    npl_protocol_type_e current_protocol;
    
    npl_ip_mc_local_inject_type_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ip_mc_local_inject_type_static_table_key_t element);
std::string to_short_string(struct npl_ip_mc_local_inject_type_static_table_key_t element);

struct npl_ip_mc_local_inject_type_static_table_value_t
{
    npl_ip_mc_local_inject_type_static_table_action_e action;
    union npl_ip_mc_local_inject_type_static_table_payloads_t {
        npl_inject_header_type_e pd_ene_encap_data_inject_header_type;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ip_mc_local_inject_type_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IP_MC_LOCAL_INJECT_TYPE_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_IP_MC_LOCAL_INJECT_TYPE_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ip_mc_local_inject_type_static_table_action_e");
        }
        return "";
    }
    npl_ip_mc_local_inject_type_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ip_mc_local_inject_type_static_table_value_t element);
std::string to_short_string(struct npl_ip_mc_local_inject_type_static_table_value_t element);

/// API-s for table: ip_mc_next_macro_static_table

typedef enum
{
    NPL_IP_MC_NEXT_MACRO_STATIC_TABLE_ACTION_SET_NPE_NEXT_MACRO = 0x0
} npl_ip_mc_next_macro_static_table_action_e;

struct npl_ip_mc_next_macro_static_table_set_npe_next_macro_payload_t
{
    uint64_t pl_inc : 2;
    uint64_t npe_macro_id : 8;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_ip_mc_next_macro_static_table_set_npe_next_macro_payload_t element);
std::string to_short_string(npl_ip_mc_next_macro_static_table_set_npe_next_macro_payload_t element);

struct npl_ip_mc_next_macro_static_table_key_t
{
    uint64_t same_l3_int : 1;
    npl_bool_e collapsed_mc;
    
    npl_ip_mc_next_macro_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ip_mc_next_macro_static_table_key_t element);
std::string to_short_string(struct npl_ip_mc_next_macro_static_table_key_t element);

struct npl_ip_mc_next_macro_static_table_value_t
{
    npl_ip_mc_next_macro_static_table_action_e action;
    union npl_ip_mc_next_macro_static_table_payloads_t {
        npl_ip_mc_next_macro_static_table_set_npe_next_macro_payload_t set_npe_next_macro;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ip_mc_next_macro_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IP_MC_NEXT_MACRO_STATIC_TABLE_ACTION_SET_NPE_NEXT_MACRO:
            {
                return "NPL_IP_MC_NEXT_MACRO_STATIC_TABLE_ACTION_SET_NPE_NEXT_MACRO(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ip_mc_next_macro_static_table_action_e");
        }
        return "";
    }
    npl_ip_mc_next_macro_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ip_mc_next_macro_static_table_value_t element);
std::string to_short_string(struct npl_ip_mc_next_macro_static_table_value_t element);

/// API-s for table: ip_meter_profile_mapping_table

typedef enum
{
    NPL_IP_METER_PROFILE_MAPPING_TABLE_ACTION_WRITE = 0x0
} npl_ip_meter_profile_mapping_table_action_e;

struct npl_ip_meter_profile_mapping_table_key_t
{
    uint64_t qos_id : 4;
    
    npl_ip_meter_profile_mapping_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ip_meter_profile_mapping_table_key_t element);
std::string to_short_string(struct npl_ip_meter_profile_mapping_table_key_t element);

struct npl_ip_meter_profile_mapping_table_value_t
{
    npl_ip_meter_profile_mapping_table_action_e action;
    union npl_ip_meter_profile_mapping_table_payloads_t {
        uint64_t slp_qos_id : 4;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ip_meter_profile_mapping_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IP_METER_PROFILE_MAPPING_TABLE_ACTION_WRITE:
            {
                return "NPL_IP_METER_PROFILE_MAPPING_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ip_meter_profile_mapping_table_action_e");
        }
        return "";
    }
    npl_ip_meter_profile_mapping_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ip_meter_profile_mapping_table_value_t element);
std::string to_short_string(struct npl_ip_meter_profile_mapping_table_value_t element);

/// API-s for table: ip_prefix_destination_table

typedef enum
{
    NPL_IP_PREFIX_DESTINATION_TABLE_ACTION_WRITE = 0x0
} npl_ip_prefix_destination_table_action_e;

struct npl_ip_prefix_destination_table_key_t
{
    uint64_t ip_prefix_ptr : 17;
    
    npl_ip_prefix_destination_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ip_prefix_destination_table_key_t element);
std::string to_short_string(struct npl_ip_prefix_destination_table_key_t element);

struct npl_ip_prefix_destination_table_value_t
{
    npl_ip_prefix_destination_table_action_e action;
    union npl_ip_prefix_destination_table_payloads_t {
        npl_destination_t prefix_destination;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ip_prefix_destination_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IP_PREFIX_DESTINATION_TABLE_ACTION_WRITE:
            {
                return "NPL_IP_PREFIX_DESTINATION_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ip_prefix_destination_table_action_e");
        }
        return "";
    }
    npl_ip_prefix_destination_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ip_prefix_destination_table_value_t element);
std::string to_short_string(struct npl_ip_prefix_destination_table_value_t element);

/// API-s for table: ip_relay_to_vni_table

typedef enum
{
    NPL_IP_RELAY_TO_VNI_TABLE_ACTION_WRITE = 0x0
} npl_ip_relay_to_vni_table_action_e;

struct npl_ip_relay_to_vni_table_key_t
{
    uint64_t overlay_nh : 10;
    npl_l3_relay_id_t l3_relay_id;
    
    npl_ip_relay_to_vni_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ip_relay_to_vni_table_key_t element);
std::string to_short_string(struct npl_ip_relay_to_vni_table_key_t element);

struct npl_ip_relay_to_vni_table_value_t
{
    npl_ip_relay_to_vni_table_action_e action;
    union npl_ip_relay_to_vni_table_payloads_t {
        npl_l3_vxlan_relay_encap_data_t l3_vxlan_relay_encap_data;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ip_relay_to_vni_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IP_RELAY_TO_VNI_TABLE_ACTION_WRITE:
            {
                return "NPL_IP_RELAY_TO_VNI_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ip_relay_to_vni_table_action_e");
        }
        return "";
    }
    npl_ip_relay_to_vni_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ip_relay_to_vni_table_value_t element);
std::string to_short_string(struct npl_ip_relay_to_vni_table_value_t element);

/// API-s for table: ip_rx_global_counter_table

typedef enum
{
    NPL_IP_RX_GLOBAL_COUNTER_TABLE_ACTION_WRITE = 0x0
} npl_ip_rx_global_counter_table_action_e;

struct npl_ip_rx_global_counter_table_key_t
{
    
    
    npl_ip_rx_global_counter_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ip_rx_global_counter_table_key_t element);
std::string to_short_string(struct npl_ip_rx_global_counter_table_key_t element);

struct npl_ip_rx_global_counter_table_value_t
{
    npl_ip_rx_global_counter_table_action_e action;
    union npl_ip_rx_global_counter_table_payloads_t {
        npl_ip_rx_global_counter_t global_counter;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ip_rx_global_counter_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IP_RX_GLOBAL_COUNTER_TABLE_ACTION_WRITE:
            {
                return "NPL_IP_RX_GLOBAL_COUNTER_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ip_rx_global_counter_table_action_e");
        }
        return "";
    }
    npl_ip_rx_global_counter_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ip_rx_global_counter_table_value_t element);
std::string to_short_string(struct npl_ip_rx_global_counter_table_value_t element);

/// API-s for table: ip_ver_mc_static_table

typedef enum
{
    NPL_IP_VER_MC_STATIC_TABLE_ACTION_SET_VALUE = 0x0
} npl_ip_ver_mc_static_table_action_e;

struct npl_ip_ver_mc_static_table_set_value_payload_t
{
    uint64_t v4_offset_zero : 1;
    npl_ip_ver_mc_t ip_ver_mc;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_ip_ver_mc_static_table_set_value_payload_t element);
std::string to_short_string(npl_ip_ver_mc_static_table_set_value_payload_t element);

struct npl_ip_ver_mc_static_table_key_t
{
    uint64_t is_v6 : 1;
    uint64_t v6_sip_127_120 : 8;
    uint64_t v4_sip_31_28 : 4;
    uint64_t v4_frag_offset : 13;
    
    npl_ip_ver_mc_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ip_ver_mc_static_table_key_t element);
std::string to_short_string(struct npl_ip_ver_mc_static_table_key_t element);

struct npl_ip_ver_mc_static_table_value_t
{
    npl_ip_ver_mc_static_table_action_e action;
    union npl_ip_ver_mc_static_table_payloads_t {
        npl_ip_ver_mc_static_table_set_value_payload_t set_value;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ip_ver_mc_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IP_VER_MC_STATIC_TABLE_ACTION_SET_VALUE:
            {
                return "NPL_IP_VER_MC_STATIC_TABLE_ACTION_SET_VALUE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ip_ver_mc_static_table_action_e");
        }
        return "";
    }
    npl_ip_ver_mc_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ip_ver_mc_static_table_value_t element);
std::string to_short_string(struct npl_ip_ver_mc_static_table_value_t element);

/// API-s for table: ipv4_acl_map_protocol_type_to_protocol_number_table

typedef enum
{
    NPL_IPV4_ACL_MAP_PROTOCOL_TYPE_TO_PROTOCOL_NUMBER_TABLE_ACTION_UPDATE = 0x0
} npl_ipv4_acl_map_protocol_type_to_protocol_number_table_action_e;

struct npl_ipv4_acl_map_protocol_type_to_protocol_number_table_update_payload_t
{
    uint64_t dummy_bits : 5;
    uint64_t is_valid : 1;
    uint64_t acl_l4_protocol : 2;
    uint64_t protocol_type : 8;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_ipv4_acl_map_protocol_type_to_protocol_number_table_update_payload_t element);
std::string to_short_string(npl_ipv4_acl_map_protocol_type_to_protocol_number_table_update_payload_t element);

struct npl_ipv4_acl_map_protocol_type_to_protocol_number_table_key_t
{
    uint64_t protocol : 8;
    
    npl_ipv4_acl_map_protocol_type_to_protocol_number_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ipv4_acl_map_protocol_type_to_protocol_number_table_key_t element);
std::string to_short_string(struct npl_ipv4_acl_map_protocol_type_to_protocol_number_table_key_t element);

struct npl_ipv4_acl_map_protocol_type_to_protocol_number_table_value_t
{
    npl_ipv4_acl_map_protocol_type_to_protocol_number_table_action_e action;
    union npl_ipv4_acl_map_protocol_type_to_protocol_number_table_payloads_t {
        npl_ipv4_acl_map_protocol_type_to_protocol_number_table_update_payload_t update;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ipv4_acl_map_protocol_type_to_protocol_number_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IPV4_ACL_MAP_PROTOCOL_TYPE_TO_PROTOCOL_NUMBER_TABLE_ACTION_UPDATE:
            {
                return "NPL_IPV4_ACL_MAP_PROTOCOL_TYPE_TO_PROTOCOL_NUMBER_TABLE_ACTION_UPDATE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ipv4_acl_map_protocol_type_to_protocol_number_table_action_e");
        }
        return "";
    }
    npl_ipv4_acl_map_protocol_type_to_protocol_number_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ipv4_acl_map_protocol_type_to_protocol_number_table_value_t element);
std::string to_short_string(struct npl_ipv4_acl_map_protocol_type_to_protocol_number_table_value_t element);

/// API-s for table: ipv4_acl_sport_static_table

typedef enum
{
    NPL_IPV4_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_MAPPED_PROTO_TYPE = 0x0,
    NPL_IPV4_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_PACKET = 0x1,
    NPL_IPV4_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_PACKET_PROTO_TYPE = 0x2
} npl_ipv4_acl_sport_static_table_action_e;

struct npl_ipv4_acl_sport_static_table_key_t
{
    uint64_t acl_is_valid : 1;
    uint64_t acl_l4_protocol : 2;
    
    npl_ipv4_acl_sport_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ipv4_acl_sport_static_table_key_t element);
std::string to_short_string(struct npl_ipv4_acl_sport_static_table_key_t element);

struct npl_ipv4_acl_sport_static_table_value_t
{
    npl_ipv4_acl_sport_static_table_action_e action;
    std::string npl_action_enum_to_string(const npl_ipv4_acl_sport_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IPV4_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_MAPPED_PROTO_TYPE:
            {
                return "NPL_IPV4_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_MAPPED_PROTO_TYPE(0x0)";
                break;
            }
            case NPL_IPV4_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_PACKET:
            {
                return "NPL_IPV4_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_PACKET(0x1)";
                break;
            }
            case NPL_IPV4_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_PACKET_PROTO_TYPE:
            {
                return "NPL_IPV4_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_PACKET_PROTO_TYPE(0x2)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ipv4_acl_sport_static_table_action_e");
        }
        return "";
    }
    npl_ipv4_acl_sport_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ipv4_acl_sport_static_table_value_t element);
std::string to_short_string(struct npl_ipv4_acl_sport_static_table_value_t element);

/// API-s for table: ipv4_ip_tunnel_termination_dip_index_tt0_table

typedef enum
{
    NPL_IPV4_IP_TUNNEL_TERMINATION_DIP_INDEX_TT0_TABLE_ACTION_WRITE = 0x0
} npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_action_e;

struct npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_key_t
{
    npl_l3_relay_id_t l3_relay_id;
    uint64_t my_dip_index : 6;
    npl_tunnel_type_e tunnel_type;
    
    npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_key_t element);
std::string to_short_string(struct npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_key_t element);

struct npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_value_t
{
    npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_action_e action;
    union npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_payloads_t {
        npl_l3_lp_attributes_t term_tt0_attributes;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IPV4_IP_TUNNEL_TERMINATION_DIP_INDEX_TT0_TABLE_ACTION_WRITE:
            {
                return "NPL_IPV4_IP_TUNNEL_TERMINATION_DIP_INDEX_TT0_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_action_e");
        }
        return "";
    }
    npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_value_t element);
std::string to_short_string(struct npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_value_t element);

/// API-s for table: ipv4_ip_tunnel_termination_sip_dip_index_tt0_table

typedef enum
{
    NPL_IPV4_IP_TUNNEL_TERMINATION_SIP_DIP_INDEX_TT0_TABLE_ACTION_WRITE = 0x0
} npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_action_e;

struct npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_key_t
{
    npl_l3_relay_id_t l3_relay_id;
    uint64_t sip : 32;
    uint64_t my_dip_index : 6;
    npl_tunnel_type_e tunnel_type;
    
    npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_key_t element);
std::string to_short_string(struct npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_key_t element);

struct npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_value_t
{
    npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_action_e action;
    union npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_payloads_t {
        npl_l3_lp_attributes_t term_tt0_attributes;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IPV4_IP_TUNNEL_TERMINATION_SIP_DIP_INDEX_TT0_TABLE_ACTION_WRITE:
            {
                return "NPL_IPV4_IP_TUNNEL_TERMINATION_SIP_DIP_INDEX_TT0_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_action_e");
        }
        return "";
    }
    npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_value_t element);
std::string to_short_string(struct npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_value_t element);

/// API-s for table: ipv4_ip_tunnel_termination_sip_dip_index_tt1_table

typedef enum
{
    NPL_IPV4_IP_TUNNEL_TERMINATION_SIP_DIP_INDEX_TT1_TABLE_ACTION_WRITE = 0x0
} npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_action_e;

struct npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_key_t
{
    npl_l3_relay_id_t l3_relay_id;
    uint64_t sip : 32;
    uint64_t my_dip_index : 6;
    npl_tunnel_type_e tunnel_type;
    
    npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_key_t element);
std::string to_short_string(struct npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_key_t element);

struct npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_value_t
{
    npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_action_e action;
    union npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_payloads_t {
        npl_l3_lp_attributes_t term_tt1_attributes;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IPV4_IP_TUNNEL_TERMINATION_SIP_DIP_INDEX_TT1_TABLE_ACTION_WRITE:
            {
                return "NPL_IPV4_IP_TUNNEL_TERMINATION_SIP_DIP_INDEX_TT1_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_action_e");
        }
        return "";
    }
    npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_value_t element);
std::string to_short_string(struct npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_value_t element);

/// API-s for table: ipv4_lpm_table

typedef enum
{
    NPL_IPV4_LPM_TABLE_ACTION_WRITE = 0x0
} npl_ipv4_lpm_table_action_e;

struct npl_ipv4_lpm_table_key_t
{
    npl_l3_relay_id_t l3_relay_id;
    uint64_t ipv4_ip_address_address : 32;
    
    npl_ipv4_lpm_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ipv4_lpm_table_key_t element);
std::string to_short_string(struct npl_ipv4_lpm_table_key_t element);

struct npl_ipv4_lpm_table_value_t
{
    npl_ipv4_lpm_table_action_e action;
    union npl_ipv4_lpm_table_payloads_t {
        npl_lpm_payload_t lpm_payload;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ipv4_lpm_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IPV4_LPM_TABLE_ACTION_WRITE:
            {
                return "NPL_IPV4_LPM_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ipv4_lpm_table_action_e");
        }
        return "";
    }
    npl_ipv4_lpm_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ipv4_lpm_table_value_t element);
std::string to_short_string(struct npl_ipv4_lpm_table_value_t element);

/// API-s for table: ipv4_lpts_table

typedef enum
{
    NPL_IPV4_LPTS_TABLE_ACTION_LPTS_FIRST_LOOKUP_RESULT = 0x0
} npl_ipv4_lpts_table_action_e;

struct npl_ipv4_lpts_table_lpts_first_lookup_result_payload_t
{
    npl_lpts_tcam_first_result_encap_data_msb_t lpts_first_result_encap_data_msb;
    npl_punt_encap_data_lsb_t punt_encap_data_lsb;
    npl_lpts_cntr_and_lookup_index_t lpts_cntr_and_second_lookup_index;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_ipv4_lpts_table_lpts_first_lookup_result_payload_t element);
std::string to_short_string(npl_ipv4_lpts_table_lpts_first_lookup_result_payload_t element);

struct npl_ipv4_lpts_table_key_t
{
    uint64_t fragmented : 1;
    uint64_t is_mc : 1;
    uint64_t app_id : 4;
    uint64_t established : 1;
    uint64_t ttl_255 : 1;
    npl_lpts_object_groups_t og_codes;
    uint64_t l4_protocol : 8;
    npl_l4_ports_header_t l4_ports;
    npl_l3_relay_id_t l3_relay_id;
    uint64_t v4_frag : 14;
    uint64_t ip_length : 14;
    uint64_t sip : 32;
    
    npl_ipv4_lpts_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ipv4_lpts_table_key_t element);
std::string to_short_string(struct npl_ipv4_lpts_table_key_t element);

struct npl_ipv4_lpts_table_value_t
{
    npl_ipv4_lpts_table_action_e action;
    union npl_ipv4_lpts_table_payloads_t {
        npl_ipv4_lpts_table_lpts_first_lookup_result_payload_t lpts_first_lookup_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ipv4_lpts_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IPV4_LPTS_TABLE_ACTION_LPTS_FIRST_LOOKUP_RESULT:
            {
                return "NPL_IPV4_LPTS_TABLE_ACTION_LPTS_FIRST_LOOKUP_RESULT(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ipv4_lpts_table_action_e");
        }
        return "";
    }
    npl_ipv4_lpts_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ipv4_lpts_table_value_t element);
std::string to_short_string(struct npl_ipv4_lpts_table_value_t element);

/// API-s for table: ipv4_og_pcl_em_table

typedef enum
{
    NPL_IPV4_OG_PCL_EM_TABLE_ACTION_WRITE = 0x0
} npl_ipv4_og_pcl_em_table_action_e;

struct npl_ipv4_og_pcl_em_table_key_t
{
    npl_og_pcl_id_t pcl_id;
    uint64_t ip_address_31_20 : 12;
    uint64_t ip_address_19_0 : 20;
    
    npl_ipv4_og_pcl_em_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ipv4_og_pcl_em_table_key_t element);
std::string to_short_string(struct npl_ipv4_og_pcl_em_table_key_t element);

struct npl_ipv4_og_pcl_em_table_value_t
{
    npl_ipv4_og_pcl_em_table_action_e action;
    union npl_ipv4_og_pcl_em_table_payloads_t {
        npl_og_em_result_t og_em_lookup_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ipv4_og_pcl_em_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IPV4_OG_PCL_EM_TABLE_ACTION_WRITE:
            {
                return "NPL_IPV4_OG_PCL_EM_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ipv4_og_pcl_em_table_action_e");
        }
        return "";
    }
    npl_ipv4_og_pcl_em_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ipv4_og_pcl_em_table_value_t element);
std::string to_short_string(struct npl_ipv4_og_pcl_em_table_value_t element);

/// API-s for table: ipv4_og_pcl_lpm_table

typedef enum
{
    NPL_IPV4_OG_PCL_LPM_TABLE_ACTION_WRITE = 0x0
} npl_ipv4_og_pcl_lpm_table_action_e;

struct npl_ipv4_og_pcl_lpm_table_key_t
{
    npl_og_pcl_id_t pcl_id;
    uint64_t ip_address : 32;
    
    npl_ipv4_og_pcl_lpm_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ipv4_og_pcl_lpm_table_key_t element);
std::string to_short_string(struct npl_ipv4_og_pcl_lpm_table_key_t element);

struct npl_ipv4_og_pcl_lpm_table_value_t
{
    npl_ipv4_og_pcl_lpm_table_action_e action;
    union npl_ipv4_og_pcl_lpm_table_payloads_t {
        npl_og_lpm_compression_code_t lpm_code;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ipv4_og_pcl_lpm_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IPV4_OG_PCL_LPM_TABLE_ACTION_WRITE:
            {
                return "NPL_IPV4_OG_PCL_LPM_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ipv4_og_pcl_lpm_table_action_e");
        }
        return "";
    }
    npl_ipv4_og_pcl_lpm_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ipv4_og_pcl_lpm_table_value_t element);
std::string to_short_string(struct npl_ipv4_og_pcl_lpm_table_value_t element);

/// API-s for table: ipv4_rtf_conf_set_mapping_table

typedef enum
{
    NPL_IPV4_RTF_CONF_SET_MAPPING_TABLE_ACTION_WRITE = 0x0
} npl_ipv4_rtf_conf_set_mapping_table_action_e;

struct npl_ipv4_rtf_conf_set_mapping_table_key_t
{
    npl_lp_rtf_conf_set_t lp_rtf_conf_set;
    npl_rtf_step_t rtf_step;
    
    npl_ipv4_rtf_conf_set_mapping_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ipv4_rtf_conf_set_mapping_table_key_t element);
std::string to_short_string(struct npl_ipv4_rtf_conf_set_mapping_table_key_t element);

struct npl_ipv4_rtf_conf_set_mapping_table_value_t
{
    npl_ipv4_rtf_conf_set_mapping_table_action_e action;
    union npl_ipv4_rtf_conf_set_mapping_table_payloads_t {
        npl_ip_rtf_iteration_properties_t ipv4_rtf_iteration_prop;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ipv4_rtf_conf_set_mapping_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IPV4_RTF_CONF_SET_MAPPING_TABLE_ACTION_WRITE:
            {
                return "NPL_IPV4_RTF_CONF_SET_MAPPING_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ipv4_rtf_conf_set_mapping_table_action_e");
        }
        return "";
    }
    npl_ipv4_rtf_conf_set_mapping_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ipv4_rtf_conf_set_mapping_table_value_t element);
std::string to_short_string(struct npl_ipv4_rtf_conf_set_mapping_table_value_t element);

/// API-s for table: ipv4_vrf_dip_em_table

typedef enum
{
    NPL_IPV4_VRF_DIP_EM_TABLE_ACTION_WRITE = 0x0
} npl_ipv4_vrf_dip_em_table_action_e;

struct npl_ipv4_vrf_dip_em_table_key_t
{
    npl_l3_relay_id_t l3_relay_id;
    uint64_t ip_address_31_20 : 12;
    uint64_t ip_address_19_0 : 20;
    
    npl_ipv4_vrf_dip_em_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ipv4_vrf_dip_em_table_key_t element);
std::string to_short_string(struct npl_ipv4_vrf_dip_em_table_key_t element);

struct npl_ipv4_vrf_dip_em_table_value_t
{
    npl_ipv4_vrf_dip_em_table_action_e action;
    union npl_ipv4_vrf_dip_em_table_payloads_t {
        npl_ip_em_result_t em_lookup_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ipv4_vrf_dip_em_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IPV4_VRF_DIP_EM_TABLE_ACTION_WRITE:
            {
                return "NPL_IPV4_VRF_DIP_EM_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ipv4_vrf_dip_em_table_action_e");
        }
        return "";
    }
    npl_ipv4_vrf_dip_em_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ipv4_vrf_dip_em_table_value_t element);
std::string to_short_string(struct npl_ipv4_vrf_dip_em_table_value_t element);

/// API-s for table: ipv4_vrf_s_g_table

typedef enum
{
    NPL_IPV4_VRF_S_G_TABLE_ACTION_WRITE = 0x0
} npl_ipv4_vrf_s_g_table_action_e;

struct npl_ipv4_vrf_s_g_table_key_t
{
    npl_l3_relay_id_t l3_relay_id;
    uint64_t dip_19_0_ : 20;
    uint64_t sip : 32;
    uint64_t dip_27_20_ : 8;
    
    npl_ipv4_vrf_s_g_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ipv4_vrf_s_g_table_key_t element);
std::string to_short_string(struct npl_ipv4_vrf_s_g_table_key_t element);

struct npl_ipv4_vrf_s_g_table_value_t
{
    npl_ipv4_vrf_s_g_table_action_e action;
    union npl_ipv4_vrf_s_g_table_payloads_t {
        npl_ip_mc_result_em_payload_t vrf_s_g_hw_ip_mc_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ipv4_vrf_s_g_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IPV4_VRF_S_G_TABLE_ACTION_WRITE:
            {
                return "NPL_IPV4_VRF_S_G_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ipv4_vrf_s_g_table_action_e");
        }
        return "";
    }
    npl_ipv4_vrf_s_g_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ipv4_vrf_s_g_table_value_t element);
std::string to_short_string(struct npl_ipv4_vrf_s_g_table_value_t element);

/// API-s for table: ipv6_acl_sport_static_table

typedef enum
{
    NPL_IPV6_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_MAPPED_PROTO_TYPE = 0x0,
    NPL_IPV6_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_PACKET = 0x1,
    NPL_IPV6_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_PACKET_PROTO_TYPE = 0x2
} npl_ipv6_acl_sport_static_table_action_e;

struct npl_ipv6_acl_sport_static_table_key_t
{
    uint64_t acl_is_valid : 1;
    uint64_t acl_l4_protocol : 2;
    
    npl_ipv6_acl_sport_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ipv6_acl_sport_static_table_key_t element);
std::string to_short_string(struct npl_ipv6_acl_sport_static_table_key_t element);

struct npl_ipv6_acl_sport_static_table_value_t
{
    npl_ipv6_acl_sport_static_table_action_e action;
    std::string npl_action_enum_to_string(const npl_ipv6_acl_sport_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IPV6_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_MAPPED_PROTO_TYPE:
            {
                return "NPL_IPV6_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_MAPPED_PROTO_TYPE(0x0)";
                break;
            }
            case NPL_IPV6_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_PACKET:
            {
                return "NPL_IPV6_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_PACKET(0x1)";
                break;
            }
            case NPL_IPV6_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_PACKET_PROTO_TYPE:
            {
                return "NPL_IPV6_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_PACKET_PROTO_TYPE(0x2)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ipv6_acl_sport_static_table_action_e");
        }
        return "";
    }
    npl_ipv6_acl_sport_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ipv6_acl_sport_static_table_value_t element);
std::string to_short_string(struct npl_ipv6_acl_sport_static_table_value_t element);

/// API-s for table: ipv6_first_fragment_static_table

typedef enum
{
    NPL_IPV6_FIRST_FRAGMENT_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_ipv6_first_fragment_static_table_action_e;

struct npl_ipv6_first_fragment_static_table_key_t
{
    uint64_t acl_on_outer : 1;
    uint64_t acl_changed_destination : 3;
    uint64_t saved_not_first_fragment : 1;
    uint64_t packet_not_first_fragment : 1;
    
    npl_ipv6_first_fragment_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ipv6_first_fragment_static_table_key_t element);
std::string to_short_string(struct npl_ipv6_first_fragment_static_table_key_t element);

struct npl_ipv6_first_fragment_static_table_value_t
{
    npl_ipv6_first_fragment_static_table_action_e action;
    union npl_ipv6_first_fragment_static_table_payloads_t {
        npl_bool_t ip_first_fragment;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ipv6_first_fragment_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IPV6_FIRST_FRAGMENT_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_IPV6_FIRST_FRAGMENT_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ipv6_first_fragment_static_table_action_e");
        }
        return "";
    }
    npl_ipv6_first_fragment_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ipv6_first_fragment_static_table_value_t element);
std::string to_short_string(struct npl_ipv6_first_fragment_static_table_value_t element);

/// API-s for table: ipv6_lpm_table

typedef enum
{
    NPL_IPV6_LPM_TABLE_ACTION_WRITE = 0x0
} npl_ipv6_lpm_table_action_e;

struct npl_ipv6_lpm_table_key_t
{
    npl_l3_relay_id_t l3_relay_id;
    uint64_t ipv6_ip_address_address[2];
    
    npl_ipv6_lpm_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ipv6_lpm_table_key_t element);
std::string to_short_string(struct npl_ipv6_lpm_table_key_t element);

struct npl_ipv6_lpm_table_value_t
{
    npl_ipv6_lpm_table_action_e action;
    union npl_ipv6_lpm_table_payloads_t {
        npl_lpm_payload_t lpm_payload;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ipv6_lpm_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IPV6_LPM_TABLE_ACTION_WRITE:
            {
                return "NPL_IPV6_LPM_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ipv6_lpm_table_action_e");
        }
        return "";
    }
    npl_ipv6_lpm_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ipv6_lpm_table_value_t element);
std::string to_short_string(struct npl_ipv6_lpm_table_value_t element);

/// API-s for table: ipv6_lpts_table

typedef enum
{
    NPL_IPV6_LPTS_TABLE_ACTION_LPTS_FIRST_LOOKUP_RESULT = 0x0
} npl_ipv6_lpts_table_action_e;

struct npl_ipv6_lpts_table_lpts_first_lookup_result_payload_t
{
    npl_lpts_tcam_first_result_encap_data_msb_t lpts_first_result_encap_data_msb;
    npl_punt_encap_data_lsb_t punt_encap_data_lsb;
    npl_lpts_cntr_and_lookup_index_t lpts_cntr_and_second_lookup_index;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_ipv6_lpts_table_lpts_first_lookup_result_payload_t element);
std::string to_short_string(npl_ipv6_lpts_table_lpts_first_lookup_result_payload_t element);

struct npl_ipv6_lpts_table_key_t
{
    uint64_t src_port : 16;
    uint64_t sip[2];
    npl_l3_relay_id_t l3_relay_id;
    uint64_t is_mc : 1;
    uint64_t app_id : 4;
    uint64_t established : 1;
    uint64_t ttl_255 : 1;
    npl_lpts_object_groups_t og_codes;
    uint64_t l4_protocol : 8;
    uint64_t dst_port : 16;
    uint64_t ip_length : 16;
    uint64_t pad : 64;
    
    npl_ipv6_lpts_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector384_t pack(void) const;
    void unpack(bit_vector384_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ipv6_lpts_table_key_t element);
std::string to_short_string(struct npl_ipv6_lpts_table_key_t element);

struct npl_ipv6_lpts_table_value_t
{
    npl_ipv6_lpts_table_action_e action;
    union npl_ipv6_lpts_table_payloads_t {
        npl_ipv6_lpts_table_lpts_first_lookup_result_payload_t lpts_first_lookup_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ipv6_lpts_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IPV6_LPTS_TABLE_ACTION_LPTS_FIRST_LOOKUP_RESULT:
            {
                return "NPL_IPV6_LPTS_TABLE_ACTION_LPTS_FIRST_LOOKUP_RESULT(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ipv6_lpts_table_action_e");
        }
        return "";
    }
    npl_ipv6_lpts_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ipv6_lpts_table_value_t element);
std::string to_short_string(struct npl_ipv6_lpts_table_value_t element);

/// API-s for table: ipv6_mc_select_qos_id

typedef enum
{
    NPL_IPV6_MC_SELECT_QOS_ID_ACTION_USE_QOS_ID_FROM_L2_LP_ATTR = 0x0,
    NPL_IPV6_MC_SELECT_QOS_ID_ACTION_USE_QOS_ID_FROM_L3_LAYER_ATTR = 0x1
} npl_ipv6_mc_select_qos_id_action_e;

struct npl_ipv6_mc_select_qos_id_key_t
{
    uint64_t mc_termination_hit : 1;
    
    npl_ipv6_mc_select_qos_id_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ipv6_mc_select_qos_id_key_t element);
std::string to_short_string(struct npl_ipv6_mc_select_qos_id_key_t element);

struct npl_ipv6_mc_select_qos_id_value_t
{
    npl_ipv6_mc_select_qos_id_action_e action;
    std::string npl_action_enum_to_string(const npl_ipv6_mc_select_qos_id_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IPV6_MC_SELECT_QOS_ID_ACTION_USE_QOS_ID_FROM_L2_LP_ATTR:
            {
                return "NPL_IPV6_MC_SELECT_QOS_ID_ACTION_USE_QOS_ID_FROM_L2_LP_ATTR(0x0)";
                break;
            }
            case NPL_IPV6_MC_SELECT_QOS_ID_ACTION_USE_QOS_ID_FROM_L3_LAYER_ATTR:
            {
                return "NPL_IPV6_MC_SELECT_QOS_ID_ACTION_USE_QOS_ID_FROM_L3_LAYER_ATTR(0x1)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ipv6_mc_select_qos_id_action_e");
        }
        return "";
    }
    npl_ipv6_mc_select_qos_id_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ipv6_mc_select_qos_id_value_t element);
std::string to_short_string(struct npl_ipv6_mc_select_qos_id_value_t element);

/// API-s for table: ipv6_og_pcl_em_table

typedef enum
{
    NPL_IPV6_OG_PCL_EM_TABLE_ACTION_WRITE = 0x0
} npl_ipv6_og_pcl_em_table_action_e;

struct npl_ipv6_og_pcl_em_table_key_t
{
    npl_og_pcl_id_t pcl_id;
    uint64_t ip_address[2];
    
    npl_ipv6_og_pcl_em_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ipv6_og_pcl_em_table_key_t element);
std::string to_short_string(struct npl_ipv6_og_pcl_em_table_key_t element);

struct npl_ipv6_og_pcl_em_table_value_t
{
    npl_ipv6_og_pcl_em_table_action_e action;
    union npl_ipv6_og_pcl_em_table_payloads_t {
        npl_og_em_result_t og_em_lookup_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ipv6_og_pcl_em_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IPV6_OG_PCL_EM_TABLE_ACTION_WRITE:
            {
                return "NPL_IPV6_OG_PCL_EM_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ipv6_og_pcl_em_table_action_e");
        }
        return "";
    }
    npl_ipv6_og_pcl_em_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ipv6_og_pcl_em_table_value_t element);
std::string to_short_string(struct npl_ipv6_og_pcl_em_table_value_t element);

/// API-s for table: ipv6_og_pcl_lpm_table

typedef enum
{
    NPL_IPV6_OG_PCL_LPM_TABLE_ACTION_WRITE = 0x0
} npl_ipv6_og_pcl_lpm_table_action_e;

struct npl_ipv6_og_pcl_lpm_table_key_t
{
    npl_og_pcl_id_t pcl_id;
    uint64_t ip_address[2];
    
    npl_ipv6_og_pcl_lpm_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ipv6_og_pcl_lpm_table_key_t element);
std::string to_short_string(struct npl_ipv6_og_pcl_lpm_table_key_t element);

struct npl_ipv6_og_pcl_lpm_table_value_t
{
    npl_ipv6_og_pcl_lpm_table_action_e action;
    union npl_ipv6_og_pcl_lpm_table_payloads_t {
        npl_og_lpm_compression_code_t lpm_code;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ipv6_og_pcl_lpm_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IPV6_OG_PCL_LPM_TABLE_ACTION_WRITE:
            {
                return "NPL_IPV6_OG_PCL_LPM_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ipv6_og_pcl_lpm_table_action_e");
        }
        return "";
    }
    npl_ipv6_og_pcl_lpm_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ipv6_og_pcl_lpm_table_value_t element);
std::string to_short_string(struct npl_ipv6_og_pcl_lpm_table_value_t element);

/// API-s for table: ipv6_rtf_conf_set_mapping_table

typedef enum
{
    NPL_IPV6_RTF_CONF_SET_MAPPING_TABLE_ACTION_WRITE = 0x0
} npl_ipv6_rtf_conf_set_mapping_table_action_e;

struct npl_ipv6_rtf_conf_set_mapping_table_key_t
{
    npl_lp_rtf_conf_set_t lp_rtf_conf_set;
    npl_rtf_step_t rtf_step;
    
    npl_ipv6_rtf_conf_set_mapping_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ipv6_rtf_conf_set_mapping_table_key_t element);
std::string to_short_string(struct npl_ipv6_rtf_conf_set_mapping_table_key_t element);

struct npl_ipv6_rtf_conf_set_mapping_table_value_t
{
    npl_ipv6_rtf_conf_set_mapping_table_action_e action;
    union npl_ipv6_rtf_conf_set_mapping_table_payloads_t {
        npl_ip_rtf_iteration_properties_t ipv6_rtf_iteration_prop;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ipv6_rtf_conf_set_mapping_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IPV6_RTF_CONF_SET_MAPPING_TABLE_ACTION_WRITE:
            {
                return "NPL_IPV6_RTF_CONF_SET_MAPPING_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ipv6_rtf_conf_set_mapping_table_action_e");
        }
        return "";
    }
    npl_ipv6_rtf_conf_set_mapping_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ipv6_rtf_conf_set_mapping_table_value_t element);
std::string to_short_string(struct npl_ipv6_rtf_conf_set_mapping_table_value_t element);

/// API-s for table: ipv6_sip_compression_table

typedef enum
{
    NPL_IPV6_SIP_COMPRESSION_TABLE_ACTION_WRITE = 0x0
} npl_ipv6_sip_compression_table_action_e;

struct npl_ipv6_sip_compression_table_key_t
{
    uint64_t ipv6_sip[2];
    
    npl_ipv6_sip_compression_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ipv6_sip_compression_table_key_t element);
std::string to_short_string(struct npl_ipv6_sip_compression_table_key_t element);

struct npl_ipv6_sip_compression_table_value_t
{
    npl_ipv6_sip_compression_table_action_e action;
    union npl_ipv6_sip_compression_table_payloads_t {
        uint64_t compressed_sip : 16;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ipv6_sip_compression_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IPV6_SIP_COMPRESSION_TABLE_ACTION_WRITE:
            {
                return "NPL_IPV6_SIP_COMPRESSION_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ipv6_sip_compression_table_action_e");
        }
        return "";
    }
    npl_ipv6_sip_compression_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ipv6_sip_compression_table_value_t element);
std::string to_short_string(struct npl_ipv6_sip_compression_table_value_t element);

/// API-s for table: ipv6_vrf_dip_em_table

typedef enum
{
    NPL_IPV6_VRF_DIP_EM_TABLE_ACTION_WRITE = 0x0
} npl_ipv6_vrf_dip_em_table_action_e;

struct npl_ipv6_vrf_dip_em_table_key_t
{
    npl_l3_relay_id_t l3_relay_id;
    uint64_t ipv6_ip_address_address[2];
    
    npl_ipv6_vrf_dip_em_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ipv6_vrf_dip_em_table_key_t element);
std::string to_short_string(struct npl_ipv6_vrf_dip_em_table_key_t element);

struct npl_ipv6_vrf_dip_em_table_value_t
{
    npl_ipv6_vrf_dip_em_table_action_e action;
    union npl_ipv6_vrf_dip_em_table_payloads_t {
        npl_ip_em_result_t em_lookup_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ipv6_vrf_dip_em_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IPV6_VRF_DIP_EM_TABLE_ACTION_WRITE:
            {
                return "NPL_IPV6_VRF_DIP_EM_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ipv6_vrf_dip_em_table_action_e");
        }
        return "";
    }
    npl_ipv6_vrf_dip_em_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ipv6_vrf_dip_em_table_value_t element);
std::string to_short_string(struct npl_ipv6_vrf_dip_em_table_value_t element);

/// API-s for table: ipv6_vrf_s_g_table

typedef enum
{
    NPL_IPV6_VRF_S_G_TABLE_ACTION_WRITE = 0x0
} npl_ipv6_vrf_s_g_table_action_e;

struct npl_ipv6_vrf_s_g_table_key_t
{
    npl_l3_relay_id_t l3_relay_id;
    uint64_t compressed_sip : 16;
    uint64_t dip_32_lsb : 32;
    
    npl_ipv6_vrf_s_g_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ipv6_vrf_s_g_table_key_t element);
std::string to_short_string(struct npl_ipv6_vrf_s_g_table_key_t element);

struct npl_ipv6_vrf_s_g_table_value_t
{
    npl_ipv6_vrf_s_g_table_action_e action;
    union npl_ipv6_vrf_s_g_table_payloads_t {
        npl_ip_mc_result_em_payload_t vrf_s_g_hw_ip_mc_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ipv6_vrf_s_g_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IPV6_VRF_S_G_TABLE_ACTION_WRITE:
            {
                return "NPL_IPV6_VRF_S_G_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ipv6_vrf_s_g_table_action_e");
        }
        return "";
    }
    npl_ipv6_vrf_s_g_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ipv6_vrf_s_g_table_value_t element);
std::string to_short_string(struct npl_ipv6_vrf_s_g_table_value_t element);

/// API-s for table: is_pacific_b1_static_table

typedef enum
{
    NPL_IS_PACIFIC_B1_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_is_pacific_b1_static_table_action_e;

struct npl_is_pacific_b1_static_table_key_t
{
    
    
    npl_is_pacific_b1_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_is_pacific_b1_static_table_key_t element);
std::string to_short_string(struct npl_is_pacific_b1_static_table_key_t element);

struct npl_is_pacific_b1_static_table_value_t
{
    npl_is_pacific_b1_static_table_action_e action;
    union npl_is_pacific_b1_static_table_payloads_t {
        npl_bool_t is_pacific_b1;
    } payloads;
    std::string npl_action_enum_to_string(const npl_is_pacific_b1_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_IS_PACIFIC_B1_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_IS_PACIFIC_B1_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_is_pacific_b1_static_table_action_e");
        }
        return "";
    }
    npl_is_pacific_b1_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_is_pacific_b1_static_table_value_t element);
std::string to_short_string(struct npl_is_pacific_b1_static_table_value_t element);

/// API-s for table: l2_dlp_table

typedef enum
{
    NPL_L2_DLP_TABLE_ACTION_WRITE = 0x0
} npl_l2_dlp_table_action_e;

struct npl_l2_dlp_table_key_t
{
    uint64_t l2_dlp_id_key_id : 18;
    
    npl_l2_dlp_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_l2_dlp_table_key_t element);
std::string to_short_string(struct npl_l2_dlp_table_key_t element);

struct npl_l2_dlp_table_value_t
{
    npl_l2_dlp_table_action_e action;
    union npl_l2_dlp_table_payloads_t {
        npl_l2_dlp_attributes_t l2_dlp_attributes;
    } payloads;
    std::string npl_action_enum_to_string(const npl_l2_dlp_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_L2_DLP_TABLE_ACTION_WRITE:
            {
                return "NPL_L2_DLP_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_l2_dlp_table_action_e");
        }
        return "";
    }
    npl_l2_dlp_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_l2_dlp_table_value_t element);
std::string to_short_string(struct npl_l2_dlp_table_value_t element);

/// API-s for table: l2_lp_profile_filter_table

typedef enum
{
    NPL_L2_LP_PROFILE_FILTER_TABLE_ACTION_WRITE = 0x0
} npl_l2_lp_profile_filter_table_action_e;

struct npl_l2_lp_profile_filter_table_key_t
{
    uint64_t slp_profile : 2;
    uint64_t lp_profile : 2;
    
    npl_l2_lp_profile_filter_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_l2_lp_profile_filter_table_key_t element);
std::string to_short_string(struct npl_l2_lp_profile_filter_table_key_t element);

struct npl_l2_lp_profile_filter_table_value_t
{
    npl_l2_lp_profile_filter_table_action_e action;
    union npl_l2_lp_profile_filter_table_payloads_t {
        uint64_t split_horizon : 1;
    } payloads;
    std::string npl_action_enum_to_string(const npl_l2_lp_profile_filter_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_L2_LP_PROFILE_FILTER_TABLE_ACTION_WRITE:
            {
                return "NPL_L2_LP_PROFILE_FILTER_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_l2_lp_profile_filter_table_action_e");
        }
        return "";
    }
    npl_l2_lp_profile_filter_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_l2_lp_profile_filter_table_value_t element);
std::string to_short_string(struct npl_l2_lp_profile_filter_table_value_t element);

/// API-s for table: l2_lpts_ctrl_fields_static_table

typedef enum
{
    NPL_L2_LPTS_CTRL_FIELDS_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_l2_lpts_ctrl_fields_static_table_action_e;

struct npl_l2_lpts_ctrl_fields_static_table_key_t
{
    npl_mac_lp_type_e mac_lp_type;
    uint64_t mac_terminated : 1;
    uint64_t is_tagged : 1;
    uint64_t is_svi : 1;
    
    npl_l2_lpts_ctrl_fields_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_l2_lpts_ctrl_fields_static_table_key_t element);
std::string to_short_string(struct npl_l2_lpts_ctrl_fields_static_table_key_t element);

struct npl_l2_lpts_ctrl_fields_static_table_value_t
{
    npl_l2_lpts_ctrl_fields_static_table_action_e action;
    union npl_l2_lpts_ctrl_fields_static_table_payloads_t {
        uint64_t ctrl_fields : 4;
    } payloads;
    std::string npl_action_enum_to_string(const npl_l2_lpts_ctrl_fields_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_L2_LPTS_CTRL_FIELDS_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_L2_LPTS_CTRL_FIELDS_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_l2_lpts_ctrl_fields_static_table_action_e");
        }
        return "";
    }
    npl_l2_lpts_ctrl_fields_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_l2_lpts_ctrl_fields_static_table_value_t element);
std::string to_short_string(struct npl_l2_lpts_ctrl_fields_static_table_value_t element);

/// API-s for table: l2_lpts_ip_fragment_static_table

typedef enum
{
    NPL_L2_LPTS_IP_FRAGMENT_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_l2_lpts_ip_fragment_static_table_action_e;

struct npl_l2_lpts_ip_fragment_static_table_key_t
{
    uint64_t ipv4_not_first_fragment : 1;
    uint64_t ipv6_not_first_fragment : 1;
    
    npl_l2_lpts_ip_fragment_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_l2_lpts_ip_fragment_static_table_key_t element);
std::string to_short_string(struct npl_l2_lpts_ip_fragment_static_table_key_t element);

struct npl_l2_lpts_ip_fragment_static_table_value_t
{
    npl_l2_lpts_ip_fragment_static_table_action_e action;
    union npl_l2_lpts_ip_fragment_static_table_payloads_t {
        npl_l2_lpts_ip_fragment_t ip_fragment;
    } payloads;
    std::string npl_action_enum_to_string(const npl_l2_lpts_ip_fragment_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_L2_LPTS_IP_FRAGMENT_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_L2_LPTS_IP_FRAGMENT_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_l2_lpts_ip_fragment_static_table_action_e");
        }
        return "";
    }
    npl_l2_lpts_ip_fragment_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_l2_lpts_ip_fragment_static_table_value_t element);
std::string to_short_string(struct npl_l2_lpts_ip_fragment_static_table_value_t element);

/// API-s for table: l2_lpts_ipv4_table

typedef enum
{
    NPL_L2_LPTS_IPV4_TABLE_ACTION_L2_LPTS_RESULT = 0x0
} npl_l2_lpts_ipv4_table_action_e;

struct npl_l2_lpts_ipv4_table_l2_lpts_result_payload_t
{
    npl_l2_lpts_payload_t l2_lpts_trap_vector;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_l2_lpts_ipv4_table_l2_lpts_result_payload_t element);
std::string to_short_string(npl_l2_lpts_ipv4_table_l2_lpts_result_payload_t element);

struct npl_l2_lpts_ipv4_table_key_t
{
    uint64_t dip : 32;
    npl_l4_ports_header_t l4_ports;
    uint64_t ttl : 8;
    uint64_t protocol : 8;
    uint64_t npp_attributes : 8;
    uint64_t bd_attributes : 6;
    uint64_t l2_slp_attributes : 2;
    npl_mac_lp_type_e mac_lp_type;
    uint64_t mac_terminated : 1;
    uint64_t is_tagged : 1;
    uint64_t is_svi : 1;
    npl_l2_lpts_ip_fragment_t ip_not_first_fragment;
    
    npl_l2_lpts_ipv4_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_l2_lpts_ipv4_table_key_t element);
std::string to_short_string(struct npl_l2_lpts_ipv4_table_key_t element);

struct npl_l2_lpts_ipv4_table_value_t
{
    npl_l2_lpts_ipv4_table_action_e action;
    union npl_l2_lpts_ipv4_table_payloads_t {
        npl_l2_lpts_ipv4_table_l2_lpts_result_payload_t l2_lpts_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_l2_lpts_ipv4_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_L2_LPTS_IPV4_TABLE_ACTION_L2_LPTS_RESULT:
            {
                return "NPL_L2_LPTS_IPV4_TABLE_ACTION_L2_LPTS_RESULT(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_l2_lpts_ipv4_table_action_e");
        }
        return "";
    }
    npl_l2_lpts_ipv4_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_l2_lpts_ipv4_table_value_t element);
std::string to_short_string(struct npl_l2_lpts_ipv4_table_value_t element);

/// API-s for table: l2_lpts_ipv6_table

typedef enum
{
    NPL_L2_LPTS_IPV6_TABLE_ACTION_L2_LPTS_RESULT = 0x0
} npl_l2_lpts_ipv6_table_action_e;

struct npl_l2_lpts_ipv6_table_l2_lpts_result_payload_t
{
    npl_l2_lpts_payload_t l2_lpts_trap_vector;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_l2_lpts_ipv6_table_l2_lpts_result_payload_t element);
std::string to_short_string(npl_l2_lpts_ipv6_table_l2_lpts_result_payload_t element);

struct npl_l2_lpts_ipv6_table_key_t
{
    uint64_t dip_32_msb : 32;
    uint64_t dip_32_lsb : 32;
    npl_l4_ports_header_t l4_ports;
    uint64_t next_header : 8;
    uint64_t hop_limit : 8;
    uint64_t npp_attributes : 8;
    uint64_t bd_attributes : 6;
    uint64_t l2_slp_attributes : 2;
    npl_mac_lp_type_e mac_lp_type;
    uint64_t mac_terminated : 1;
    uint64_t is_tagged : 1;
    uint64_t is_svi : 1;
    npl_l2_lpts_ip_fragment_t ip_not_first_fragment;
    
    npl_l2_lpts_ipv6_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_l2_lpts_ipv6_table_key_t element);
std::string to_short_string(struct npl_l2_lpts_ipv6_table_key_t element);

struct npl_l2_lpts_ipv6_table_value_t
{
    npl_l2_lpts_ipv6_table_action_e action;
    union npl_l2_lpts_ipv6_table_payloads_t {
        npl_l2_lpts_ipv6_table_l2_lpts_result_payload_t l2_lpts_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_l2_lpts_ipv6_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_L2_LPTS_IPV6_TABLE_ACTION_L2_LPTS_RESULT:
            {
                return "NPL_L2_LPTS_IPV6_TABLE_ACTION_L2_LPTS_RESULT(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_l2_lpts_ipv6_table_action_e");
        }
        return "";
    }
    npl_l2_lpts_ipv6_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_l2_lpts_ipv6_table_value_t element);
std::string to_short_string(struct npl_l2_lpts_ipv6_table_value_t element);

/// API-s for table: l2_lpts_mac_table

typedef enum
{
    NPL_L2_LPTS_MAC_TABLE_ACTION_L2_LPTS_RESULT = 0x0
} npl_l2_lpts_mac_table_action_e;

struct npl_l2_lpts_mac_table_l2_lpts_result_payload_t
{
    npl_l2_lpts_payload_t l2_lpts_trap_vector;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_l2_lpts_mac_table_l2_lpts_result_payload_t element);
std::string to_short_string(npl_l2_lpts_mac_table_l2_lpts_result_payload_t element);

struct npl_l2_lpts_mac_table_key_t
{
    npl_mac_addr_t mac_da;
    uint64_t ether_type : 16;
    uint64_t npp_attributes : 8;
    uint64_t bd_attributes : 6;
    uint64_t l2_slp_attributes : 2;
    npl_mac_lp_type_e mac_lp_type;
    uint64_t mac_terminated : 1;
    uint64_t is_tagged : 1;
    uint64_t is_svi : 1;
    
    npl_l2_lpts_mac_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_l2_lpts_mac_table_key_t element);
std::string to_short_string(struct npl_l2_lpts_mac_table_key_t element);

struct npl_l2_lpts_mac_table_value_t
{
    npl_l2_lpts_mac_table_action_e action;
    union npl_l2_lpts_mac_table_payloads_t {
        npl_l2_lpts_mac_table_l2_lpts_result_payload_t l2_lpts_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_l2_lpts_mac_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_L2_LPTS_MAC_TABLE_ACTION_L2_LPTS_RESULT:
            {
                return "NPL_L2_LPTS_MAC_TABLE_ACTION_L2_LPTS_RESULT(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_l2_lpts_mac_table_action_e");
        }
        return "";
    }
    npl_l2_lpts_mac_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_l2_lpts_mac_table_value_t element);
std::string to_short_string(struct npl_l2_lpts_mac_table_value_t element);

/// API-s for table: l2_lpts_next_macro_static_table

typedef enum
{
    NPL_L2_LPTS_NEXT_MACRO_STATIC_TABLE_ACTION_L2_LPTS_NEXT_MACRO_ACTION = 0x0
} npl_l2_lpts_next_macro_static_table_action_e;

struct npl_l2_lpts_next_macro_static_table_l2_lpts_next_macro_action_payload_t
{
    uint64_t pl_inc : 2;
    uint64_t macro_id : 8;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_l2_lpts_next_macro_static_table_l2_lpts_next_macro_action_payload_t element);
std::string to_short_string(npl_l2_lpts_next_macro_static_table_l2_lpts_next_macro_action_payload_t element);

struct npl_l2_lpts_next_macro_static_table_key_t
{
    npl_protocol_type_e type;
    npl_l2_lpts_next_macro_pack_fields_t ctrl_fields;
    uint64_t v4_mc : 1;
    uint64_t v6_mc : 1;
    
    npl_l2_lpts_next_macro_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_l2_lpts_next_macro_static_table_key_t element);
std::string to_short_string(struct npl_l2_lpts_next_macro_static_table_key_t element);

struct npl_l2_lpts_next_macro_static_table_value_t
{
    npl_l2_lpts_next_macro_static_table_action_e action;
    union npl_l2_lpts_next_macro_static_table_payloads_t {
        npl_l2_lpts_next_macro_static_table_l2_lpts_next_macro_action_payload_t l2_lpts_next_macro_action;
    } payloads;
    std::string npl_action_enum_to_string(const npl_l2_lpts_next_macro_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_L2_LPTS_NEXT_MACRO_STATIC_TABLE_ACTION_L2_LPTS_NEXT_MACRO_ACTION:
            {
                return "NPL_L2_LPTS_NEXT_MACRO_STATIC_TABLE_ACTION_L2_LPTS_NEXT_MACRO_ACTION(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_l2_lpts_next_macro_static_table_action_e");
        }
        return "";
    }
    npl_l2_lpts_next_macro_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_l2_lpts_next_macro_static_table_value_t element);
std::string to_short_string(struct npl_l2_lpts_next_macro_static_table_value_t element);

/// API-s for table: l2_lpts_protocol_table

typedef enum
{
    NPL_L2_LPTS_PROTOCOL_TABLE_ACTION_WRITE = 0x0
} npl_l2_lpts_protocol_table_action_e;

struct npl_l2_lpts_protocol_table_key_t
{
    npl_protocol_type_e next_protocol_type;
    npl_protocol_type_e next_header_1_type;
    uint64_t dst_udp_port : 16;
    uint64_t mac_da_use_l2_lpts : 1;
    
    npl_l2_lpts_protocol_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_l2_lpts_protocol_table_key_t element);
std::string to_short_string(struct npl_l2_lpts_protocol_table_key_t element);

struct npl_l2_lpts_protocol_table_value_t
{
    npl_l2_lpts_protocol_table_action_e action;
    union npl_l2_lpts_protocol_table_payloads_t {
        uint64_t use_l2_lpts : 1;
    } payloads;
    std::string npl_action_enum_to_string(const npl_l2_lpts_protocol_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_L2_LPTS_PROTOCOL_TABLE_ACTION_WRITE:
            {
                return "NPL_L2_LPTS_PROTOCOL_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_l2_lpts_protocol_table_action_e");
        }
        return "";
    }
    npl_l2_lpts_protocol_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_l2_lpts_protocol_table_value_t element);
std::string to_short_string(struct npl_l2_lpts_protocol_table_value_t element);

/// API-s for table: l2_lpts_skip_p2p_static_table

typedef enum
{
    NPL_L2_LPTS_SKIP_P2P_STATIC_TABLE_ACTION_L2_LPTS_SET_SKIP_P2P_TRAP = 0x0
} npl_l2_lpts_skip_p2p_static_table_action_e;

struct npl_l2_lpts_skip_p2p_static_table_l2_lpts_set_skip_p2p_trap_payload_t
{
    uint64_t skip_p2p_trap : 1;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_l2_lpts_skip_p2p_static_table_l2_lpts_set_skip_p2p_trap_payload_t element);
std::string to_short_string(npl_l2_lpts_skip_p2p_static_table_l2_lpts_set_skip_p2p_trap_payload_t element);

struct npl_l2_lpts_skip_p2p_static_table_key_t
{
    uint64_t mac_lp_type_and_term : 2;
    uint64_t is_p2p : 1;
    
    npl_l2_lpts_skip_p2p_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_l2_lpts_skip_p2p_static_table_key_t element);
std::string to_short_string(struct npl_l2_lpts_skip_p2p_static_table_key_t element);

struct npl_l2_lpts_skip_p2p_static_table_value_t
{
    npl_l2_lpts_skip_p2p_static_table_action_e action;
    union npl_l2_lpts_skip_p2p_static_table_payloads_t {
        npl_l2_lpts_skip_p2p_static_table_l2_lpts_set_skip_p2p_trap_payload_t l2_lpts_set_skip_p2p_trap;
    } payloads;
    std::string npl_action_enum_to_string(const npl_l2_lpts_skip_p2p_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_L2_LPTS_SKIP_P2P_STATIC_TABLE_ACTION_L2_LPTS_SET_SKIP_P2P_TRAP:
            {
                return "NPL_L2_LPTS_SKIP_P2P_STATIC_TABLE_ACTION_L2_LPTS_SET_SKIP_P2P_TRAP(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_l2_lpts_skip_p2p_static_table_action_e");
        }
        return "";
    }
    npl_l2_lpts_skip_p2p_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_l2_lpts_skip_p2p_static_table_value_t element);
std::string to_short_string(struct npl_l2_lpts_skip_p2p_static_table_value_t element);

/// API-s for table: l2_termination_next_macro_static_table

typedef enum
{
    NPL_L2_TERMINATION_NEXT_MACRO_STATIC_TABLE_ACTION_L2_TERMINATION_NEXT_MACRO_ACTION = 0x0
} npl_l2_termination_next_macro_static_table_action_e;

struct npl_l2_termination_next_macro_static_table_l2_termination_next_macro_action_payload_t
{
    uint64_t pl_inc : 2;
    uint64_t macro_id : 8;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_l2_termination_next_macro_static_table_l2_termination_next_macro_action_payload_t element);
std::string to_short_string(npl_l2_termination_next_macro_static_table_l2_termination_next_macro_action_payload_t element);

struct npl_l2_termination_next_macro_static_table_key_t
{
    uint64_t next_hdr_type : 4;
    npl_ipv4_ipv6_eth_init_rtf_stages_t ipv4_ipv6_eth_init_rtf_stage;
    
    npl_l2_termination_next_macro_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_l2_termination_next_macro_static_table_key_t element);
std::string to_short_string(struct npl_l2_termination_next_macro_static_table_key_t element);

struct npl_l2_termination_next_macro_static_table_value_t
{
    npl_l2_termination_next_macro_static_table_action_e action;
    union npl_l2_termination_next_macro_static_table_payloads_t {
        npl_l2_termination_next_macro_static_table_l2_termination_next_macro_action_payload_t l2_termination_next_macro_action;
    } payloads;
    std::string npl_action_enum_to_string(const npl_l2_termination_next_macro_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_L2_TERMINATION_NEXT_MACRO_STATIC_TABLE_ACTION_L2_TERMINATION_NEXT_MACRO_ACTION:
            {
                return "NPL_L2_TERMINATION_NEXT_MACRO_STATIC_TABLE_ACTION_L2_TERMINATION_NEXT_MACRO_ACTION(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_l2_termination_next_macro_static_table_action_e");
        }
        return "";
    }
    npl_l2_termination_next_macro_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_l2_termination_next_macro_static_table_value_t element);
std::string to_short_string(struct npl_l2_termination_next_macro_static_table_value_t element);

/// API-s for table: l2_tunnel_term_next_macro_static_table

typedef enum
{
    NPL_L2_TUNNEL_TERM_NEXT_MACRO_STATIC_TABLE_ACTION_L2_TERMINATION_NEXT_MACRO_ACTION = 0x0
} npl_l2_tunnel_term_next_macro_static_table_action_e;

struct npl_l2_tunnel_term_next_macro_static_table_l2_termination_next_macro_action_payload_t
{
    uint64_t pl_inc : 2;
    uint64_t macro_id : 8;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_l2_tunnel_term_next_macro_static_table_l2_termination_next_macro_action_payload_t element);
std::string to_short_string(npl_l2_tunnel_term_next_macro_static_table_l2_termination_next_macro_action_payload_t element);

struct npl_l2_tunnel_term_next_macro_static_table_key_t
{
    uint64_t overlay_or_pwe_lp_type : 1;
    npl_ipv4_ipv6_init_rtf_stage_t ipv4_ipv6_init_rtf_stage;
    
    npl_l2_tunnel_term_next_macro_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_l2_tunnel_term_next_macro_static_table_key_t element);
std::string to_short_string(struct npl_l2_tunnel_term_next_macro_static_table_key_t element);

struct npl_l2_tunnel_term_next_macro_static_table_value_t
{
    npl_l2_tunnel_term_next_macro_static_table_action_e action;
    union npl_l2_tunnel_term_next_macro_static_table_payloads_t {
        npl_l2_tunnel_term_next_macro_static_table_l2_termination_next_macro_action_payload_t l2_termination_next_macro_action;
    } payloads;
    std::string npl_action_enum_to_string(const npl_l2_tunnel_term_next_macro_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_L2_TUNNEL_TERM_NEXT_MACRO_STATIC_TABLE_ACTION_L2_TERMINATION_NEXT_MACRO_ACTION:
            {
                return "NPL_L2_TUNNEL_TERM_NEXT_MACRO_STATIC_TABLE_ACTION_L2_TERMINATION_NEXT_MACRO_ACTION(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_l2_tunnel_term_next_macro_static_table_action_e");
        }
        return "";
    }
    npl_l2_tunnel_term_next_macro_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_l2_tunnel_term_next_macro_static_table_value_t element);
std::string to_short_string(struct npl_l2_tunnel_term_next_macro_static_table_value_t element);

/// API-s for table: l3_dlp_p_counter_offset_table

typedef enum
{
    NPL_L3_DLP_P_COUNTER_OFFSET_TABLE_ACTION_WRITE = 0x0
} npl_l3_dlp_p_counter_offset_table_action_e;

struct npl_l3_dlp_p_counter_offset_table_key_t
{
    uint64_t is_mc : 1;
    npl_ip_acl_macro_control_e ip_acl_macro_control;
    npl_npu_encap_l3_header_type_e l3_encap_type;
    npl_fwd_header_type_e fwd_header_type;
    
    npl_l3_dlp_p_counter_offset_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_l3_dlp_p_counter_offset_table_key_t element);
std::string to_short_string(struct npl_l3_dlp_p_counter_offset_table_key_t element);

struct npl_l3_dlp_p_counter_offset_table_value_t
{
    npl_l3_dlp_p_counter_offset_table_action_e action;
    union npl_l3_dlp_p_counter_offset_table_payloads_t {
        npl_counter_offset_t local_tx_counter_offset;
    } payloads;
    std::string npl_action_enum_to_string(const npl_l3_dlp_p_counter_offset_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_L3_DLP_P_COUNTER_OFFSET_TABLE_ACTION_WRITE:
            {
                return "NPL_L3_DLP_P_COUNTER_OFFSET_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_l3_dlp_p_counter_offset_table_action_e");
        }
        return "";
    }
    npl_l3_dlp_p_counter_offset_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_l3_dlp_p_counter_offset_table_value_t element);
std::string to_short_string(struct npl_l3_dlp_p_counter_offset_table_value_t element);

/// API-s for table: l3_dlp_table

typedef enum
{
    NPL_L3_DLP_TABLE_ACTION_WRITE = 0x0
} npl_l3_dlp_table_action_e;

struct npl_l3_dlp_table_key_t
{
    npl_no_acls_t l3_dlp_msbs;
    uint64_t l3_dlp_lsbs : 12;
    
    npl_l3_dlp_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_l3_dlp_table_key_t element);
std::string to_short_string(struct npl_l3_dlp_table_key_t element);

struct npl_l3_dlp_table_value_t
{
    npl_l3_dlp_table_action_e action;
    union npl_l3_dlp_table_payloads_t {
        npl_l3_dlp_attributes_t l3_dlp_attributes;
    } payloads;
    std::string npl_action_enum_to_string(const npl_l3_dlp_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_L3_DLP_TABLE_ACTION_WRITE:
            {
                return "NPL_L3_DLP_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_l3_dlp_table_action_e");
        }
        return "";
    }
    npl_l3_dlp_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_l3_dlp_table_value_t element);
std::string to_short_string(struct npl_l3_dlp_table_value_t element);

/// API-s for table: l3_termination_classify_ip_tunnels_table

typedef enum
{
    NPL_L3_TERMINATION_CLASSIFY_IP_TUNNELS_TABLE_ACTION_WRITE = 0x0
} npl_l3_termination_classify_ip_tunnels_table_action_e;

struct npl_l3_termination_classify_ip_tunnels_table_key_t
{
    uint64_t l3_protocol_type : 4;
    npl_protocol_type_e l4_protocol_type;
    uint64_t udp_dst_port_or_gre_proto : 16;
    
    npl_l3_termination_classify_ip_tunnels_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_l3_termination_classify_ip_tunnels_table_key_t element);
std::string to_short_string(struct npl_l3_termination_classify_ip_tunnels_table_key_t element);

struct npl_l3_termination_classify_ip_tunnels_table_value_t
{
    npl_l3_termination_classify_ip_tunnels_table_action_e action;
    union npl_l3_termination_classify_ip_tunnels_table_payloads_t {
        npl_tunnel_type_and_force_pipe_ttl_ingress_ptp_info_t tunnel_type;
    } payloads;
    std::string npl_action_enum_to_string(const npl_l3_termination_classify_ip_tunnels_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_L3_TERMINATION_CLASSIFY_IP_TUNNELS_TABLE_ACTION_WRITE:
            {
                return "NPL_L3_TERMINATION_CLASSIFY_IP_TUNNELS_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_l3_termination_classify_ip_tunnels_table_action_e");
        }
        return "";
    }
    npl_l3_termination_classify_ip_tunnels_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_l3_termination_classify_ip_tunnels_table_value_t element);
std::string to_short_string(struct npl_l3_termination_classify_ip_tunnels_table_value_t element);

/// API-s for table: l3_termination_next_macro_static_table

typedef enum
{
    NPL_L3_TERMINATION_NEXT_MACRO_STATIC_TABLE_ACTION_IP_TERMINATION_NEXT_MACRO_ACTION = 0x0
} npl_l3_termination_next_macro_static_table_action_e;

struct npl_l3_termination_next_macro_static_table_ip_termination_next_macro_action_payload_t
{
    uint64_t pl_inc : 2;
    uint64_t macro_id : 8;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_l3_termination_next_macro_static_table_ip_termination_next_macro_action_payload_t element);
std::string to_short_string(npl_l3_termination_next_macro_static_table_ip_termination_next_macro_action_payload_t element);

struct npl_l3_termination_next_macro_static_table_key_t
{
    uint64_t hdr_type : 4;
    npl_ipv4_ipv6_init_rtf_stage_t ipv4_ipv6_init_rtf_stage;
    uint64_t dont_inc_pl : 1;
    
    npl_l3_termination_next_macro_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_l3_termination_next_macro_static_table_key_t element);
std::string to_short_string(struct npl_l3_termination_next_macro_static_table_key_t element);

struct npl_l3_termination_next_macro_static_table_value_t
{
    npl_l3_termination_next_macro_static_table_action_e action;
    union npl_l3_termination_next_macro_static_table_payloads_t {
        npl_l3_termination_next_macro_static_table_ip_termination_next_macro_action_payload_t ip_termination_next_macro_action;
    } payloads;
    std::string npl_action_enum_to_string(const npl_l3_termination_next_macro_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_L3_TERMINATION_NEXT_MACRO_STATIC_TABLE_ACTION_IP_TERMINATION_NEXT_MACRO_ACTION:
            {
                return "NPL_L3_TERMINATION_NEXT_MACRO_STATIC_TABLE_ACTION_IP_TERMINATION_NEXT_MACRO_ACTION(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_l3_termination_next_macro_static_table_action_e");
        }
        return "";
    }
    npl_l3_termination_next_macro_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_l3_termination_next_macro_static_table_value_t element);
std::string to_short_string(struct npl_l3_termination_next_macro_static_table_value_t element);

/// API-s for table: l3_tunnel_termination_next_macro_static_table

typedef enum
{
    NPL_L3_TUNNEL_TERMINATION_NEXT_MACRO_STATIC_TABLE_ACTION_IP_TERMINATION_NEXT_MACRO_ACTION = 0x0
} npl_l3_tunnel_termination_next_macro_static_table_action_e;

struct npl_l3_tunnel_termination_next_macro_static_table_ip_termination_next_macro_action_payload_t
{
    uint64_t pl_inc : 2;
    uint64_t macro_id : 8;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_l3_tunnel_termination_next_macro_static_table_ip_termination_next_macro_action_payload_t element);
std::string to_short_string(npl_l3_tunnel_termination_next_macro_static_table_ip_termination_next_macro_action_payload_t element);

struct npl_l3_tunnel_termination_next_macro_static_table_key_t
{
    uint64_t next_hdr_type : 4;
    npl_ipv4_ipv6_init_rtf_stage_t term_attr_ipv4_ipv6_init_rtf_stage;
    npl_init_rtf_stage_and_type_e pd_ipv4_init_rtf_stage;
    uint64_t lp_set : 1;
    
    npl_l3_tunnel_termination_next_macro_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_l3_tunnel_termination_next_macro_static_table_key_t element);
std::string to_short_string(struct npl_l3_tunnel_termination_next_macro_static_table_key_t element);

struct npl_l3_tunnel_termination_next_macro_static_table_value_t
{
    npl_l3_tunnel_termination_next_macro_static_table_action_e action;
    union npl_l3_tunnel_termination_next_macro_static_table_payloads_t {
        npl_l3_tunnel_termination_next_macro_static_table_ip_termination_next_macro_action_payload_t ip_termination_next_macro_action;
    } payloads;
    std::string npl_action_enum_to_string(const npl_l3_tunnel_termination_next_macro_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_L3_TUNNEL_TERMINATION_NEXT_MACRO_STATIC_TABLE_ACTION_IP_TERMINATION_NEXT_MACRO_ACTION:
            {
                return "NPL_L3_TUNNEL_TERMINATION_NEXT_MACRO_STATIC_TABLE_ACTION_IP_TERMINATION_NEXT_MACRO_ACTION(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_l3_tunnel_termination_next_macro_static_table_action_e");
        }
        return "";
    }
    npl_l3_tunnel_termination_next_macro_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_l3_tunnel_termination_next_macro_static_table_value_t element);
std::string to_short_string(struct npl_l3_tunnel_termination_next_macro_static_table_value_t element);

/// API-s for table: l3_vxlan_overlay_sa_table

typedef enum
{
    NPL_L3_VXLAN_OVERLAY_SA_TABLE_ACTION_WRITE = 0x0
} npl_l3_vxlan_overlay_sa_table_action_e;

struct npl_l3_vxlan_overlay_sa_table_key_t
{
    uint64_t sa_prefix_index : 4;
    
    npl_l3_vxlan_overlay_sa_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_l3_vxlan_overlay_sa_table_key_t element);
std::string to_short_string(struct npl_l3_vxlan_overlay_sa_table_key_t element);

struct npl_l3_vxlan_overlay_sa_table_value_t
{
    npl_l3_vxlan_overlay_sa_table_action_e action;
    union npl_l3_vxlan_overlay_sa_table_payloads_t {
        uint64_t overlay_sa_msb : 32;
    } payloads;
    std::string npl_action_enum_to_string(const npl_l3_vxlan_overlay_sa_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_L3_VXLAN_OVERLAY_SA_TABLE_ACTION_WRITE:
            {
                return "NPL_L3_VXLAN_OVERLAY_SA_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_l3_vxlan_overlay_sa_table_action_e");
        }
        return "";
    }
    npl_l3_vxlan_overlay_sa_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_l3_vxlan_overlay_sa_table_value_t element);
std::string to_short_string(struct npl_l3_vxlan_overlay_sa_table_value_t element);

/// API-s for table: large_encap_global_lsp_prefix_table

typedef enum
{
    NPL_LARGE_ENCAP_GLOBAL_LSP_PREFIX_TABLE_ACTION_WRITE = 0x0
} npl_large_encap_global_lsp_prefix_table_action_e;

struct npl_large_encap_global_lsp_prefix_table_key_t
{
    uint64_t lsp_dest_prefix : 16;
    
    npl_large_encap_global_lsp_prefix_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_large_encap_global_lsp_prefix_table_key_t element);
std::string to_short_string(struct npl_large_encap_global_lsp_prefix_table_key_t element);

struct npl_large_encap_global_lsp_prefix_table_value_t
{
    npl_large_encap_global_lsp_prefix_table_action_e action;
    union npl_large_encap_global_lsp_prefix_table_payloads_t {
        npl_lsp_encap_mapping_data_payload_t lsp_encap_mapping_data_payload;
    } payloads;
    std::string npl_action_enum_to_string(const npl_large_encap_global_lsp_prefix_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_LARGE_ENCAP_GLOBAL_LSP_PREFIX_TABLE_ACTION_WRITE:
            {
                return "NPL_LARGE_ENCAP_GLOBAL_LSP_PREFIX_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_large_encap_global_lsp_prefix_table_action_e");
        }
        return "";
    }
    npl_large_encap_global_lsp_prefix_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_large_encap_global_lsp_prefix_table_value_t element);
std::string to_short_string(struct npl_large_encap_global_lsp_prefix_table_value_t element);

/// API-s for table: large_encap_ip_tunnel_table

typedef enum
{
    NPL_LARGE_ENCAP_IP_TUNNEL_TABLE_ACTION_WRITE = 0x0
} npl_large_encap_ip_tunnel_table_action_e;

struct npl_large_encap_ip_tunnel_table_key_t
{
    uint64_t gre_tunnel_dlp : 16;
    
    npl_large_encap_ip_tunnel_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_large_encap_ip_tunnel_table_key_t element);
std::string to_short_string(struct npl_large_encap_ip_tunnel_table_key_t element);

struct npl_large_encap_ip_tunnel_table_value_t
{
    npl_large_encap_ip_tunnel_table_action_e action;
    union npl_large_encap_ip_tunnel_table_payloads_t {
        npl_gre_tunnel_attributes_t gre_tunnel_attributes;
    } payloads;
    std::string npl_action_enum_to_string(const npl_large_encap_ip_tunnel_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_LARGE_ENCAP_IP_TUNNEL_TABLE_ACTION_WRITE:
            {
                return "NPL_LARGE_ENCAP_IP_TUNNEL_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_large_encap_ip_tunnel_table_action_e");
        }
        return "";
    }
    npl_large_encap_ip_tunnel_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_large_encap_ip_tunnel_table_value_t element);
std::string to_short_string(struct npl_large_encap_ip_tunnel_table_value_t element);

/// API-s for table: large_encap_mpls_he_no_ldp_table

typedef enum
{
    NPL_LARGE_ENCAP_MPLS_HE_NO_LDP_TABLE_ACTION_WRITE = 0x0
} npl_large_encap_mpls_he_no_ldp_table_action_e;

struct npl_large_encap_mpls_he_no_ldp_table_key_t
{
    uint64_t lsp_dest_prefix : 16;
    uint64_t nh_ptr : 12;
    
    npl_large_encap_mpls_he_no_ldp_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_large_encap_mpls_he_no_ldp_table_key_t element);
std::string to_short_string(struct npl_large_encap_mpls_he_no_ldp_table_key_t element);

struct npl_large_encap_mpls_he_no_ldp_table_value_t
{
    npl_large_encap_mpls_he_no_ldp_table_action_e action;
    union npl_large_encap_mpls_he_no_ldp_table_payloads_t {
        npl_lsp_encap_mapping_data_payload_t lsp_encap_mapping_data_payload;
    } payloads;
    std::string npl_action_enum_to_string(const npl_large_encap_mpls_he_no_ldp_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_LARGE_ENCAP_MPLS_HE_NO_LDP_TABLE_ACTION_WRITE:
            {
                return "NPL_LARGE_ENCAP_MPLS_HE_NO_LDP_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_large_encap_mpls_he_no_ldp_table_action_e");
        }
        return "";
    }
    npl_large_encap_mpls_he_no_ldp_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_large_encap_mpls_he_no_ldp_table_value_t element);
std::string to_short_string(struct npl_large_encap_mpls_he_no_ldp_table_value_t element);

/// API-s for table: large_encap_mpls_ldp_over_te_table

typedef enum
{
    NPL_LARGE_ENCAP_MPLS_LDP_OVER_TE_TABLE_ACTION_WRITE = 0x0
} npl_large_encap_mpls_ldp_over_te_table_action_e;

struct npl_large_encap_mpls_ldp_over_te_table_key_t
{
    uint64_t lsp_dest_prefix : 16;
    uint64_t te_tunnel : 16;
    
    npl_large_encap_mpls_ldp_over_te_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_large_encap_mpls_ldp_over_te_table_key_t element);
std::string to_short_string(struct npl_large_encap_mpls_ldp_over_te_table_key_t element);

struct npl_large_encap_mpls_ldp_over_te_table_value_t
{
    npl_large_encap_mpls_ldp_over_te_table_action_e action;
    union npl_large_encap_mpls_ldp_over_te_table_payloads_t {
        npl_large_em_label_encap_data_and_counter_ptr_t large_em_label_encap_data_and_counter_ptr;
    } payloads;
    std::string npl_action_enum_to_string(const npl_large_encap_mpls_ldp_over_te_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_LARGE_ENCAP_MPLS_LDP_OVER_TE_TABLE_ACTION_WRITE:
            {
                return "NPL_LARGE_ENCAP_MPLS_LDP_OVER_TE_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_large_encap_mpls_ldp_over_te_table_action_e");
        }
        return "";
    }
    npl_large_encap_mpls_ldp_over_te_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_large_encap_mpls_ldp_over_te_table_value_t element);
std::string to_short_string(struct npl_large_encap_mpls_ldp_over_te_table_value_t element);

/// API-s for table: large_encap_te_he_tunnel_id_table

typedef enum
{
    NPL_LARGE_ENCAP_TE_HE_TUNNEL_ID_TABLE_ACTION_WRITE = 0x0
} npl_large_encap_te_he_tunnel_id_table_action_e;

struct npl_large_encap_te_he_tunnel_id_table_key_t
{
    uint64_t te_tunnel : 16;
    uint64_t nh_ptr : 12;
    
    npl_large_encap_te_he_tunnel_id_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_large_encap_te_he_tunnel_id_table_key_t element);
std::string to_short_string(struct npl_large_encap_te_he_tunnel_id_table_key_t element);

struct npl_large_encap_te_he_tunnel_id_table_value_t
{
    npl_large_encap_te_he_tunnel_id_table_action_e action;
    union npl_large_encap_te_he_tunnel_id_table_payloads_t {
        npl_lsp_encap_mapping_data_payload_t lsp_encap_mapping_data_payload;
    } payloads;
    std::string npl_action_enum_to_string(const npl_large_encap_te_he_tunnel_id_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_LARGE_ENCAP_TE_HE_TUNNEL_ID_TABLE_ACTION_WRITE:
            {
                return "NPL_LARGE_ENCAP_TE_HE_TUNNEL_ID_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_large_encap_te_he_tunnel_id_table_action_e");
        }
        return "";
    }
    npl_large_encap_te_he_tunnel_id_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_large_encap_te_he_tunnel_id_table_value_t element);
std::string to_short_string(struct npl_large_encap_te_he_tunnel_id_table_value_t element);

/// API-s for table: latest_learn_records_table

typedef enum
{
    NPL_LATEST_LEARN_RECORDS_TABLE_ACTION_WRITE = 0x0
} npl_latest_learn_records_table_action_e;

struct npl_latest_learn_records_table_key_t
{
    npl_lr_filter_fifo_register_t learn_record_filter_vars_read_ptr;
    
    npl_latest_learn_records_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_latest_learn_records_table_key_t element);
std::string to_short_string(struct npl_latest_learn_records_table_key_t element);

struct npl_latest_learn_records_table_value_t
{
    npl_latest_learn_records_table_action_e action;
    union npl_latest_learn_records_table_payloads_t {
        npl_output_learn_record_t learn_record_filter_vars_filter_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_latest_learn_records_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_LATEST_LEARN_RECORDS_TABLE_ACTION_WRITE:
            {
                return "NPL_LATEST_LEARN_RECORDS_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_latest_learn_records_table_action_e");
        }
        return "";
    }
    npl_latest_learn_records_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_latest_learn_records_table_value_t element);
std::string to_short_string(struct npl_latest_learn_records_table_value_t element);

/// API-s for table: learn_manager_cfg_max_learn_type_reg

typedef enum
{
    NPL_LEARN_MANAGER_CFG_MAX_LEARN_TYPE_REG_ACTION_WRITE = 0x0
} npl_learn_manager_cfg_max_learn_type_reg_action_e;

struct npl_learn_manager_cfg_max_learn_type_reg_key_t
{
    
    
    npl_learn_manager_cfg_max_learn_type_reg_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_learn_manager_cfg_max_learn_type_reg_key_t element);
std::string to_short_string(struct npl_learn_manager_cfg_max_learn_type_reg_key_t element);

struct npl_learn_manager_cfg_max_learn_type_reg_value_t
{
    npl_learn_manager_cfg_max_learn_type_reg_action_e action;
    union npl_learn_manager_cfg_max_learn_type_reg_payloads_t {
        npl_learn_manager_cfg_max_learn_type_t learn_manager_cfg_max_learn_type;
    } payloads;
    std::string npl_action_enum_to_string(const npl_learn_manager_cfg_max_learn_type_reg_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_LEARN_MANAGER_CFG_MAX_LEARN_TYPE_REG_ACTION_WRITE:
            {
                return "NPL_LEARN_MANAGER_CFG_MAX_LEARN_TYPE_REG_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_learn_manager_cfg_max_learn_type_reg_action_e");
        }
        return "";
    }
    npl_learn_manager_cfg_max_learn_type_reg_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_learn_manager_cfg_max_learn_type_reg_value_t element);
std::string to_short_string(struct npl_learn_manager_cfg_max_learn_type_reg_value_t element);

/// API-s for table: learn_record_fifo_table

typedef enum
{
    NPL_LEARN_RECORD_FIFO_TABLE_ACTION_WRITE = 0x0
} npl_learn_record_fifo_table_action_e;

struct npl_learn_record_fifo_table_key_t
{
    npl_lr_fifo_register_t learn_record_fifo_address;
    
    npl_learn_record_fifo_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_learn_record_fifo_table_key_t element);
std::string to_short_string(struct npl_learn_record_fifo_table_key_t element);

struct npl_learn_record_fifo_table_value_t
{
    npl_learn_record_fifo_table_action_e action;
    union npl_learn_record_fifo_table_payloads_t {
        npl_output_learn_record_t learn_record_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_learn_record_fifo_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_LEARN_RECORD_FIFO_TABLE_ACTION_WRITE:
            {
                return "NPL_LEARN_RECORD_FIFO_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_learn_record_fifo_table_action_e");
        }
        return "";
    }
    npl_learn_record_fifo_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_learn_record_fifo_table_value_t element);
std::string to_short_string(struct npl_learn_record_fifo_table_value_t element);

/// API-s for table: light_fi_fabric_table

typedef enum
{
    NPL_LIGHT_FI_FABRIC_TABLE_ACTION_LIGHT_FI_LEABA_TABLE_HIT = 0x0
} npl_light_fi_fabric_table_action_e;

struct npl_light_fi_fabric_table_light_fi_leaba_table_hit_payload_t
{
    uint64_t use_additional_size : 1;
    uint64_t base_size : 7;
    uint64_t is_protocol_layer : 1;
    npl_light_fi_stage_type_e next_fi_macro_id;
    uint64_t npe_macro_id : 8;
    uint64_t npe_macro_id_valid : 1;
    npl_header_format_t next_header_format;
    npl_header_format_t header_format;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_light_fi_fabric_table_light_fi_leaba_table_hit_payload_t element);
std::string to_short_string(npl_light_fi_fabric_table_light_fi_leaba_table_hit_payload_t element);

struct npl_light_fi_fabric_table_key_t
{
    uint64_t fabric_header_type : 4;
    
    npl_light_fi_fabric_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_light_fi_fabric_table_key_t element);
std::string to_short_string(struct npl_light_fi_fabric_table_key_t element);

struct npl_light_fi_fabric_table_value_t
{
    npl_light_fi_fabric_table_action_e action;
    union npl_light_fi_fabric_table_payloads_t {
        npl_light_fi_fabric_table_light_fi_leaba_table_hit_payload_t light_fi_leaba_table_hit;
    } payloads;
    std::string npl_action_enum_to_string(const npl_light_fi_fabric_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_LIGHT_FI_FABRIC_TABLE_ACTION_LIGHT_FI_LEABA_TABLE_HIT:
            {
                return "NPL_LIGHT_FI_FABRIC_TABLE_ACTION_LIGHT_FI_LEABA_TABLE_HIT(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_light_fi_fabric_table_action_e");
        }
        return "";
    }
    npl_light_fi_fabric_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_light_fi_fabric_table_value_t element);
std::string to_short_string(struct npl_light_fi_fabric_table_value_t element);

/// API-s for table: light_fi_npu_base_table

typedef enum
{
    NPL_LIGHT_FI_NPU_BASE_TABLE_ACTION_LIGHT_FI_LEABA_TABLE_HIT = 0x0
} npl_light_fi_npu_base_table_action_e;

struct npl_light_fi_npu_base_table_light_fi_leaba_table_hit_payload_t
{
    uint64_t use_additional_size : 1;
    uint64_t base_size : 7;
    uint64_t is_protocol_layer : 1;
    npl_light_fi_stage_type_e next_fi_macro_id;
    uint64_t npe_macro_id : 8;
    uint64_t npe_macro_id_valid : 1;
    npl_header_format_t next_header_format;
    npl_header_format_t header_format;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_light_fi_npu_base_table_light_fi_leaba_table_hit_payload_t element);
std::string to_short_string(npl_light_fi_npu_base_table_light_fi_leaba_table_hit_payload_t element);

struct npl_light_fi_npu_base_table_key_t
{
    uint64_t npu_header_type : 6;
    
    npl_light_fi_npu_base_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_light_fi_npu_base_table_key_t element);
std::string to_short_string(struct npl_light_fi_npu_base_table_key_t element);

struct npl_light_fi_npu_base_table_value_t
{
    npl_light_fi_npu_base_table_action_e action;
    union npl_light_fi_npu_base_table_payloads_t {
        npl_light_fi_npu_base_table_light_fi_leaba_table_hit_payload_t light_fi_leaba_table_hit;
    } payloads;
    std::string npl_action_enum_to_string(const npl_light_fi_npu_base_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_LIGHT_FI_NPU_BASE_TABLE_ACTION_LIGHT_FI_LEABA_TABLE_HIT:
            {
                return "NPL_LIGHT_FI_NPU_BASE_TABLE_ACTION_LIGHT_FI_LEABA_TABLE_HIT(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_light_fi_npu_base_table_action_e");
        }
        return "";
    }
    npl_light_fi_npu_base_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_light_fi_npu_base_table_value_t element);
std::string to_short_string(struct npl_light_fi_npu_base_table_value_t element);

/// API-s for table: light_fi_npu_encap_table

typedef enum
{
    NPL_LIGHT_FI_NPU_ENCAP_TABLE_ACTION_LIGHT_FI_NPU_ENCAP_TABLE_HIT = 0x0
} npl_light_fi_npu_encap_table_action_e;

struct npl_light_fi_npu_encap_table_light_fi_npu_encap_table_hit_payload_t
{
    uint64_t spare : 21;
    uint64_t next_stage_size_width : 4;
    uint64_t next_stage_size_offset : 6;
    uint64_t next_stage_protocol_or_type_offset : 6;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_light_fi_npu_encap_table_light_fi_npu_encap_table_hit_payload_t element);
std::string to_short_string(npl_light_fi_npu_encap_table_light_fi_npu_encap_table_hit_payload_t element);

struct npl_light_fi_npu_encap_table_key_t
{
    uint64_t next_header_type : 8;
    
    npl_light_fi_npu_encap_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_light_fi_npu_encap_table_key_t element);
std::string to_short_string(struct npl_light_fi_npu_encap_table_key_t element);

struct npl_light_fi_npu_encap_table_value_t
{
    npl_light_fi_npu_encap_table_action_e action;
    union npl_light_fi_npu_encap_table_payloads_t {
        npl_light_fi_npu_encap_table_light_fi_npu_encap_table_hit_payload_t light_fi_npu_encap_table_hit;
    } payloads;
    std::string npl_action_enum_to_string(const npl_light_fi_npu_encap_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_LIGHT_FI_NPU_ENCAP_TABLE_ACTION_LIGHT_FI_NPU_ENCAP_TABLE_HIT:
            {
                return "NPL_LIGHT_FI_NPU_ENCAP_TABLE_ACTION_LIGHT_FI_NPU_ENCAP_TABLE_HIT(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_light_fi_npu_encap_table_action_e");
        }
        return "";
    }
    npl_light_fi_npu_encap_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_light_fi_npu_encap_table_value_t element);
std::string to_short_string(struct npl_light_fi_npu_encap_table_value_t element);

/// API-s for table: light_fi_nw_0_table

typedef enum
{
    NPL_LIGHT_FI_NW_0_TABLE_ACTION_LIGHT_FI_NW_TABLE_HIT = 0x0
} npl_light_fi_nw_0_table_action_e;

struct npl_light_fi_nw_0_table_light_fi_nw_table_hit_payload_t
{
    uint64_t next_stage_size_width : 4;
    uint64_t next_stage_size_offset : 6;
    uint64_t next_stage_protocol_or_type_offset : 6;
    uint64_t use_additional_size : 1;
    uint64_t base_size : 7;
    uint64_t is_protocol_layer : 1;
    npl_light_fi_stage_type_e next_fi_macro_id;
    npl_header_format_t next_header_format;
    npl_header_format_t header_format;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_light_fi_nw_0_table_light_fi_nw_table_hit_payload_t element);
std::string to_short_string(npl_light_fi_nw_0_table_light_fi_nw_table_hit_payload_t element);

struct npl_light_fi_nw_0_table_key_t
{
    npl_protocol_type_e current_header_type;
    uint64_t next_protocol_field : 16;
    
    npl_light_fi_nw_0_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_light_fi_nw_0_table_key_t element);
std::string to_short_string(struct npl_light_fi_nw_0_table_key_t element);

struct npl_light_fi_nw_0_table_value_t
{
    npl_light_fi_nw_0_table_action_e action;
    union npl_light_fi_nw_0_table_payloads_t {
        npl_light_fi_nw_0_table_light_fi_nw_table_hit_payload_t light_fi_nw_table_hit;
    } payloads;
    std::string npl_action_enum_to_string(const npl_light_fi_nw_0_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_LIGHT_FI_NW_0_TABLE_ACTION_LIGHT_FI_NW_TABLE_HIT:
            {
                return "NPL_LIGHT_FI_NW_0_TABLE_ACTION_LIGHT_FI_NW_TABLE_HIT(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_light_fi_nw_0_table_action_e");
        }
        return "";
    }
    npl_light_fi_nw_0_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_light_fi_nw_0_table_value_t element);
std::string to_short_string(struct npl_light_fi_nw_0_table_value_t element);

/// API-s for table: light_fi_nw_1_table

typedef enum
{
    NPL_LIGHT_FI_NW_1_TABLE_ACTION_LIGHT_FI_NW_TABLE_HIT = 0x0
} npl_light_fi_nw_1_table_action_e;

struct npl_light_fi_nw_1_table_light_fi_nw_table_hit_payload_t
{
    uint64_t next_stage_size_width : 4;
    uint64_t next_stage_size_offset : 6;
    uint64_t next_stage_protocol_or_type_offset : 6;
    uint64_t use_additional_size : 1;
    uint64_t base_size : 7;
    uint64_t is_protocol_layer : 1;
    npl_light_fi_stage_type_e next_fi_macro_id;
    npl_header_format_t next_header_format;
    npl_header_format_t header_format;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_light_fi_nw_1_table_light_fi_nw_table_hit_payload_t element);
std::string to_short_string(npl_light_fi_nw_1_table_light_fi_nw_table_hit_payload_t element);

struct npl_light_fi_nw_1_table_key_t
{
    npl_protocol_type_e current_header_type;
    uint64_t next_protocol_field : 16;
    
    npl_light_fi_nw_1_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_light_fi_nw_1_table_key_t element);
std::string to_short_string(struct npl_light_fi_nw_1_table_key_t element);

struct npl_light_fi_nw_1_table_value_t
{
    npl_light_fi_nw_1_table_action_e action;
    union npl_light_fi_nw_1_table_payloads_t {
        npl_light_fi_nw_1_table_light_fi_nw_table_hit_payload_t light_fi_nw_table_hit;
    } payloads;
    std::string npl_action_enum_to_string(const npl_light_fi_nw_1_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_LIGHT_FI_NW_1_TABLE_ACTION_LIGHT_FI_NW_TABLE_HIT:
            {
                return "NPL_LIGHT_FI_NW_1_TABLE_ACTION_LIGHT_FI_NW_TABLE_HIT(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_light_fi_nw_1_table_action_e");
        }
        return "";
    }
    npl_light_fi_nw_1_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_light_fi_nw_1_table_value_t element);
std::string to_short_string(struct npl_light_fi_nw_1_table_value_t element);

/// API-s for table: light_fi_nw_2_table

typedef enum
{
    NPL_LIGHT_FI_NW_2_TABLE_ACTION_LIGHT_FI_NW_TABLE_HIT = 0x0
} npl_light_fi_nw_2_table_action_e;

struct npl_light_fi_nw_2_table_light_fi_nw_table_hit_payload_t
{
    uint64_t next_stage_size_width : 4;
    uint64_t next_stage_size_offset : 6;
    uint64_t next_stage_protocol_or_type_offset : 6;
    uint64_t use_additional_size : 1;
    uint64_t base_size : 7;
    uint64_t is_protocol_layer : 1;
    npl_light_fi_stage_type_e next_fi_macro_id;
    npl_header_format_t next_header_format;
    npl_header_format_t header_format;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_light_fi_nw_2_table_light_fi_nw_table_hit_payload_t element);
std::string to_short_string(npl_light_fi_nw_2_table_light_fi_nw_table_hit_payload_t element);

struct npl_light_fi_nw_2_table_key_t
{
    npl_protocol_type_e current_header_type;
    uint64_t next_protocol_field : 16;
    
    npl_light_fi_nw_2_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_light_fi_nw_2_table_key_t element);
std::string to_short_string(struct npl_light_fi_nw_2_table_key_t element);

struct npl_light_fi_nw_2_table_value_t
{
    npl_light_fi_nw_2_table_action_e action;
    union npl_light_fi_nw_2_table_payloads_t {
        npl_light_fi_nw_2_table_light_fi_nw_table_hit_payload_t light_fi_nw_table_hit;
    } payloads;
    std::string npl_action_enum_to_string(const npl_light_fi_nw_2_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_LIGHT_FI_NW_2_TABLE_ACTION_LIGHT_FI_NW_TABLE_HIT:
            {
                return "NPL_LIGHT_FI_NW_2_TABLE_ACTION_LIGHT_FI_NW_TABLE_HIT(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_light_fi_nw_2_table_action_e");
        }
        return "";
    }
    npl_light_fi_nw_2_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_light_fi_nw_2_table_value_t element);
std::string to_short_string(struct npl_light_fi_nw_2_table_value_t element);

/// API-s for table: light_fi_nw_3_table

typedef enum
{
    NPL_LIGHT_FI_NW_3_TABLE_ACTION_LIGHT_FI_NW_TABLE_HIT = 0x0
} npl_light_fi_nw_3_table_action_e;

struct npl_light_fi_nw_3_table_light_fi_nw_table_hit_payload_t
{
    uint64_t next_stage_size_width : 4;
    uint64_t next_stage_size_offset : 6;
    uint64_t next_stage_protocol_or_type_offset : 6;
    uint64_t use_additional_size : 1;
    uint64_t base_size : 7;
    uint64_t is_protocol_layer : 1;
    npl_light_fi_stage_type_e next_fi_macro_id;
    npl_header_format_t next_header_format;
    npl_header_format_t header_format;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_light_fi_nw_3_table_light_fi_nw_table_hit_payload_t element);
std::string to_short_string(npl_light_fi_nw_3_table_light_fi_nw_table_hit_payload_t element);

struct npl_light_fi_nw_3_table_key_t
{
    npl_protocol_type_e current_header_type;
    uint64_t next_protocol_field : 16;
    
    npl_light_fi_nw_3_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_light_fi_nw_3_table_key_t element);
std::string to_short_string(struct npl_light_fi_nw_3_table_key_t element);

struct npl_light_fi_nw_3_table_value_t
{
    npl_light_fi_nw_3_table_action_e action;
    union npl_light_fi_nw_3_table_payloads_t {
        npl_light_fi_nw_3_table_light_fi_nw_table_hit_payload_t light_fi_nw_table_hit;
    } payloads;
    std::string npl_action_enum_to_string(const npl_light_fi_nw_3_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_LIGHT_FI_NW_3_TABLE_ACTION_LIGHT_FI_NW_TABLE_HIT:
            {
                return "NPL_LIGHT_FI_NW_3_TABLE_ACTION_LIGHT_FI_NW_TABLE_HIT(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_light_fi_nw_3_table_action_e");
        }
        return "";
    }
    npl_light_fi_nw_3_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_light_fi_nw_3_table_value_t element);
std::string to_short_string(struct npl_light_fi_nw_3_table_value_t element);

/// API-s for table: light_fi_stages_cfg_table

typedef enum
{
    NPL_LIGHT_FI_STAGES_CFG_TABLE_ACTION_WRITE = 0x0
} npl_light_fi_stages_cfg_table_action_e;

struct npl_light_fi_stages_cfg_table_key_t
{
    uint64_t macro_id : 3;
    
    npl_light_fi_stages_cfg_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_light_fi_stages_cfg_table_key_t element);
std::string to_short_string(struct npl_light_fi_stages_cfg_table_key_t element);

struct npl_light_fi_stages_cfg_table_value_t
{
    npl_light_fi_stages_cfg_table_action_e action;
    union npl_light_fi_stages_cfg_table_payloads_t {
        npl_light_fi_stage_cfg_t light_fi_stage_cfg;
    } payloads;
    std::string npl_action_enum_to_string(const npl_light_fi_stages_cfg_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_LIGHT_FI_STAGES_CFG_TABLE_ACTION_WRITE:
            {
                return "NPL_LIGHT_FI_STAGES_CFG_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_light_fi_stages_cfg_table_action_e");
        }
        return "";
    }
    npl_light_fi_stages_cfg_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_light_fi_stages_cfg_table_value_t element);
std::string to_short_string(struct npl_light_fi_stages_cfg_table_value_t element);

/// API-s for table: light_fi_tm_table

typedef enum
{
    NPL_LIGHT_FI_TM_TABLE_ACTION_LIGHT_FI_LEABA_TABLE_HIT = 0x0
} npl_light_fi_tm_table_action_e;

struct npl_light_fi_tm_table_light_fi_leaba_table_hit_payload_t
{
    uint64_t use_additional_size : 1;
    uint64_t base_size : 7;
    uint64_t is_protocol_layer : 1;
    npl_light_fi_stage_type_e next_fi_macro_id;
    uint64_t npe_macro_id : 8;
    uint64_t npe_macro_id_valid : 1;
    npl_header_format_t next_header_format;
    npl_header_format_t header_format;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_light_fi_tm_table_light_fi_leaba_table_hit_payload_t element);
std::string to_short_string(npl_light_fi_tm_table_light_fi_leaba_table_hit_payload_t element);

struct npl_light_fi_tm_table_key_t
{
    uint64_t tm_header_type : 4;
    
    npl_light_fi_tm_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_light_fi_tm_table_key_t element);
std::string to_short_string(struct npl_light_fi_tm_table_key_t element);

struct npl_light_fi_tm_table_value_t
{
    npl_light_fi_tm_table_action_e action;
    union npl_light_fi_tm_table_payloads_t {
        npl_light_fi_tm_table_light_fi_leaba_table_hit_payload_t light_fi_leaba_table_hit;
    } payloads;
    std::string npl_action_enum_to_string(const npl_light_fi_tm_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_LIGHT_FI_TM_TABLE_ACTION_LIGHT_FI_LEABA_TABLE_HIT:
            {
                return "NPL_LIGHT_FI_TM_TABLE_ACTION_LIGHT_FI_LEABA_TABLE_HIT(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_light_fi_tm_table_action_e");
        }
        return "";
    }
    npl_light_fi_tm_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_light_fi_tm_table_value_t element);
std::string to_short_string(struct npl_light_fi_tm_table_value_t element);

/// API-s for table: link_relay_attributes_table

typedef enum
{
    NPL_LINK_RELAY_ATTRIBUTES_TABLE_ACTION_RELAY = 0x0
} npl_link_relay_attributes_table_action_e;

struct npl_link_relay_attributes_table_relay_payload_t
{
    npl_relay_attr_table_payload_t relay_table_payload;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_link_relay_attributes_table_relay_payload_t element);
std::string to_short_string(npl_link_relay_attributes_table_relay_payload_t element);

struct npl_link_relay_attributes_table_key_t
{
    uint64_t service_relay_attributes_table_key_11_0_ : 12;
    
    npl_link_relay_attributes_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_link_relay_attributes_table_key_t element);
std::string to_short_string(struct npl_link_relay_attributes_table_key_t element);

struct npl_link_relay_attributes_table_value_t
{
    npl_link_relay_attributes_table_action_e action;
    union npl_link_relay_attributes_table_payloads_t {
        npl_link_relay_attributes_table_relay_payload_t relay;
    } payloads;
    std::string npl_action_enum_to_string(const npl_link_relay_attributes_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_LINK_RELAY_ATTRIBUTES_TABLE_ACTION_RELAY:
            {
                return "NPL_LINK_RELAY_ATTRIBUTES_TABLE_ACTION_RELAY(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_link_relay_attributes_table_action_e");
        }
        return "";
    }
    npl_link_relay_attributes_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_link_relay_attributes_table_value_t element);
std::string to_short_string(struct npl_link_relay_attributes_table_value_t element);

/// API-s for table: link_up_vector

typedef enum
{
    NPL_LINK_UP_VECTOR_ACTION_WRITE = 0x0
} npl_link_up_vector_action_e;

struct npl_link_up_vector_key_t
{
    
    
    npl_link_up_vector_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_link_up_vector_key_t element);
std::string to_short_string(struct npl_link_up_vector_key_t element);

struct npl_link_up_vector_value_t
{
    npl_link_up_vector_action_e action;
    union npl_link_up_vector_payloads_t {
        npl_link_up_vector_result_t link_up_vector_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_link_up_vector_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_LINK_UP_VECTOR_ACTION_WRITE:
            {
                return "NPL_LINK_UP_VECTOR_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_link_up_vector_action_e");
        }
        return "";
    }
    npl_link_up_vector_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_link_up_vector_value_t element);
std::string to_short_string(struct npl_link_up_vector_value_t element);

/// API-s for table: lp_over_lag_table

typedef enum
{
    NPL_LP_OVER_LAG_TABLE_ACTION_WRITE = 0x0
} npl_lp_over_lag_table_action_e;

struct npl_lp_over_lag_table_key_t
{
    uint64_t destination : 20;
    npl_no_acls_t l3_dlp_msbs;
    uint64_t l3_dlp_lsbs : 12;
    
    npl_lp_over_lag_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_lp_over_lag_table_key_t element);
std::string to_short_string(struct npl_lp_over_lag_table_key_t element);

struct npl_lp_over_lag_table_value_t
{
    npl_lp_over_lag_table_action_e action;
    union npl_lp_over_lag_table_payloads_t {
        uint64_t bvn_destination : 20;
    } payloads;
    std::string npl_action_enum_to_string(const npl_lp_over_lag_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_LP_OVER_LAG_TABLE_ACTION_WRITE:
            {
                return "NPL_LP_OVER_LAG_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_lp_over_lag_table_action_e");
        }
        return "";
    }
    npl_lp_over_lag_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_lp_over_lag_table_value_t element);
std::string to_short_string(struct npl_lp_over_lag_table_value_t element);

/// API-s for table: lpm_destination_prefix_map_table

typedef enum
{
    NPL_LPM_DESTINATION_PREFIX_MAP_TABLE_ACTION_WRITE = 0x0
} npl_lpm_destination_prefix_map_table_action_e;

struct npl_lpm_destination_prefix_map_table_key_t
{
    uint64_t lpm_prefix_map_input_prefix : 6;
    
    npl_lpm_destination_prefix_map_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_lpm_destination_prefix_map_table_key_t element);
std::string to_short_string(struct npl_lpm_destination_prefix_map_table_key_t element);

struct npl_lpm_destination_prefix_map_table_value_t
{
    npl_lpm_destination_prefix_map_table_action_e action;
    union npl_lpm_destination_prefix_map_table_payloads_t {
        npl_lpm_prefix_map_output_t lpm_prefix_map_output;
    } payloads;
    std::string npl_action_enum_to_string(const npl_lpm_destination_prefix_map_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_LPM_DESTINATION_PREFIX_MAP_TABLE_ACTION_WRITE:
            {
                return "NPL_LPM_DESTINATION_PREFIX_MAP_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_lpm_destination_prefix_map_table_action_e");
        }
        return "";
    }
    npl_lpm_destination_prefix_map_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_lpm_destination_prefix_map_table_value_t element);
std::string to_short_string(struct npl_lpm_destination_prefix_map_table_value_t element);

/// API-s for table: lpts_2nd_lookup_table

typedef enum
{
    NPL_LPTS_2ND_LOOKUP_TABLE_ACTION_WRITE = 0x0
} npl_lpts_2nd_lookup_table_action_e;

struct npl_lpts_2nd_lookup_table_key_t
{
    uint64_t lpts_second_lookup_key : 5;
    
    npl_lpts_2nd_lookup_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_lpts_2nd_lookup_table_key_t element);
std::string to_short_string(struct npl_lpts_2nd_lookup_table_key_t element);

struct npl_lpts_2nd_lookup_table_value_t
{
    npl_lpts_2nd_lookup_table_action_e action;
    union npl_lpts_2nd_lookup_table_payloads_t {
        npl_lpts_payload_t lpts_payload;
    } payloads;
    std::string npl_action_enum_to_string(const npl_lpts_2nd_lookup_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_LPTS_2ND_LOOKUP_TABLE_ACTION_WRITE:
            {
                return "NPL_LPTS_2ND_LOOKUP_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_lpts_2nd_lookup_table_action_e");
        }
        return "";
    }
    npl_lpts_2nd_lookup_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_lpts_2nd_lookup_table_value_t element);
std::string to_short_string(struct npl_lpts_2nd_lookup_table_value_t element);

/// API-s for table: lpts_meter_table

typedef enum
{
    NPL_LPTS_METER_TABLE_ACTION_WRITE = 0x0
} npl_lpts_meter_table_action_e;

struct npl_lpts_meter_table_key_t
{
    uint64_t meter_index_msb : 1;
    uint64_t meter_index_lsb : 7;
    
    npl_lpts_meter_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_lpts_meter_table_key_t element);
std::string to_short_string(struct npl_lpts_meter_table_key_t element);

struct npl_lpts_meter_table_value_t
{
    npl_lpts_meter_table_action_e action;
    union npl_lpts_meter_table_payloads_t {
        npl_counter_ptr_t counter_ptr;
    } payloads;
    std::string npl_action_enum_to_string(const npl_lpts_meter_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_LPTS_METER_TABLE_ACTION_WRITE:
            {
                return "NPL_LPTS_METER_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_lpts_meter_table_action_e");
        }
        return "";
    }
    npl_lpts_meter_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_lpts_meter_table_value_t element);
std::string to_short_string(struct npl_lpts_meter_table_value_t element);

/// API-s for table: lpts_og_application_table

typedef enum
{
    NPL_LPTS_OG_APPLICATION_TABLE_ACTION_WRITE = 0x0
} npl_lpts_og_application_table_action_e;

struct npl_lpts_og_application_table_key_t
{
    uint64_t ip_version : 1;
    uint64_t ipv4_l4_protocol : 8;
    uint64_t ipv6_l4_protocol : 8;
    npl_l4_ports_header_t l4_ports;
    uint64_t fragmented : 1;
    npl_l3_relay_id_t l3_relay_id;
    
    npl_lpts_og_application_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_lpts_og_application_table_key_t element);
std::string to_short_string(struct npl_lpts_og_application_table_key_t element);

struct npl_lpts_og_application_table_value_t
{
    npl_lpts_og_application_table_action_e action;
    union npl_lpts_og_application_table_payloads_t {
        npl_ingress_lpts_og_app_config_t og_app_config;
    } payloads;
    std::string npl_action_enum_to_string(const npl_lpts_og_application_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_LPTS_OG_APPLICATION_TABLE_ACTION_WRITE:
            {
                return "NPL_LPTS_OG_APPLICATION_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_lpts_og_application_table_action_e");
        }
        return "";
    }
    npl_lpts_og_application_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_lpts_og_application_table_value_t element);
std::string to_short_string(struct npl_lpts_og_application_table_value_t element);

/// API-s for table: lr_filter_write_ptr_reg

typedef enum
{
    NPL_LR_FILTER_WRITE_PTR_REG_ACTION_WRITE = 0x0
} npl_lr_filter_write_ptr_reg_action_e;

struct npl_lr_filter_write_ptr_reg_key_t
{
    
    
    npl_lr_filter_write_ptr_reg_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_lr_filter_write_ptr_reg_key_t element);
std::string to_short_string(struct npl_lr_filter_write_ptr_reg_key_t element);

struct npl_lr_filter_write_ptr_reg_value_t
{
    npl_lr_filter_write_ptr_reg_action_e action;
    union npl_lr_filter_write_ptr_reg_payloads_t {
        npl_lr_filter_fifo_register_t learn_record_filter_vars_write_ptr;
    } payloads;
    std::string npl_action_enum_to_string(const npl_lr_filter_write_ptr_reg_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_LR_FILTER_WRITE_PTR_REG_ACTION_WRITE:
            {
                return "NPL_LR_FILTER_WRITE_PTR_REG_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_lr_filter_write_ptr_reg_action_e");
        }
        return "";
    }
    npl_lr_filter_write_ptr_reg_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_lr_filter_write_ptr_reg_value_t element);
std::string to_short_string(struct npl_lr_filter_write_ptr_reg_value_t element);

/// API-s for table: lr_write_ptr_reg

typedef enum
{
    NPL_LR_WRITE_PTR_REG_ACTION_WRITE = 0x0
} npl_lr_write_ptr_reg_action_e;

struct npl_lr_write_ptr_reg_key_t
{
    
    
    npl_lr_write_ptr_reg_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_lr_write_ptr_reg_key_t element);
std::string to_short_string(struct npl_lr_write_ptr_reg_key_t element);

struct npl_lr_write_ptr_reg_value_t
{
    npl_lr_write_ptr_reg_action_e action;
    union npl_lr_write_ptr_reg_payloads_t {
        npl_lr_fifo_register_t learn_record_fifo_vars_write_ptr;
    } payloads;
    std::string npl_action_enum_to_string(const npl_lr_write_ptr_reg_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_LR_WRITE_PTR_REG_ACTION_WRITE:
            {
                return "NPL_LR_WRITE_PTR_REG_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_lr_write_ptr_reg_action_e");
        }
        return "";
    }
    npl_lr_write_ptr_reg_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_lr_write_ptr_reg_value_t element);
std::string to_short_string(struct npl_lr_write_ptr_reg_value_t element);

/// API-s for table: mac_af_npp_attributes_table

typedef enum
{
    NPL_MAC_AF_NPP_ATTRIBUTES_TABLE_ACTION_WRITE = 0x0
} npl_mac_af_npp_attributes_table_action_e;

struct npl_mac_af_npp_attributes_table_key_t
{
    uint64_t npp_attributes_index : 8;
    
    npl_mac_af_npp_attributes_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mac_af_npp_attributes_table_key_t element);
std::string to_short_string(struct npl_mac_af_npp_attributes_table_key_t element);

struct npl_mac_af_npp_attributes_table_value_t
{
    npl_mac_af_npp_attributes_table_action_e action;
    union npl_mac_af_npp_attributes_table_payloads_t {
        npl_mac_af_npp_attributes_t mac_af_npp_attributes;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mac_af_npp_attributes_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MAC_AF_NPP_ATTRIBUTES_TABLE_ACTION_WRITE:
            {
                return "NPL_MAC_AF_NPP_ATTRIBUTES_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mac_af_npp_attributes_table_action_e");
        }
        return "";
    }
    npl_mac_af_npp_attributes_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mac_af_npp_attributes_table_value_t element);
std::string to_short_string(struct npl_mac_af_npp_attributes_table_value_t element);

/// API-s for table: mac_da_table

typedef enum
{
    NPL_MAC_DA_TABLE_ACTION_WRITE = 0x0
} npl_mac_da_table_action_e;

struct npl_mac_da_table_key_t
{
    npl_mac_addr_t packet_ethernet_header_da;
    npl_protocol_type_e next_protocol_type;
    
    npl_mac_da_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mac_da_table_key_t element);
std::string to_short_string(struct npl_mac_da_table_key_t element);

struct npl_mac_da_table_value_t
{
    npl_mac_da_table_action_e action;
    union npl_mac_da_table_payloads_t {
        npl_mac_da_t mac_da;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mac_da_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MAC_DA_TABLE_ACTION_WRITE:
            {
                return "NPL_MAC_DA_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mac_da_table_action_e");
        }
        return "";
    }
    npl_mac_da_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mac_da_table_value_t element);
std::string to_short_string(struct npl_mac_da_table_value_t element);

/// API-s for table: mac_ethernet_rate_limit_type_static_table

typedef enum
{
    NPL_MAC_ETHERNET_RATE_LIMIT_TYPE_STATIC_TABLE_ACTION_UPDATE_ETHERNET_RATE_LIMIT_TYPE = 0x0
} npl_mac_ethernet_rate_limit_type_static_table_action_e;

struct npl_mac_ethernet_rate_limit_type_static_table_update_ethernet_rate_limit_type_payload_t
{
    npl_ethernet_rate_limiter_type_e ethernet_rate_limiter_type;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_mac_ethernet_rate_limit_type_static_table_update_ethernet_rate_limit_type_payload_t element);
std::string to_short_string(npl_mac_ethernet_rate_limit_type_static_table_update_ethernet_rate_limit_type_payload_t element);

struct npl_mac_ethernet_rate_limit_type_static_table_key_t
{
    uint64_t is_bc : 1;
    uint64_t is_mc : 1;
    uint64_t mac_forwarding_hit : 1;
    
    npl_mac_ethernet_rate_limit_type_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mac_ethernet_rate_limit_type_static_table_key_t element);
std::string to_short_string(struct npl_mac_ethernet_rate_limit_type_static_table_key_t element);

struct npl_mac_ethernet_rate_limit_type_static_table_value_t
{
    npl_mac_ethernet_rate_limit_type_static_table_action_e action;
    union npl_mac_ethernet_rate_limit_type_static_table_payloads_t {
        npl_mac_ethernet_rate_limit_type_static_table_update_ethernet_rate_limit_type_payload_t update_ethernet_rate_limit_type;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mac_ethernet_rate_limit_type_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MAC_ETHERNET_RATE_LIMIT_TYPE_STATIC_TABLE_ACTION_UPDATE_ETHERNET_RATE_LIMIT_TYPE:
            {
                return "NPL_MAC_ETHERNET_RATE_LIMIT_TYPE_STATIC_TABLE_ACTION_UPDATE_ETHERNET_RATE_LIMIT_TYPE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mac_ethernet_rate_limit_type_static_table_action_e");
        }
        return "";
    }
    npl_mac_ethernet_rate_limit_type_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mac_ethernet_rate_limit_type_static_table_value_t element);
std::string to_short_string(struct npl_mac_ethernet_rate_limit_type_static_table_value_t element);

/// API-s for table: mac_forwarding_table

typedef enum
{
    NPL_MAC_FORWARDING_TABLE_ACTION_WRITE = 0x0
} npl_mac_forwarding_table_action_e;

struct npl_mac_forwarding_table_key_t
{
    npl_mac_forwarding_key_t mac_forwarding_key;
    
    npl_mac_forwarding_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mac_forwarding_table_key_t element);
std::string to_short_string(struct npl_mac_forwarding_table_key_t element);

struct npl_mac_forwarding_table_value_t
{
    npl_mac_forwarding_table_action_e action;
    union npl_mac_forwarding_table_payloads_t {
        npl_mact_result_t mact_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mac_forwarding_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MAC_FORWARDING_TABLE_ACTION_WRITE:
            {
                return "NPL_MAC_FORWARDING_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mac_forwarding_table_action_e");
        }
        return "";
    }
    npl_mac_forwarding_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mac_forwarding_table_value_t element);
std::string to_short_string(struct npl_mac_forwarding_table_value_t element);

/// API-s for table: mac_mc_em_termination_attributes_table

typedef enum
{
    NPL_MAC_MC_EM_TERMINATION_ATTRIBUTES_TABLE_ACTION_WRITE = 0x0
} npl_mac_mc_em_termination_attributes_table_action_e;

struct npl_mac_mc_em_termination_attributes_table_key_t
{
    uint64_t l2_relay_attributes_id : 14;
    
    npl_mac_mc_em_termination_attributes_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mac_mc_em_termination_attributes_table_key_t element);
std::string to_short_string(struct npl_mac_mc_em_termination_attributes_table_key_t element);

struct npl_mac_mc_em_termination_attributes_table_value_t
{
    npl_mac_mc_em_termination_attributes_table_action_e action;
    union npl_mac_mc_em_termination_attributes_table_payloads_t {
        npl_base_l3_lp_attr_union_t termination_attributes;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mac_mc_em_termination_attributes_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MAC_MC_EM_TERMINATION_ATTRIBUTES_TABLE_ACTION_WRITE:
            {
                return "NPL_MAC_MC_EM_TERMINATION_ATTRIBUTES_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mac_mc_em_termination_attributes_table_action_e");
        }
        return "";
    }
    npl_mac_mc_em_termination_attributes_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mac_mc_em_termination_attributes_table_value_t element);
std::string to_short_string(struct npl_mac_mc_em_termination_attributes_table_value_t element);

/// API-s for table: mac_mc_tcam_termination_attributes_table

typedef enum
{
    NPL_MAC_MC_TCAM_TERMINATION_ATTRIBUTES_TABLE_ACTION_WRITE = 0x0
} npl_mac_mc_tcam_termination_attributes_table_action_e;

struct npl_mac_mc_tcam_termination_attributes_table_key_t
{
    uint64_t l2_relay_attributes_id : 14;
    
    npl_mac_mc_tcam_termination_attributes_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mac_mc_tcam_termination_attributes_table_key_t element);
std::string to_short_string(struct npl_mac_mc_tcam_termination_attributes_table_key_t element);

struct npl_mac_mc_tcam_termination_attributes_table_value_t
{
    npl_mac_mc_tcam_termination_attributes_table_action_e action;
    union npl_mac_mc_tcam_termination_attributes_table_payloads_t {
        npl_base_l3_lp_attr_union_t termination_attributes;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mac_mc_tcam_termination_attributes_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MAC_MC_TCAM_TERMINATION_ATTRIBUTES_TABLE_ACTION_WRITE:
            {
                return "NPL_MAC_MC_TCAM_TERMINATION_ATTRIBUTES_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mac_mc_tcam_termination_attributes_table_action_e");
        }
        return "";
    }
    npl_mac_mc_tcam_termination_attributes_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mac_mc_tcam_termination_attributes_table_value_t element);
std::string to_short_string(struct npl_mac_mc_tcam_termination_attributes_table_value_t element);

/// API-s for table: mac_qos_mapping_table

typedef enum
{
    NPL_MAC_QOS_MAPPING_TABLE_ACTION_WRITE = 0x0
} npl_mac_qos_mapping_table_action_e;

struct npl_mac_qos_mapping_table_key_t
{
    uint64_t qos_key : 4;
    uint64_t qos_id : 4;
    
    npl_mac_qos_mapping_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mac_qos_mapping_table_key_t element);
std::string to_short_string(struct npl_mac_qos_mapping_table_key_t element);

struct npl_mac_qos_mapping_table_value_t
{
    npl_mac_qos_mapping_table_action_e action;
    union npl_mac_qos_mapping_table_payloads_t {
        npl_ingress_qos_acl_result_t ingress_mac_qos_mapping_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mac_qos_mapping_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MAC_QOS_MAPPING_TABLE_ACTION_WRITE:
            {
                return "NPL_MAC_QOS_MAPPING_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mac_qos_mapping_table_action_e");
        }
        return "";
    }
    npl_mac_qos_mapping_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mac_qos_mapping_table_value_t element);
std::string to_short_string(struct npl_mac_qos_mapping_table_value_t element);

/// API-s for table: mac_relay_g_ipv4_table

typedef enum
{
    NPL_MAC_RELAY_G_IPV4_TABLE_ACTION_WRITE = 0x0
} npl_mac_relay_g_ipv4_table_action_e;

struct npl_mac_relay_g_ipv4_table_key_t
{
    npl_l2_relay_id_t relay_id;
    uint64_t dip_27_0 : 28;
    
    npl_mac_relay_g_ipv4_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mac_relay_g_ipv4_table_key_t element);
std::string to_short_string(struct npl_mac_relay_g_ipv4_table_key_t element);

struct npl_mac_relay_g_ipv4_table_value_t
{
    npl_mac_relay_g_ipv4_table_action_e action;
    union npl_mac_relay_g_ipv4_table_payloads_t {
        npl_mac_relay_g_destination_t mac_relay_g_destination;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mac_relay_g_ipv4_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MAC_RELAY_G_IPV4_TABLE_ACTION_WRITE:
            {
                return "NPL_MAC_RELAY_G_IPV4_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mac_relay_g_ipv4_table_action_e");
        }
        return "";
    }
    npl_mac_relay_g_ipv4_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mac_relay_g_ipv4_table_value_t element);
std::string to_short_string(struct npl_mac_relay_g_ipv4_table_value_t element);

/// API-s for table: mac_relay_g_ipv6_table

typedef enum
{
    NPL_MAC_RELAY_G_IPV6_TABLE_ACTION_WRITE = 0x0
} npl_mac_relay_g_ipv6_table_action_e;

struct npl_mac_relay_g_ipv6_table_key_t
{
    npl_l2_relay_id_t relay_id;
    uint64_t dip_119_0[2];
    
    npl_mac_relay_g_ipv6_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mac_relay_g_ipv6_table_key_t element);
std::string to_short_string(struct npl_mac_relay_g_ipv6_table_key_t element);

struct npl_mac_relay_g_ipv6_table_value_t
{
    npl_mac_relay_g_ipv6_table_action_e action;
    union npl_mac_relay_g_ipv6_table_payloads_t {
        npl_mac_relay_g_destination_t mac_relay_g_destination;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mac_relay_g_ipv6_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MAC_RELAY_G_IPV6_TABLE_ACTION_WRITE:
            {
                return "NPL_MAC_RELAY_G_IPV6_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mac_relay_g_ipv6_table_action_e");
        }
        return "";
    }
    npl_mac_relay_g_ipv6_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mac_relay_g_ipv6_table_value_t element);
std::string to_short_string(struct npl_mac_relay_g_ipv6_table_value_t element);

/// API-s for table: mac_relay_to_vni_table

typedef enum
{
    NPL_MAC_RELAY_TO_VNI_TABLE_ACTION_WRITE = 0x0
} npl_mac_relay_to_vni_table_action_e;

struct npl_mac_relay_to_vni_table_key_t
{
    npl_l2_relay_id_t l2_relay_id;
    
    npl_mac_relay_to_vni_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mac_relay_to_vni_table_key_t element);
std::string to_short_string(struct npl_mac_relay_to_vni_table_key_t element);

struct npl_mac_relay_to_vni_table_value_t
{
    npl_mac_relay_to_vni_table_action_e action;
    union npl_mac_relay_to_vni_table_payloads_t {
        npl_vxlan_relay_encap_data_t vxlan_relay_encap_data;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mac_relay_to_vni_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MAC_RELAY_TO_VNI_TABLE_ACTION_WRITE:
            {
                return "NPL_MAC_RELAY_TO_VNI_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mac_relay_to_vni_table_action_e");
        }
        return "";
    }
    npl_mac_relay_to_vni_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mac_relay_to_vni_table_value_t element);
std::string to_short_string(struct npl_mac_relay_to_vni_table_value_t element);

/// API-s for table: mac_termination_em_table

typedef enum
{
    NPL_MAC_TERMINATION_EM_TABLE_ACTION_WRITE = 0x0
} npl_mac_termination_em_table_action_e;

struct npl_mac_termination_em_table_key_t
{
    npl_relay_id_t relay_id;
    uint64_t ethernet_header_da_18_0_ : 19;
    uint64_t da_prefix : 5;
    
    npl_mac_termination_em_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mac_termination_em_table_key_t element);
std::string to_short_string(struct npl_mac_termination_em_table_key_t element);

struct npl_mac_termination_em_table_value_t
{
    npl_mac_termination_em_table_action_e action;
    union npl_mac_termination_em_table_payloads_t {
        npl_base_l3_lp_attr_union_t termination_attributes;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mac_termination_em_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MAC_TERMINATION_EM_TABLE_ACTION_WRITE:
            {
                return "NPL_MAC_TERMINATION_EM_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mac_termination_em_table_action_e");
        }
        return "";
    }
    npl_mac_termination_em_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mac_termination_em_table_value_t element);
std::string to_short_string(struct npl_mac_termination_em_table_value_t element);

/// API-s for table: mac_termination_next_macro_static_table

typedef enum
{
    NPL_MAC_TERMINATION_NEXT_MACRO_STATIC_TABLE_ACTION_MAC_TERMINATION_NEXT_MACRO_ACTION = 0x0
} npl_mac_termination_next_macro_static_table_action_e;

struct npl_mac_termination_next_macro_static_table_mac_termination_next_macro_action_payload_t
{
    uint64_t pl_inc : 2;
    uint64_t macro_id : 8;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_mac_termination_next_macro_static_table_mac_termination_next_macro_action_payload_t element);
std::string to_short_string(npl_mac_termination_next_macro_static_table_mac_termination_next_macro_action_payload_t element);

struct npl_mac_termination_next_macro_static_table_key_t
{
    npl_protocol_type_e next_proto_type;
    npl_l2_lp_type_e l2_lp_type;
    npl_ipv4_ipv6_init_rtf_stage_t ipv4_ipv6_init_rtf_stage;
    
    npl_mac_termination_next_macro_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mac_termination_next_macro_static_table_key_t element);
std::string to_short_string(struct npl_mac_termination_next_macro_static_table_key_t element);

struct npl_mac_termination_next_macro_static_table_value_t
{
    npl_mac_termination_next_macro_static_table_action_e action;
    union npl_mac_termination_next_macro_static_table_payloads_t {
        npl_mac_termination_next_macro_static_table_mac_termination_next_macro_action_payload_t mac_termination_next_macro_action;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mac_termination_next_macro_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MAC_TERMINATION_NEXT_MACRO_STATIC_TABLE_ACTION_MAC_TERMINATION_NEXT_MACRO_ACTION:
            {
                return "NPL_MAC_TERMINATION_NEXT_MACRO_STATIC_TABLE_ACTION_MAC_TERMINATION_NEXT_MACRO_ACTION(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mac_termination_next_macro_static_table_action_e");
        }
        return "";
    }
    npl_mac_termination_next_macro_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mac_termination_next_macro_static_table_value_t element);
std::string to_short_string(struct npl_mac_termination_next_macro_static_table_value_t element);

/// API-s for table: mac_termination_no_da_em_table

typedef enum
{
    NPL_MAC_TERMINATION_NO_DA_EM_TABLE_ACTION_WRITE = 0x0
} npl_mac_termination_no_da_em_table_action_e;

struct npl_mac_termination_no_da_em_table_key_t
{
    npl_relay_id_t service_relay_attributes_table_key;
    
    npl_mac_termination_no_da_em_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mac_termination_no_da_em_table_key_t element);
std::string to_short_string(struct npl_mac_termination_no_da_em_table_key_t element);

struct npl_mac_termination_no_da_em_table_value_t
{
    npl_mac_termination_no_da_em_table_action_e action;
    union npl_mac_termination_no_da_em_table_payloads_t {
        npl_base_l3_lp_attr_union_t termination_attributes;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mac_termination_no_da_em_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MAC_TERMINATION_NO_DA_EM_TABLE_ACTION_WRITE:
            {
                return "NPL_MAC_TERMINATION_NO_DA_EM_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mac_termination_no_da_em_table_action_e");
        }
        return "";
    }
    npl_mac_termination_no_da_em_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mac_termination_no_da_em_table_value_t element);
std::string to_short_string(struct npl_mac_termination_no_da_em_table_value_t element);

/// API-s for table: mac_termination_tcam_table

typedef enum
{
    NPL_MAC_TERMINATION_TCAM_TABLE_ACTION_WRITE = 0x0
} npl_mac_termination_tcam_table_action_e;

struct npl_mac_termination_tcam_table_key_t
{
    npl_relay_id_t service_relay_attributes_table_key;
    uint64_t ethernet_header_da_18_0_ : 19;
    uint64_t da_prefix : 5;
    
    npl_mac_termination_tcam_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mac_termination_tcam_table_key_t element);
std::string to_short_string(struct npl_mac_termination_tcam_table_key_t element);

struct npl_mac_termination_tcam_table_value_t
{
    npl_mac_termination_tcam_table_action_e action;
    union npl_mac_termination_tcam_table_payloads_t {
        npl_base_l3_lp_attr_union_t termination_attributes;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mac_termination_tcam_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MAC_TERMINATION_TCAM_TABLE_ACTION_WRITE:
            {
                return "NPL_MAC_TERMINATION_TCAM_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mac_termination_tcam_table_action_e");
        }
        return "";
    }
    npl_mac_termination_tcam_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mac_termination_tcam_table_value_t element);
std::string to_short_string(struct npl_mac_termination_tcam_table_value_t element);

/// API-s for table: map_ene_subcode_to8bit_static_table

typedef enum
{
    NPL_MAP_ENE_SUBCODE_TO8BIT_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_map_ene_subcode_to8bit_static_table_action_e;

struct npl_map_ene_subcode_to8bit_static_table_key_t
{
    uint64_t tx_npu_header_ingress_punt_encap_data_mirror_local_encap_format : 1;
    npl_lpts_flow_type_t tx_npu_header_encap_punt_mc_expand_encap_lpts_flow_type;
    
    npl_map_ene_subcode_to8bit_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_map_ene_subcode_to8bit_static_table_key_t element);
std::string to_short_string(struct npl_map_ene_subcode_to8bit_static_table_key_t element);

struct npl_map_ene_subcode_to8bit_static_table_value_t
{
    npl_map_ene_subcode_to8bit_static_table_action_e action;
    union npl_map_ene_subcode_to8bit_static_table_payloads_t {
        uint64_t tx_punt_local_var_local_ene_punt_sub_code : 8;
    } payloads;
    std::string npl_action_enum_to_string(const npl_map_ene_subcode_to8bit_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MAP_ENE_SUBCODE_TO8BIT_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_MAP_ENE_SUBCODE_TO8BIT_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_map_ene_subcode_to8bit_static_table_action_e");
        }
        return "";
    }
    npl_map_ene_subcode_to8bit_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_map_ene_subcode_to8bit_static_table_value_t element);
std::string to_short_string(struct npl_map_ene_subcode_to8bit_static_table_value_t element);

/// API-s for table: map_inject_ccm_macro_static_table

typedef enum
{
    NPL_MAP_INJECT_CCM_MACRO_STATIC_TABLE_ACTION_MAP_INJECT_CCM_MACRO = 0x0
} npl_map_inject_ccm_macro_static_table_action_e;

struct npl_map_inject_ccm_macro_static_table_map_inject_ccm_macro_payload_t
{
    npl_ene_macro_ids_e next_macro;
    npl_ene_macro_id_t second_ene_macro;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_map_inject_ccm_macro_static_table_map_inject_ccm_macro_payload_t element);
std::string to_short_string(npl_map_inject_ccm_macro_static_table_map_inject_ccm_macro_payload_t element);

struct npl_map_inject_ccm_macro_static_table_key_t
{
    uint64_t outer_tpid_ptr : 4;
    uint64_t inner_tpid_ptr : 4;
    
    npl_map_inject_ccm_macro_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_map_inject_ccm_macro_static_table_key_t element);
std::string to_short_string(struct npl_map_inject_ccm_macro_static_table_key_t element);

struct npl_map_inject_ccm_macro_static_table_value_t
{
    npl_map_inject_ccm_macro_static_table_action_e action;
    union npl_map_inject_ccm_macro_static_table_payloads_t {
        npl_map_inject_ccm_macro_static_table_map_inject_ccm_macro_payload_t map_inject_ccm_macro;
    } payloads;
    std::string npl_action_enum_to_string(const npl_map_inject_ccm_macro_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MAP_INJECT_CCM_MACRO_STATIC_TABLE_ACTION_MAP_INJECT_CCM_MACRO:
            {
                return "NPL_MAP_INJECT_CCM_MACRO_STATIC_TABLE_ACTION_MAP_INJECT_CCM_MACRO(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_map_inject_ccm_macro_static_table_action_e");
        }
        return "";
    }
    npl_map_inject_ccm_macro_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_map_inject_ccm_macro_static_table_value_t element);
std::string to_short_string(struct npl_map_inject_ccm_macro_static_table_value_t element);

/// API-s for table: map_more_labels_static_table

typedef enum
{
    NPL_MAP_MORE_LABELS_STATIC_TABLE_ACTION_SET_VALUE = 0x0
} npl_map_more_labels_static_table_action_e;

struct npl_map_more_labels_static_table_set_value_payload_t
{
    npl_additional_mpls_labels_offset_t more_labels_offset;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_map_more_labels_static_table_set_value_payload_t element);
std::string to_short_string(npl_map_more_labels_static_table_set_value_payload_t element);

struct npl_map_more_labels_static_table_key_t
{
    uint64_t num_labels_is_8 : 1;
    uint64_t num_labels : 3;
    
    npl_map_more_labels_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_map_more_labels_static_table_key_t element);
std::string to_short_string(struct npl_map_more_labels_static_table_key_t element);

struct npl_map_more_labels_static_table_value_t
{
    npl_map_more_labels_static_table_action_e action;
    union npl_map_more_labels_static_table_payloads_t {
        npl_map_more_labels_static_table_set_value_payload_t set_value;
    } payloads;
    std::string npl_action_enum_to_string(const npl_map_more_labels_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MAP_MORE_LABELS_STATIC_TABLE_ACTION_SET_VALUE:
            {
                return "NPL_MAP_MORE_LABELS_STATIC_TABLE_ACTION_SET_VALUE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_map_more_labels_static_table_action_e");
        }
        return "";
    }
    npl_map_more_labels_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_map_more_labels_static_table_value_t element);
std::string to_short_string(struct npl_map_more_labels_static_table_value_t element);

/// API-s for table: map_recyle_tx_to_rx_data_on_pd_static_table

typedef enum
{
    NPL_MAP_RECYLE_TX_TO_RX_DATA_ON_PD_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_map_recyle_tx_to_rx_data_on_pd_static_table_action_e;

struct npl_map_recyle_tx_to_rx_data_on_pd_static_table_key_t
{
    npl_dsp_map_info_t dsp_map_dma_info;
    
    npl_map_recyle_tx_to_rx_data_on_pd_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_map_recyle_tx_to_rx_data_on_pd_static_table_key_t element);
std::string to_short_string(struct npl_map_recyle_tx_to_rx_data_on_pd_static_table_key_t element);

struct npl_map_recyle_tx_to_rx_data_on_pd_static_table_value_t
{
    npl_map_recyle_tx_to_rx_data_on_pd_static_table_action_e action;
    union npl_map_recyle_tx_to_rx_data_on_pd_static_table_payloads_t {
        npl_snoop_or_rcy_data_t pd_recycle_data;
    } payloads;
    std::string npl_action_enum_to_string(const npl_map_recyle_tx_to_rx_data_on_pd_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MAP_RECYLE_TX_TO_RX_DATA_ON_PD_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_MAP_RECYLE_TX_TO_RX_DATA_ON_PD_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_map_recyle_tx_to_rx_data_on_pd_static_table_action_e");
        }
        return "";
    }
    npl_map_recyle_tx_to_rx_data_on_pd_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_map_recyle_tx_to_rx_data_on_pd_static_table_value_t element);
std::string to_short_string(struct npl_map_recyle_tx_to_rx_data_on_pd_static_table_value_t element);

/// API-s for table: map_tm_dp_ecn_to_wa_ecn_dp_static_table

typedef enum
{
    NPL_MAP_TM_DP_ECN_TO_WA_ECN_DP_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_action_e;

struct npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_key_t
{
    uint64_t tm_h_ecn : 1;
    uint64_t tm_h_dp_0 : 1;
    
    npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_key_t element);
std::string to_short_string(struct npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_key_t element);

struct npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_value_t
{
    npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_action_e action;
    union npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_payloads_t {
        uint64_t dp_ecn_wa_local_var_new_dp : 2;
    } payloads;
    std::string npl_action_enum_to_string(const npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MAP_TM_DP_ECN_TO_WA_ECN_DP_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_MAP_TM_DP_ECN_TO_WA_ECN_DP_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_action_e");
        }
        return "";
    }
    npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_value_t element);
std::string to_short_string(struct npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_value_t element);

/// API-s for table: map_tx_punt_next_macro_static_table

typedef enum
{
    NPL_MAP_TX_PUNT_NEXT_MACRO_STATIC_TABLE_ACTION_TX_PUNT_NEXT_MACRO = 0x0
} npl_map_tx_punt_next_macro_static_table_action_e;

struct npl_map_tx_punt_next_macro_static_table_tx_punt_next_macro_payload_t
{
    uint64_t ene_bytes_added : 7;
    uint64_t pl_inc : 2;
    npl_ene_macro_id_t macro_id;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_map_tx_punt_next_macro_static_table_tx_punt_next_macro_payload_t element);
std::string to_short_string(npl_map_tx_punt_next_macro_static_table_tx_punt_next_macro_payload_t element);

struct npl_map_tx_punt_next_macro_static_table_key_t
{
    npl_punt_cud_type_e cud_type;
    npl_punt_nw_encap_type_e punt_encap_type;
    npl_punt_header_format_type_e punt_format;
    
    npl_map_tx_punt_next_macro_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_map_tx_punt_next_macro_static_table_key_t element);
std::string to_short_string(struct npl_map_tx_punt_next_macro_static_table_key_t element);

struct npl_map_tx_punt_next_macro_static_table_value_t
{
    npl_map_tx_punt_next_macro_static_table_action_e action;
    union npl_map_tx_punt_next_macro_static_table_payloads_t {
        npl_map_tx_punt_next_macro_static_table_tx_punt_next_macro_payload_t tx_punt_next_macro;
    } payloads;
    std::string npl_action_enum_to_string(const npl_map_tx_punt_next_macro_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MAP_TX_PUNT_NEXT_MACRO_STATIC_TABLE_ACTION_TX_PUNT_NEXT_MACRO:
            {
                return "NPL_MAP_TX_PUNT_NEXT_MACRO_STATIC_TABLE_ACTION_TX_PUNT_NEXT_MACRO(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_map_tx_punt_next_macro_static_table_action_e");
        }
        return "";
    }
    npl_map_tx_punt_next_macro_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_map_tx_punt_next_macro_static_table_value_t element);
std::string to_short_string(struct npl_map_tx_punt_next_macro_static_table_value_t element);

/// API-s for table: map_tx_punt_rcy_next_macro_static_table

typedef enum
{
    NPL_MAP_TX_PUNT_RCY_NEXT_MACRO_STATIC_TABLE_ACTION_SET_NPE_NEXT_MACRO = 0x0
} npl_map_tx_punt_rcy_next_macro_static_table_action_e;

struct npl_map_tx_punt_rcy_next_macro_static_table_set_npe_next_macro_payload_t
{
    uint64_t pl_inc : 2;
    npl_ene_macro_id_t macro_id;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_map_tx_punt_rcy_next_macro_static_table_set_npe_next_macro_payload_t element);
std::string to_short_string(npl_map_tx_punt_rcy_next_macro_static_table_set_npe_next_macro_payload_t element);

struct npl_map_tx_punt_rcy_next_macro_static_table_key_t
{
    uint64_t inject_only : 1;
    uint64_t eth_stage : 1;
    uint64_t redirect_code : 8;
    
    npl_map_tx_punt_rcy_next_macro_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_map_tx_punt_rcy_next_macro_static_table_key_t element);
std::string to_short_string(struct npl_map_tx_punt_rcy_next_macro_static_table_key_t element);

struct npl_map_tx_punt_rcy_next_macro_static_table_value_t
{
    npl_map_tx_punt_rcy_next_macro_static_table_action_e action;
    union npl_map_tx_punt_rcy_next_macro_static_table_payloads_t {
        npl_map_tx_punt_rcy_next_macro_static_table_set_npe_next_macro_payload_t set_npe_next_macro;
    } payloads;
    std::string npl_action_enum_to_string(const npl_map_tx_punt_rcy_next_macro_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MAP_TX_PUNT_RCY_NEXT_MACRO_STATIC_TABLE_ACTION_SET_NPE_NEXT_MACRO:
            {
                return "NPL_MAP_TX_PUNT_RCY_NEXT_MACRO_STATIC_TABLE_ACTION_SET_NPE_NEXT_MACRO(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_map_tx_punt_rcy_next_macro_static_table_action_e");
        }
        return "";
    }
    npl_map_tx_punt_rcy_next_macro_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_map_tx_punt_rcy_next_macro_static_table_value_t element);
std::string to_short_string(struct npl_map_tx_punt_rcy_next_macro_static_table_value_t element);

/// API-s for table: mc_bitmap_base_voq_lookup_table

typedef enum
{
    NPL_MC_BITMAP_BASE_VOQ_LOOKUP_TABLE_ACTION_WRITE = 0x0
} npl_mc_bitmap_base_voq_lookup_table_action_e;

struct npl_mc_bitmap_base_voq_lookup_table_key_t
{
    uint64_t rxpdr_local_vars_current_slice : 3;
    
    npl_mc_bitmap_base_voq_lookup_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mc_bitmap_base_voq_lookup_table_key_t element);
std::string to_short_string(struct npl_mc_bitmap_base_voq_lookup_table_key_t element);

struct npl_mc_bitmap_base_voq_lookup_table_value_t
{
    npl_mc_bitmap_base_voq_lookup_table_action_e action;
    union npl_mc_bitmap_base_voq_lookup_table_payloads_t {
        npl_mc_bitmap_base_voq_lookup_table_result_t mc_bitmap_base_voq_lookup_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mc_bitmap_base_voq_lookup_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MC_BITMAP_BASE_VOQ_LOOKUP_TABLE_ACTION_WRITE:
            {
                return "NPL_MC_BITMAP_BASE_VOQ_LOOKUP_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mc_bitmap_base_voq_lookup_table_action_e");
        }
        return "";
    }
    npl_mc_bitmap_base_voq_lookup_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mc_bitmap_base_voq_lookup_table_value_t element);
std::string to_short_string(struct npl_mc_bitmap_base_voq_lookup_table_value_t element);

/// API-s for table: mc_bitmap_tc_map_table

typedef enum
{
    NPL_MC_BITMAP_TC_MAP_TABLE_ACTION_WRITE = 0x0
} npl_mc_bitmap_tc_map_table_action_e;

struct npl_mc_bitmap_tc_map_table_key_t
{
    uint64_t mc_bitmap_base_voq_lookup_table_result_tc_map_profile : 2;
    uint64_t rxpp_pd_tc : 3;
    
    npl_mc_bitmap_tc_map_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mc_bitmap_tc_map_table_key_t element);
std::string to_short_string(struct npl_mc_bitmap_tc_map_table_key_t element);

struct npl_mc_bitmap_tc_map_table_value_t
{
    npl_mc_bitmap_tc_map_table_action_e action;
    union npl_mc_bitmap_tc_map_table_payloads_t {
        uint64_t rxpdr_local_vars_tc_offset : 3;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mc_bitmap_tc_map_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MC_BITMAP_TC_MAP_TABLE_ACTION_WRITE:
            {
                return "NPL_MC_BITMAP_TC_MAP_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mc_bitmap_tc_map_table_action_e");
        }
        return "";
    }
    npl_mc_bitmap_tc_map_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mc_bitmap_tc_map_table_value_t element);
std::string to_short_string(struct npl_mc_bitmap_tc_map_table_value_t element);

/// API-s for table: mc_copy_id_map

typedef enum
{
    NPL_MC_COPY_ID_MAP_ACTION_UPDATE = 0x0
} npl_mc_copy_id_map_action_e;

struct npl_mc_copy_id_map_update_payload_t
{
    npl_cud_encap_size_e encap_size;
    uint64_t mc_copy_id_msbs : 8;
    uint64_t encap_type : 4;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_mc_copy_id_map_update_payload_t element);
std::string to_short_string(npl_mc_copy_id_map_update_payload_t element);

struct npl_mc_copy_id_map_key_t
{
    uint64_t cud_mapping_local_vars_mc_copy_id_17_12_ : 6;
    
    npl_mc_copy_id_map_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mc_copy_id_map_key_t element);
std::string to_short_string(struct npl_mc_copy_id_map_key_t element);

struct npl_mc_copy_id_map_value_t
{
    npl_mc_copy_id_map_action_e action;
    union npl_mc_copy_id_map_payloads_t {
        npl_mc_copy_id_map_update_payload_t update;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mc_copy_id_map_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MC_COPY_ID_MAP_ACTION_UPDATE:
            {
                return "NPL_MC_COPY_ID_MAP_ACTION_UPDATE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mc_copy_id_map_action_e");
        }
        return "";
    }
    npl_mc_copy_id_map_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mc_copy_id_map_value_t element);
std::string to_short_string(struct npl_mc_copy_id_map_value_t element);

/// API-s for table: mc_cud_is_wide_table

typedef enum
{
    NPL_MC_CUD_IS_WIDE_TABLE_ACTION_WRITE = 0x0
} npl_mc_cud_is_wide_table_action_e;

struct npl_mc_cud_is_wide_table_key_t
{
    uint64_t cud_mapping_local_vars_mc_copy_id_12_7_ : 6;
    
    npl_mc_cud_is_wide_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mc_cud_is_wide_table_key_t element);
std::string to_short_string(struct npl_mc_cud_is_wide_table_key_t element);

struct npl_mc_cud_is_wide_table_value_t
{
    npl_mc_cud_is_wide_table_action_e action;
    union npl_mc_cud_is_wide_table_payloads_t {
        uint64_t cud_mapping_local_vars_mc_cud_is_wide : 1;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mc_cud_is_wide_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MC_CUD_IS_WIDE_TABLE_ACTION_WRITE:
            {
                return "NPL_MC_CUD_IS_WIDE_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mc_cud_is_wide_table_action_e");
        }
        return "";
    }
    npl_mc_cud_is_wide_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mc_cud_is_wide_table_value_t element);
std::string to_short_string(struct npl_mc_cud_is_wide_table_value_t element);

/// API-s for table: mc_em_db

typedef enum
{
    NPL_MC_EM_DB_ACTION_WRITE = 0x0
} npl_mc_em_db_action_e;

struct npl_mc_em_db_key_t
{
    npl_mc_em_db__key_t mc_em_db_key;
    
    npl_mc_em_db_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mc_em_db_key_t element);
std::string to_short_string(struct npl_mc_em_db_key_t element);

struct npl_mc_em_db_value_t
{
    npl_mc_em_db_action_e action;
    union npl_mc_em_db_payloads_t {
        npl_mc_em_db_result_t mc_em_db_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mc_em_db_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MC_EM_DB_ACTION_WRITE:
            {
                return "NPL_MC_EM_DB_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mc_em_db_action_e");
        }
        return "";
    }
    npl_mc_em_db_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mc_em_db_value_t element);
std::string to_short_string(struct npl_mc_em_db_value_t element);

/// API-s for table: mc_emdb_tc_map_table

typedef enum
{
    NPL_MC_EMDB_TC_MAP_TABLE_ACTION_WRITE = 0x0
} npl_mc_emdb_tc_map_table_action_e;

struct npl_mc_emdb_tc_map_table_key_t
{
    uint64_t rxpdr_local_vars_tc_map_profile_1_0_ : 2;
    uint64_t rxpp_pd_tc : 3;
    
    npl_mc_emdb_tc_map_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mc_emdb_tc_map_table_key_t element);
std::string to_short_string(struct npl_mc_emdb_tc_map_table_key_t element);

struct npl_mc_emdb_tc_map_table_value_t
{
    npl_mc_emdb_tc_map_table_action_e action;
    union npl_mc_emdb_tc_map_table_payloads_t {
        uint64_t rxpdr_local_vars_tc_offset : 3;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mc_emdb_tc_map_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MC_EMDB_TC_MAP_TABLE_ACTION_WRITE:
            {
                return "NPL_MC_EMDB_TC_MAP_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mc_emdb_tc_map_table_action_e");
        }
        return "";
    }
    npl_mc_emdb_tc_map_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mc_emdb_tc_map_table_value_t element);
std::string to_short_string(struct npl_mc_emdb_tc_map_table_value_t element);

/// API-s for table: mc_fe_links_bmp

typedef enum
{
    NPL_MC_FE_LINKS_BMP_ACTION_WRITE = 0x0
} npl_mc_fe_links_bmp_action_e;

struct npl_mc_fe_links_bmp_key_t
{
    uint64_t rxpp_pd_fwd_destination_15_0_ : 16;
    
    npl_mc_fe_links_bmp_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mc_fe_links_bmp_key_t element);
std::string to_short_string(struct npl_mc_fe_links_bmp_key_t element);

struct npl_mc_fe_links_bmp_value_t
{
    npl_mc_fe_links_bmp_action_e action;
    union npl_mc_fe_links_bmp_payloads_t {
        npl_mc_fe_links_bmp_db_result_t mc_fe_links_bmp_db_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mc_fe_links_bmp_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MC_FE_LINKS_BMP_ACTION_WRITE:
            {
                return "NPL_MC_FE_LINKS_BMP_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mc_fe_links_bmp_action_e");
        }
        return "";
    }
    npl_mc_fe_links_bmp_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mc_fe_links_bmp_value_t element);
std::string to_short_string(struct npl_mc_fe_links_bmp_value_t element);

/// API-s for table: mc_ibm_cud_mapping_table

typedef enum
{
    NPL_MC_IBM_CUD_MAPPING_TABLE_ACTION_WRITE = 0x0
} npl_mc_ibm_cud_mapping_table_action_e;

struct npl_mc_ibm_cud_mapping_table_key_t
{
    uint64_t ibm_mc_cud_key : 9;
    
    npl_mc_ibm_cud_mapping_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mc_ibm_cud_mapping_table_key_t element);
std::string to_short_string(struct npl_mc_ibm_cud_mapping_table_key_t element);

struct npl_mc_ibm_cud_mapping_table_value_t
{
    npl_mc_ibm_cud_mapping_table_action_e action;
    union npl_mc_ibm_cud_mapping_table_payloads_t {
        npl_ibm_encap_header_on_direct_t mc_ibm_cud_mapping_encap;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mc_ibm_cud_mapping_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MC_IBM_CUD_MAPPING_TABLE_ACTION_WRITE:
            {
                return "NPL_MC_IBM_CUD_MAPPING_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mc_ibm_cud_mapping_table_action_e");
        }
        return "";
    }
    npl_mc_ibm_cud_mapping_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mc_ibm_cud_mapping_table_value_t element);
std::string to_short_string(struct npl_mc_ibm_cud_mapping_table_value_t element);

/// API-s for table: mc_slice_bitmap_table

typedef enum
{
    NPL_MC_SLICE_BITMAP_TABLE_ACTION_WRITE = 0x0
} npl_mc_slice_bitmap_table_action_e;

struct npl_mc_slice_bitmap_table_key_t
{
    uint64_t rxpp_pd_fwd_destination_15_0_ : 16;
    
    npl_mc_slice_bitmap_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mc_slice_bitmap_table_key_t element);
std::string to_short_string(struct npl_mc_slice_bitmap_table_key_t element);

struct npl_mc_slice_bitmap_table_value_t
{
    npl_mc_slice_bitmap_table_action_e action;
    union npl_mc_slice_bitmap_table_payloads_t {
        npl_mc_slice_bitmap_table_entry_t mc_slice_bitmap_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mc_slice_bitmap_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MC_SLICE_BITMAP_TABLE_ACTION_WRITE:
            {
                return "NPL_MC_SLICE_BITMAP_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mc_slice_bitmap_table_action_e");
        }
        return "";
    }
    npl_mc_slice_bitmap_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mc_slice_bitmap_table_value_t element);
std::string to_short_string(struct npl_mc_slice_bitmap_table_value_t element);

/// API-s for table: meg_id_format_table

typedef enum
{
    NPL_MEG_ID_FORMAT_TABLE_ACTION_WRITE = 0x0
} npl_meg_id_format_table_action_e;

struct npl_meg_id_format_table_key_t
{
    npl_meg_id_format_e eth_oam_mp_table_read_payload_meg_id_format;
    uint64_t eth_oam_ccm_meg_id_format : 8;
    uint64_t meg_id_length : 8;
    
    npl_meg_id_format_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_meg_id_format_table_key_t element);
std::string to_short_string(struct npl_meg_id_format_table_key_t element);

struct npl_meg_id_format_table_value_t
{
    npl_meg_id_format_table_action_e action;
    union npl_meg_id_format_table_payloads_t {
        uint64_t eth_wrong_meg_id_format : 1;
    } payloads;
    std::string npl_action_enum_to_string(const npl_meg_id_format_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MEG_ID_FORMAT_TABLE_ACTION_WRITE:
            {
                return "NPL_MEG_ID_FORMAT_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_meg_id_format_table_action_e");
        }
        return "";
    }
    npl_meg_id_format_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_meg_id_format_table_value_t element);
std::string to_short_string(struct npl_meg_id_format_table_value_t element);

/// API-s for table: mep_address_prefix_table

typedef enum
{
    NPL_MEP_ADDRESS_PREFIX_TABLE_ACTION_WRITE = 0x0
} npl_mep_address_prefix_table_action_e;

struct npl_mep_address_prefix_table_key_t
{
    uint64_t mep_address_prefix_index : 2;
    
    npl_mep_address_prefix_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mep_address_prefix_table_key_t element);
std::string to_short_string(struct npl_mep_address_prefix_table_key_t element);

struct npl_mep_address_prefix_table_value_t
{
    npl_mep_address_prefix_table_action_e action;
    union npl_mep_address_prefix_table_payloads_t {
        uint64_t mep_mac_address_prefix : 32;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mep_address_prefix_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MEP_ADDRESS_PREFIX_TABLE_ACTION_WRITE:
            {
                return "NPL_MEP_ADDRESS_PREFIX_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mep_address_prefix_table_action_e");
        }
        return "";
    }
    npl_mep_address_prefix_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mep_address_prefix_table_value_t element);
std::string to_short_string(struct npl_mep_address_prefix_table_value_t element);

/// API-s for table: mii_loopback_table

typedef enum
{
    NPL_MII_LOOPBACK_TABLE_ACTION_WRITE = 0x0
} npl_mii_loopback_table_action_e;

struct npl_mii_loopback_table_key_t
{
    uint64_t device_packet_info_ifg : 1;
    uint64_t device_packet_info_pif : 5;
    
    npl_mii_loopback_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mii_loopback_table_key_t element);
std::string to_short_string(struct npl_mii_loopback_table_key_t element);

struct npl_mii_loopback_table_value_t
{
    npl_mii_loopback_table_action_e action;
    union npl_mii_loopback_table_payloads_t {
        npl_mii_loopback_data_t mii_loopback_data;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mii_loopback_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MII_LOOPBACK_TABLE_ACTION_WRITE:
            {
                return "NPL_MII_LOOPBACK_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mii_loopback_table_action_e");
        }
        return "";
    }
    npl_mii_loopback_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mii_loopback_table_value_t element);
std::string to_short_string(struct npl_mii_loopback_table_value_t element);

/// API-s for table: mirror_code_hw_table

typedef enum
{
    NPL_MIRROR_CODE_HW_TABLE_ACTION_WRITE = 0x0
} npl_mirror_code_hw_table_action_e;

struct npl_mirror_code_hw_table_key_t
{
    uint64_t pd_common_leaba_fields_mirror_code : 8;
    
    npl_mirror_code_hw_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mirror_code_hw_table_key_t element);
std::string to_short_string(struct npl_mirror_code_hw_table_key_t element);

struct npl_mirror_code_hw_table_value_t
{
    npl_mirror_code_hw_table_action_e action;
    union npl_mirror_code_hw_table_payloads_t {
        uint64_t rxpp_pd_rxn_in_mirror_cmd1 : 5;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mirror_code_hw_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MIRROR_CODE_HW_TABLE_ACTION_WRITE:
            {
                return "NPL_MIRROR_CODE_HW_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mirror_code_hw_table_action_e");
        }
        return "";
    }
    npl_mirror_code_hw_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mirror_code_hw_table_value_t element);
std::string to_short_string(struct npl_mirror_code_hw_table_value_t element);

/// API-s for table: mirror_egress_attributes_table

typedef enum
{
    NPL_MIRROR_EGRESS_ATTRIBUTES_TABLE_ACTION_SET_MIRROR_EGRESS_ATTRIBUTES = 0x0
} npl_mirror_egress_attributes_table_action_e;

struct npl_mirror_egress_attributes_table_set_mirror_egress_attributes_payload_t
{
    uint64_t session_id : 12;
    npl_counter_ptr_t counter;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_mirror_egress_attributes_table_set_mirror_egress_attributes_payload_t element);
std::string to_short_string(npl_mirror_egress_attributes_table_set_mirror_egress_attributes_payload_t element);

struct npl_mirror_egress_attributes_table_key_t
{
    npl_bool_t is_ibm;
    uint64_t mirror_code : 8;
    
    npl_mirror_egress_attributes_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mirror_egress_attributes_table_key_t element);
std::string to_short_string(struct npl_mirror_egress_attributes_table_key_t element);

struct npl_mirror_egress_attributes_table_value_t
{
    npl_mirror_egress_attributes_table_action_e action;
    union npl_mirror_egress_attributes_table_payloads_t {
        npl_mirror_egress_attributes_table_set_mirror_egress_attributes_payload_t set_mirror_egress_attributes;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mirror_egress_attributes_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MIRROR_EGRESS_ATTRIBUTES_TABLE_ACTION_SET_MIRROR_EGRESS_ATTRIBUTES:
            {
                return "NPL_MIRROR_EGRESS_ATTRIBUTES_TABLE_ACTION_SET_MIRROR_EGRESS_ATTRIBUTES(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mirror_egress_attributes_table_action_e");
        }
        return "";
    }
    npl_mirror_egress_attributes_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mirror_egress_attributes_table_value_t element);
std::string to_short_string(struct npl_mirror_egress_attributes_table_value_t element);

/// API-s for table: mirror_to_dsp_in_npu_soft_header_table

typedef enum
{
    NPL_MIRROR_TO_DSP_IN_NPU_SOFT_HEADER_TABLE_ACTION_WRITE = 0x0
} npl_mirror_to_dsp_in_npu_soft_header_table_action_e;

struct npl_mirror_to_dsp_in_npu_soft_header_table_key_t
{
    uint64_t mirror_code : 5;
    
    npl_mirror_to_dsp_in_npu_soft_header_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mirror_to_dsp_in_npu_soft_header_table_key_t element);
std::string to_short_string(struct npl_mirror_to_dsp_in_npu_soft_header_table_key_t element);

struct npl_mirror_to_dsp_in_npu_soft_header_table_value_t
{
    npl_mirror_to_dsp_in_npu_soft_header_table_action_e action;
    union npl_mirror_to_dsp_in_npu_soft_header_table_payloads_t {
        uint64_t update_dsp_in_npu_soft_header : 1;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mirror_to_dsp_in_npu_soft_header_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MIRROR_TO_DSP_IN_NPU_SOFT_HEADER_TABLE_ACTION_WRITE:
            {
                return "NPL_MIRROR_TO_DSP_IN_NPU_SOFT_HEADER_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mirror_to_dsp_in_npu_soft_header_table_action_e");
        }
        return "";
    }
    npl_mirror_to_dsp_in_npu_soft_header_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mirror_to_dsp_in_npu_soft_header_table_value_t element);
std::string to_short_string(struct npl_mirror_to_dsp_in_npu_soft_header_table_value_t element);

/// API-s for table: mldp_protection_enabled_static_table

typedef enum
{
    NPL_MLDP_PROTECTION_ENABLED_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_mldp_protection_enabled_static_table_action_e;

struct npl_mldp_protection_enabled_static_table_key_t
{
    uint64_t is_mc : 1;
    npl_npu_encap_l3_header_type_e l3_encap;
    
    npl_mldp_protection_enabled_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mldp_protection_enabled_static_table_key_t element);
std::string to_short_string(struct npl_mldp_protection_enabled_static_table_key_t element);

struct npl_mldp_protection_enabled_static_table_value_t
{
    npl_mldp_protection_enabled_static_table_action_e action;
    union npl_mldp_protection_enabled_static_table_payloads_t {
        uint64_t enabled : 1;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mldp_protection_enabled_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MLDP_PROTECTION_ENABLED_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_MLDP_PROTECTION_ENABLED_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mldp_protection_enabled_static_table_action_e");
        }
        return "";
    }
    npl_mldp_protection_enabled_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mldp_protection_enabled_static_table_value_t element);
std::string to_short_string(struct npl_mldp_protection_enabled_static_table_value_t element);

/// API-s for table: mldp_protection_table

typedef enum
{
    NPL_MLDP_PROTECTION_TABLE_ACTION_WRITE = 0x0
} npl_mldp_protection_table_action_e;

struct npl_mldp_protection_table_key_t
{
    npl_mldp_protection_id_t mlp_protection;
    
    npl_mldp_protection_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mldp_protection_table_key_t element);
std::string to_short_string(struct npl_mldp_protection_table_key_t element);

struct npl_mldp_protection_table_value_t
{
    npl_mldp_protection_table_action_e action;
    union npl_mldp_protection_table_payloads_t {
        npl_mldp_protection_entry_t mld_entry;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mldp_protection_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MLDP_PROTECTION_TABLE_ACTION_WRITE:
            {
                return "NPL_MLDP_PROTECTION_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mldp_protection_table_action_e");
        }
        return "";
    }
    npl_mldp_protection_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mldp_protection_table_value_t element);
std::string to_short_string(struct npl_mldp_protection_table_value_t element);

/// API-s for table: mp_aux_data_table

typedef enum
{
    NPL_MP_AUX_DATA_TABLE_ACTION_WRITE = 0x0
} npl_mp_aux_data_table_action_e;

struct npl_mp_aux_data_table_key_t
{
    npl_aux_table_key_t aux_table_key;
    
    npl_mp_aux_data_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mp_aux_data_table_key_t element);
std::string to_short_string(struct npl_mp_aux_data_table_key_t element);

struct npl_mp_aux_data_table_value_t
{
    npl_mp_aux_data_table_action_e action;
    union npl_mp_aux_data_table_payloads_t {
        npl_aux_table_result_t aux_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mp_aux_data_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MP_AUX_DATA_TABLE_ACTION_WRITE:
            {
                return "NPL_MP_AUX_DATA_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mp_aux_data_table_action_e");
        }
        return "";
    }
    npl_mp_aux_data_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mp_aux_data_table_value_t element);
std::string to_short_string(struct npl_mp_aux_data_table_value_t element);

/// API-s for table: mp_data_table

typedef enum
{
    NPL_MP_DATA_TABLE_ACTION_WRITE = 0x0
} npl_mp_data_table_action_e;

struct npl_mp_data_table_key_t
{
    npl_scanner_id_t line_id;
    
    npl_mp_data_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mp_data_table_key_t element);
std::string to_short_string(struct npl_mp_data_table_key_t element);

struct npl_mp_data_table_value_t
{
    npl_mp_data_table_action_e action;
    union npl_mp_data_table_payloads_t {
        npl_mp_data_result_t mp_data_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mp_data_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MP_DATA_TABLE_ACTION_WRITE:
            {
                return "NPL_MP_DATA_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mp_data_table_action_e");
        }
        return "";
    }
    npl_mp_data_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector384_t pack(void) const;
    void unpack(bit_vector384_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mp_data_table_value_t element);
std::string to_short_string(struct npl_mp_data_table_value_t element);

/// API-s for table: mpls_encap_control_static_table

typedef enum
{
    NPL_MPLS_ENCAP_CONTROL_STATIC_TABLE_ACTION_SET_MPLS_CONTROLS = 0x0
} npl_mpls_encap_control_static_table_action_e;

struct npl_mpls_encap_control_static_table_set_mpls_controls_payload_t
{
    npl_mpls_encap_control_bits_t mpls_encap_control_bits;
    uint64_t is_vpn : 1;
    uint64_t is_asbr : 1;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_mpls_encap_control_static_table_set_mpls_controls_payload_t element);
std::string to_short_string(npl_mpls_encap_control_static_table_set_mpls_controls_payload_t element);

struct npl_mpls_encap_control_static_table_key_t
{
    npl_npu_encap_l3_header_type_e encap_type;
    uint64_t lsp_type : 2;
    
    npl_mpls_encap_control_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mpls_encap_control_static_table_key_t element);
std::string to_short_string(struct npl_mpls_encap_control_static_table_key_t element);

struct npl_mpls_encap_control_static_table_value_t
{
    npl_mpls_encap_control_static_table_action_e action;
    union npl_mpls_encap_control_static_table_payloads_t {
        npl_mpls_encap_control_static_table_set_mpls_controls_payload_t set_mpls_controls;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mpls_encap_control_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MPLS_ENCAP_CONTROL_STATIC_TABLE_ACTION_SET_MPLS_CONTROLS:
            {
                return "NPL_MPLS_ENCAP_CONTROL_STATIC_TABLE_ACTION_SET_MPLS_CONTROLS(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mpls_encap_control_static_table_action_e");
        }
        return "";
    }
    npl_mpls_encap_control_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mpls_encap_control_static_table_value_t element);
std::string to_short_string(struct npl_mpls_encap_control_static_table_value_t element);

/// API-s for table: mpls_forwarding_table

typedef enum
{
    NPL_MPLS_FORWARDING_TABLE_ACTION_WRITE = 0x0
} npl_mpls_forwarding_table_action_e;

struct npl_mpls_forwarding_table_key_t
{
    uint64_t label : 20;
    
    npl_mpls_forwarding_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mpls_forwarding_table_key_t element);
std::string to_short_string(struct npl_mpls_forwarding_table_key_t element);

struct npl_mpls_forwarding_table_value_t
{
    npl_mpls_forwarding_table_action_e action;
    union npl_mpls_forwarding_table_payloads_t {
        npl_nhlfe_t nhlfe;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mpls_forwarding_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MPLS_FORWARDING_TABLE_ACTION_WRITE:
            {
                return "NPL_MPLS_FORWARDING_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mpls_forwarding_table_action_e");
        }
        return "";
    }
    npl_mpls_forwarding_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mpls_forwarding_table_value_t element);
std::string to_short_string(struct npl_mpls_forwarding_table_value_t element);

/// API-s for table: mpls_header_offset_in_bytes_static_table

typedef enum
{
    NPL_MPLS_HEADER_OFFSET_IN_BYTES_STATIC_TABLE_ACTION_IS_NULL_LABEL_FALSE = 0x0,
    NPL_MPLS_HEADER_OFFSET_IN_BYTES_STATIC_TABLE_ACTION_IS_NULL_LABEL_TRUE = 0x1
} npl_mpls_header_offset_in_bytes_static_table_action_e;

struct npl_mpls_header_offset_in_bytes_static_table_key_t
{
    uint64_t mpls_is_null_labels : 1;
    
    npl_mpls_header_offset_in_bytes_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mpls_header_offset_in_bytes_static_table_key_t element);
std::string to_short_string(struct npl_mpls_header_offset_in_bytes_static_table_key_t element);

struct npl_mpls_header_offset_in_bytes_static_table_value_t
{
    npl_mpls_header_offset_in_bytes_static_table_action_e action;
    std::string npl_action_enum_to_string(const npl_mpls_header_offset_in_bytes_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MPLS_HEADER_OFFSET_IN_BYTES_STATIC_TABLE_ACTION_IS_NULL_LABEL_FALSE:
            {
                return "NPL_MPLS_HEADER_OFFSET_IN_BYTES_STATIC_TABLE_ACTION_IS_NULL_LABEL_FALSE(0x0)";
                break;
            }
            case NPL_MPLS_HEADER_OFFSET_IN_BYTES_STATIC_TABLE_ACTION_IS_NULL_LABEL_TRUE:
            {
                return "NPL_MPLS_HEADER_OFFSET_IN_BYTES_STATIC_TABLE_ACTION_IS_NULL_LABEL_TRUE(0x1)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mpls_header_offset_in_bytes_static_table_action_e");
        }
        return "";
    }
    npl_mpls_header_offset_in_bytes_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mpls_header_offset_in_bytes_static_table_value_t element);
std::string to_short_string(struct npl_mpls_header_offset_in_bytes_static_table_value_t element);

/// API-s for table: mpls_l3_lsp_static_table

typedef enum
{
    NPL_MPLS_L3_LSP_STATIC_TABLE_ACTION_UPDATE_BACKUP_PAYLOAD = 0x0,
    NPL_MPLS_L3_LSP_STATIC_TABLE_ACTION_UPDATE_LSP_ASBR_PAYLOAD = 0x1,
    NPL_MPLS_L3_LSP_STATIC_TABLE_ACTION_UPDATE_LSP_PAYLOAD = 0x2,
    NPL_MPLS_L3_LSP_STATIC_TABLE_ACTION_UPDATE_LSP_ZERO_PAYLOAD = 0x3,
    NPL_MPLS_L3_LSP_STATIC_TABLE_ACTION_UPDATE_MIDPOINT_PAYLOAD = 0x4
} npl_mpls_l3_lsp_static_table_action_e;

struct npl_mpls_l3_lsp_static_table_key_t
{
    npl_mpls_encap_control_bits_t mpls_encap_control_bits;
    
    npl_mpls_l3_lsp_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mpls_l3_lsp_static_table_key_t element);
std::string to_short_string(struct npl_mpls_l3_lsp_static_table_key_t element);

struct npl_mpls_l3_lsp_static_table_value_t
{
    npl_mpls_l3_lsp_static_table_action_e action;
    std::string npl_action_enum_to_string(const npl_mpls_l3_lsp_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MPLS_L3_LSP_STATIC_TABLE_ACTION_UPDATE_BACKUP_PAYLOAD:
            {
                return "NPL_MPLS_L3_LSP_STATIC_TABLE_ACTION_UPDATE_BACKUP_PAYLOAD(0x0)";
                break;
            }
            case NPL_MPLS_L3_LSP_STATIC_TABLE_ACTION_UPDATE_LSP_ASBR_PAYLOAD:
            {
                return "NPL_MPLS_L3_LSP_STATIC_TABLE_ACTION_UPDATE_LSP_ASBR_PAYLOAD(0x1)";
                break;
            }
            case NPL_MPLS_L3_LSP_STATIC_TABLE_ACTION_UPDATE_LSP_PAYLOAD:
            {
                return "NPL_MPLS_L3_LSP_STATIC_TABLE_ACTION_UPDATE_LSP_PAYLOAD(0x2)";
                break;
            }
            case NPL_MPLS_L3_LSP_STATIC_TABLE_ACTION_UPDATE_LSP_ZERO_PAYLOAD:
            {
                return "NPL_MPLS_L3_LSP_STATIC_TABLE_ACTION_UPDATE_LSP_ZERO_PAYLOAD(0x3)";
                break;
            }
            case NPL_MPLS_L3_LSP_STATIC_TABLE_ACTION_UPDATE_MIDPOINT_PAYLOAD:
            {
                return "NPL_MPLS_L3_LSP_STATIC_TABLE_ACTION_UPDATE_MIDPOINT_PAYLOAD(0x4)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mpls_l3_lsp_static_table_action_e");
        }
        return "";
    }
    npl_mpls_l3_lsp_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mpls_l3_lsp_static_table_value_t element);
std::string to_short_string(struct npl_mpls_l3_lsp_static_table_value_t element);

/// API-s for table: mpls_labels_1_to_4_jump_offset_static_table

typedef enum
{
    NPL_MPLS_LABELS_1_TO_4_JUMP_OFFSET_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_mpls_labels_1_to_4_jump_offset_static_table_action_e;

struct npl_mpls_labels_1_to_4_jump_offset_static_table_key_t
{
    uint64_t jump_offset_code : 2;
    
    npl_mpls_labels_1_to_4_jump_offset_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mpls_labels_1_to_4_jump_offset_static_table_key_t element);
std::string to_short_string(struct npl_mpls_labels_1_to_4_jump_offset_static_table_key_t element);

struct npl_mpls_labels_1_to_4_jump_offset_static_table_value_t
{
    npl_mpls_labels_1_to_4_jump_offset_static_table_action_e action;
    union npl_mpls_labels_1_to_4_jump_offset_static_table_payloads_t {
        npl_lsp_impose_mpls_labels_ene_offset_t jump_offsets;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mpls_labels_1_to_4_jump_offset_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MPLS_LABELS_1_TO_4_JUMP_OFFSET_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_MPLS_LABELS_1_TO_4_JUMP_OFFSET_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mpls_labels_1_to_4_jump_offset_static_table_action_e");
        }
        return "";
    }
    npl_mpls_labels_1_to_4_jump_offset_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mpls_labels_1_to_4_jump_offset_static_table_value_t element);
std::string to_short_string(struct npl_mpls_labels_1_to_4_jump_offset_static_table_value_t element);

/// API-s for table: mpls_lsp_labels_config_static_table

typedef enum
{
    NPL_MPLS_LSP_LABELS_CONFIG_STATIC_TABLE_ACTION_SET_SECOND_MPLS_ENE_MACRO = 0x0
} npl_mpls_lsp_labels_config_static_table_action_e;

struct npl_mpls_lsp_labels_config_static_table_set_second_mpls_ene_macro_payload_t
{
    uint64_t num_labels_is_8 : 1;
    uint64_t outer_transport_labels_exist : 1;
    uint64_t additional_labels_exist : 1;
    uint64_t transport_labels_size : 6;
    npl_second_ene_macro_code_e second_ene_macro_code;
    npl_ene_jump_offset_code_e jump_offset_code;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_mpls_lsp_labels_config_static_table_set_second_mpls_ene_macro_payload_t element);
std::string to_short_string(npl_mpls_lsp_labels_config_static_table_set_second_mpls_ene_macro_payload_t element);

struct npl_mpls_lsp_labels_config_static_table_key_t
{
    uint64_t inner_transport_labels_exist : 1;
    npl_num_outer_transport_labels_t num_outer_transport_labels;
    
    npl_mpls_lsp_labels_config_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mpls_lsp_labels_config_static_table_key_t element);
std::string to_short_string(struct npl_mpls_lsp_labels_config_static_table_key_t element);

struct npl_mpls_lsp_labels_config_static_table_value_t
{
    npl_mpls_lsp_labels_config_static_table_action_e action;
    union npl_mpls_lsp_labels_config_static_table_payloads_t {
        npl_mpls_lsp_labels_config_static_table_set_second_mpls_ene_macro_payload_t set_second_mpls_ene_macro;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mpls_lsp_labels_config_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MPLS_LSP_LABELS_CONFIG_STATIC_TABLE_ACTION_SET_SECOND_MPLS_ENE_MACRO:
            {
                return "NPL_MPLS_LSP_LABELS_CONFIG_STATIC_TABLE_ACTION_SET_SECOND_MPLS_ENE_MACRO(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mpls_lsp_labels_config_static_table_action_e");
        }
        return "";
    }
    npl_mpls_lsp_labels_config_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mpls_lsp_labels_config_static_table_value_t element);
std::string to_short_string(struct npl_mpls_lsp_labels_config_static_table_value_t element);

/// API-s for table: mpls_qos_mapping_table

typedef enum
{
    NPL_MPLS_QOS_MAPPING_TABLE_ACTION_WRITE = 0x0
} npl_mpls_qos_mapping_table_action_e;

struct npl_mpls_qos_mapping_table_key_t
{
    uint64_t l3_qos_mapping_key : 3;
    uint64_t qos_id : 4;
    
    npl_mpls_qos_mapping_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mpls_qos_mapping_table_key_t element);
std::string to_short_string(struct npl_mpls_qos_mapping_table_key_t element);

struct npl_mpls_qos_mapping_table_value_t
{
    npl_mpls_qos_mapping_table_action_e action;
    union npl_mpls_qos_mapping_table_payloads_t {
        npl_ingress_qos_result_t mpls_qos_mapping_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mpls_qos_mapping_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MPLS_QOS_MAPPING_TABLE_ACTION_WRITE:
            {
                return "NPL_MPLS_QOS_MAPPING_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mpls_qos_mapping_table_action_e");
        }
        return "";
    }
    npl_mpls_qos_mapping_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mpls_qos_mapping_table_value_t element);
std::string to_short_string(struct npl_mpls_qos_mapping_table_value_t element);

/// API-s for table: mpls_resolve_service_labels_static_table

typedef enum
{
    NPL_MPLS_RESOLVE_SERVICE_LABELS_STATIC_TABLE_ACTION_SET_CONDITIONS = 0x0
} npl_mpls_resolve_service_labels_static_table_action_e;

struct npl_mpls_resolve_service_labels_static_table_set_conditions_payload_t
{
    uint64_t vpn_label_exists : 1;
    uint64_t sizeof_labels : 6;
    npl_mpls_first_ene_macro_control_t mpls_first_ene_macro_control;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_mpls_resolve_service_labels_static_table_set_conditions_payload_t element);
std::string to_short_string(npl_mpls_resolve_service_labels_static_table_set_conditions_payload_t element);

struct npl_mpls_resolve_service_labels_static_table_key_t
{
    npl_lsp_encap_fields_t lsp_flags;
    uint64_t vpn_enabled : 1;
    npl_fwd_header_type_e fwd_hdr_type;
    
    npl_mpls_resolve_service_labels_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mpls_resolve_service_labels_static_table_key_t element);
std::string to_short_string(struct npl_mpls_resolve_service_labels_static_table_key_t element);

struct npl_mpls_resolve_service_labels_static_table_value_t
{
    npl_mpls_resolve_service_labels_static_table_action_e action;
    union npl_mpls_resolve_service_labels_static_table_payloads_t {
        npl_mpls_resolve_service_labels_static_table_set_conditions_payload_t set_conditions;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mpls_resolve_service_labels_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MPLS_RESOLVE_SERVICE_LABELS_STATIC_TABLE_ACTION_SET_CONDITIONS:
            {
                return "NPL_MPLS_RESOLVE_SERVICE_LABELS_STATIC_TABLE_ACTION_SET_CONDITIONS(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mpls_resolve_service_labels_static_table_action_e");
        }
        return "";
    }
    npl_mpls_resolve_service_labels_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mpls_resolve_service_labels_static_table_value_t element);
std::string to_short_string(struct npl_mpls_resolve_service_labels_static_table_value_t element);

/// API-s for table: mpls_termination_em0_table

typedef enum
{
    NPL_MPLS_TERMINATION_EM0_TABLE_ACTION_WRITE = 0x0
} npl_mpls_termination_em0_table_action_e;

struct npl_mpls_termination_em0_table_key_t
{
    uint64_t termination_label : 20;
    
    npl_mpls_termination_em0_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mpls_termination_em0_table_key_t element);
std::string to_short_string(struct npl_mpls_termination_em0_table_key_t element);

struct npl_mpls_termination_em0_table_value_t
{
    npl_mpls_termination_em0_table_action_e action;
    union npl_mpls_termination_em0_table_payloads_t {
        npl_mpls_termination_res_t mpls_termination_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mpls_termination_em0_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MPLS_TERMINATION_EM0_TABLE_ACTION_WRITE:
            {
                return "NPL_MPLS_TERMINATION_EM0_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mpls_termination_em0_table_action_e");
        }
        return "";
    }
    npl_mpls_termination_em0_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mpls_termination_em0_table_value_t element);
std::string to_short_string(struct npl_mpls_termination_em0_table_value_t element);

/// API-s for table: mpls_termination_em1_table

typedef enum
{
    NPL_MPLS_TERMINATION_EM1_TABLE_ACTION_WRITE = 0x0
} npl_mpls_termination_em1_table_action_e;

struct npl_mpls_termination_em1_table_key_t
{
    uint64_t termination_label : 20;
    
    npl_mpls_termination_em1_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mpls_termination_em1_table_key_t element);
std::string to_short_string(struct npl_mpls_termination_em1_table_key_t element);

struct npl_mpls_termination_em1_table_value_t
{
    npl_mpls_termination_em1_table_action_e action;
    union npl_mpls_termination_em1_table_payloads_t {
        npl_mpls_termination_res_t mpls_termination_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mpls_termination_em1_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MPLS_TERMINATION_EM1_TABLE_ACTION_WRITE:
            {
                return "NPL_MPLS_TERMINATION_EM1_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mpls_termination_em1_table_action_e");
        }
        return "";
    }
    npl_mpls_termination_em1_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mpls_termination_em1_table_value_t element);
std::string to_short_string(struct npl_mpls_termination_em1_table_value_t element);

/// API-s for table: mpls_vpn_enabled_static_table

typedef enum
{
    NPL_MPLS_VPN_ENABLED_STATIC_TABLE_ACTION_SET_VALUE = 0x0
} npl_mpls_vpn_enabled_static_table_action_e;

struct npl_mpls_vpn_enabled_static_table_set_value_payload_t
{
    uint64_t is_l2_vpn : 1;
    uint64_t vpn_enabled : 1;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_mpls_vpn_enabled_static_table_set_value_payload_t element);
std::string to_short_string(npl_mpls_vpn_enabled_static_table_set_value_payload_t element);

struct npl_mpls_vpn_enabled_static_table_key_t
{
    uint64_t is_vpn : 1;
    npl_fwd_header_type_e fwd_header_type;
    npl_l3_relay_id_t l3_relay_id;
    uint64_t is_prefix_id : 3;
    
    npl_mpls_vpn_enabled_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_mpls_vpn_enabled_static_table_key_t element);
std::string to_short_string(struct npl_mpls_vpn_enabled_static_table_key_t element);

struct npl_mpls_vpn_enabled_static_table_value_t
{
    npl_mpls_vpn_enabled_static_table_action_e action;
    union npl_mpls_vpn_enabled_static_table_payloads_t {
        npl_mpls_vpn_enabled_static_table_set_value_payload_t set_value;
    } payloads;
    std::string npl_action_enum_to_string(const npl_mpls_vpn_enabled_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MPLS_VPN_ENABLED_STATIC_TABLE_ACTION_SET_VALUE:
            {
                return "NPL_MPLS_VPN_ENABLED_STATIC_TABLE_ACTION_SET_VALUE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_mpls_vpn_enabled_static_table_action_e");
        }
        return "";
    }
    npl_mpls_vpn_enabled_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_mpls_vpn_enabled_static_table_value_t element);
std::string to_short_string(struct npl_mpls_vpn_enabled_static_table_value_t element);

/// API-s for table: ms_voq_fabric_context_offset_table

typedef enum
{
    NPL_MS_VOQ_FABRIC_CONTEXT_OFFSET_TABLE_ACTION_WRITE = 0x0
} npl_ms_voq_fabric_context_offset_table_action_e;

struct npl_ms_voq_fabric_context_offset_table_key_t
{
    npl_fabric_context_e calc_msvoq_num_input_fabric_context;
    
    npl_ms_voq_fabric_context_offset_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ms_voq_fabric_context_offset_table_key_t element);
std::string to_short_string(struct npl_ms_voq_fabric_context_offset_table_key_t element);

struct npl_ms_voq_fabric_context_offset_table_value_t
{
    npl_ms_voq_fabric_context_offset_table_action_e action;
    union npl_ms_voq_fabric_context_offset_table_payloads_t {
        npl_ms_voq_fabric_context_offset_table_result_t ms_voq_fabric_context_offset_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ms_voq_fabric_context_offset_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MS_VOQ_FABRIC_CONTEXT_OFFSET_TABLE_ACTION_WRITE:
            {
                return "NPL_MS_VOQ_FABRIC_CONTEXT_OFFSET_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ms_voq_fabric_context_offset_table_action_e");
        }
        return "";
    }
    npl_ms_voq_fabric_context_offset_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ms_voq_fabric_context_offset_table_value_t element);
std::string to_short_string(struct npl_ms_voq_fabric_context_offset_table_value_t element);

/// API-s for table: my_ipv4_table

typedef enum
{
    NPL_MY_IPV4_TABLE_ACTION_WRITE = 0x0
} npl_my_ipv4_table_action_e;

struct npl_my_ipv4_table_key_t
{
    uint64_t l4_protocol_type_3_2 : 2;
    npl_l3_relay_id_t l3_relay_id;
    uint64_t dip : 32;
    
    npl_my_ipv4_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_my_ipv4_table_key_t element);
std::string to_short_string(struct npl_my_ipv4_table_key_t element);

struct npl_my_ipv4_table_value_t
{
    npl_my_ipv4_table_action_e action;
    union npl_my_ipv4_table_payloads_t {
        npl_my_ipv4_table_payload_t ip_tunnel_termination_attr;
    } payloads;
    std::string npl_action_enum_to_string(const npl_my_ipv4_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_MY_IPV4_TABLE_ACTION_WRITE:
            {
                return "NPL_MY_IPV4_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_my_ipv4_table_action_e");
        }
        return "";
    }
    npl_my_ipv4_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_my_ipv4_table_value_t element);
std::string to_short_string(struct npl_my_ipv4_table_value_t element);

/// API-s for table: native_ce_ptr_table

typedef enum
{
    NPL_NATIVE_CE_PTR_TABLE_ACTION_NARROW_ENTRY = 0x0,
    NPL_NATIVE_CE_PTR_TABLE_ACTION_PROTECTED_ENTRY = 0x1,
    NPL_NATIVE_CE_PTR_TABLE_ACTION_WIDE_ENTRY = 0x2
} npl_native_ce_ptr_table_action_e;

struct npl_native_ce_ptr_table_narrow_entry_payload_t
{
    npl_native_ce_ptr_table_result_narrow_t entry;
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_native_ce_ptr_table_narrow_entry_payload_t element);
std::string to_short_string(npl_native_ce_ptr_table_narrow_entry_payload_t element);

struct npl_native_ce_ptr_table_protected_entry_payload_t
{
    npl_native_l2_lp_table_result_protected_t data;
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_native_ce_ptr_table_protected_entry_payload_t element);
std::string to_short_string(npl_native_ce_ptr_table_protected_entry_payload_t element);

struct npl_native_ce_ptr_table_wide_entry_payload_t
{
    npl_native_ce_ptr_table_result_wide_t entry;
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_native_ce_ptr_table_wide_entry_payload_t element);
std::string to_short_string(npl_native_ce_ptr_table_wide_entry_payload_t element);

struct npl_native_ce_ptr_table_key_t
{
    uint64_t ce_ptr : 17;
    
    npl_native_ce_ptr_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_native_ce_ptr_table_key_t element);
std::string to_short_string(struct npl_native_ce_ptr_table_key_t element);

struct npl_native_ce_ptr_table_value_t
{
    npl_native_ce_ptr_table_action_e action;
    union npl_native_ce_ptr_table_payloads_t {
        npl_native_ce_ptr_table_narrow_entry_payload_t narrow_entry;
        npl_native_ce_ptr_table_protected_entry_payload_t protected_entry;
        npl_native_ce_ptr_table_wide_entry_payload_t wide_entry;
    } payloads;
    std::string npl_action_enum_to_string(const npl_native_ce_ptr_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_NATIVE_CE_PTR_TABLE_ACTION_NARROW_ENTRY:
            {
                return "NPL_NATIVE_CE_PTR_TABLE_ACTION_NARROW_ENTRY(0x0)";
                break;
            }
            case NPL_NATIVE_CE_PTR_TABLE_ACTION_PROTECTED_ENTRY:
            {
                return "NPL_NATIVE_CE_PTR_TABLE_ACTION_PROTECTED_ENTRY(0x1)";
                break;
            }
            case NPL_NATIVE_CE_PTR_TABLE_ACTION_WIDE_ENTRY:
            {
                return "NPL_NATIVE_CE_PTR_TABLE_ACTION_WIDE_ENTRY(0x2)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_native_ce_ptr_table_action_e");
        }
        return "";
    }
    npl_native_ce_ptr_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_native_ce_ptr_table_value_t element);
std::string to_short_string(struct npl_native_ce_ptr_table_value_t element);

/// API-s for table: native_fec_table

typedef enum
{
    NPL_NATIVE_FEC_TABLE_ACTION_WRITE = 0x0
} npl_native_fec_table_action_e;

struct npl_native_fec_table_key_t
{
    npl_fec_t fec;
    
    npl_native_fec_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_native_fec_table_key_t element);
std::string to_short_string(struct npl_native_fec_table_key_t element);

struct npl_native_fec_table_value_t
{
    npl_native_fec_table_action_e action;
    union npl_native_fec_table_payloads_t {
        npl_native_fec_table_result_t native_fec_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_native_fec_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_NATIVE_FEC_TABLE_ACTION_WRITE:
            {
                return "NPL_NATIVE_FEC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_native_fec_table_action_e");
        }
        return "";
    }
    npl_native_fec_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_native_fec_table_value_t element);
std::string to_short_string(struct npl_native_fec_table_value_t element);

/// API-s for table: native_fec_type_decoding_table

typedef enum
{
    NPL_NATIVE_FEC_TYPE_DECODING_TABLE_ACTION_WRITE = 0x0
} npl_native_fec_type_decoding_table_action_e;

struct npl_native_fec_type_decoding_table_key_t
{
    npl_native_fec_entry_type_e type;
    
    npl_native_fec_type_decoding_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_native_fec_type_decoding_table_key_t element);
std::string to_short_string(struct npl_native_fec_type_decoding_table_key_t element);

struct npl_native_fec_type_decoding_table_value_t
{
    npl_native_fec_type_decoding_table_action_e action;
    union npl_native_fec_type_decoding_table_payloads_t {
        npl_resolution_type_decoding_table_result_t native_fec_type_decoding_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_native_fec_type_decoding_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_NATIVE_FEC_TYPE_DECODING_TABLE_ACTION_WRITE:
            {
                return "NPL_NATIVE_FEC_TYPE_DECODING_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_native_fec_type_decoding_table_action_e");
        }
        return "";
    }
    npl_native_fec_type_decoding_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_native_fec_type_decoding_table_value_t element);
std::string to_short_string(struct npl_native_fec_type_decoding_table_value_t element);

/// API-s for table: native_frr_table

typedef enum
{
    NPL_NATIVE_FRR_TABLE_ACTION_PROTECTED_DATA = 0x0
} npl_native_frr_table_action_e;

struct npl_native_frr_table_protected_data_payload_t
{
    npl_native_frr_table_result_protected_t data;
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_native_frr_table_protected_data_payload_t element);
std::string to_short_string(npl_native_frr_table_protected_data_payload_t element);

struct npl_native_frr_table_key_t
{
    npl_frr_t frr_id;
    
    npl_native_frr_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_native_frr_table_key_t element);
std::string to_short_string(struct npl_native_frr_table_key_t element);

struct npl_native_frr_table_value_t
{
    npl_native_frr_table_action_e action;
    union npl_native_frr_table_payloads_t {
        npl_native_frr_table_protected_data_payload_t protected_data;
    } payloads;
    std::string npl_action_enum_to_string(const npl_native_frr_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_NATIVE_FRR_TABLE_ACTION_PROTECTED_DATA:
            {
                return "NPL_NATIVE_FRR_TABLE_ACTION_PROTECTED_DATA(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_native_frr_table_action_e");
        }
        return "";
    }
    npl_native_frr_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_native_frr_table_value_t element);
std::string to_short_string(struct npl_native_frr_table_value_t element);

/// API-s for table: native_frr_type_decoding_table

typedef enum
{
    NPL_NATIVE_FRR_TYPE_DECODING_TABLE_ACTION_WRITE = 0x0
} npl_native_frr_type_decoding_table_action_e;

struct npl_native_frr_type_decoding_table_key_t
{
    npl_native_frr_entry_type_e type;
    
    npl_native_frr_type_decoding_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_native_frr_type_decoding_table_key_t element);
std::string to_short_string(struct npl_native_frr_type_decoding_table_key_t element);

struct npl_native_frr_type_decoding_table_value_t
{
    npl_native_frr_type_decoding_table_action_e action;
    union npl_native_frr_type_decoding_table_payloads_t {
        npl_resolution_type_decoding_table_result_t native_frr_type_decoding_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_native_frr_type_decoding_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_NATIVE_FRR_TYPE_DECODING_TABLE_ACTION_WRITE:
            {
                return "NPL_NATIVE_FRR_TYPE_DECODING_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_native_frr_type_decoding_table_action_e");
        }
        return "";
    }
    npl_native_frr_type_decoding_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_native_frr_type_decoding_table_value_t element);
std::string to_short_string(struct npl_native_frr_type_decoding_table_value_t element);

/// API-s for table: native_l2_lp_table

typedef enum
{
    NPL_NATIVE_L2_LP_TABLE_ACTION_NARROW_ENTRY = 0x0,
    NPL_NATIVE_L2_LP_TABLE_ACTION_PROTECTED_ENTRY = 0x1,
    NPL_NATIVE_L2_LP_TABLE_ACTION_WIDE_ENTRY = 0x2
} npl_native_l2_lp_table_action_e;

struct npl_native_l2_lp_table_narrow_entry_payload_t
{
    npl_native_l2_lp_table_result_narrow_t entry;
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_native_l2_lp_table_narrow_entry_payload_t element);
std::string to_short_string(npl_native_l2_lp_table_narrow_entry_payload_t element);

struct npl_native_l2_lp_table_protected_entry_payload_t
{
    npl_native_l2_lp_table_result_protected_t data;
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_native_l2_lp_table_protected_entry_payload_t element);
std::string to_short_string(npl_native_l2_lp_table_protected_entry_payload_t element);

struct npl_native_l2_lp_table_wide_entry_payload_t
{
    npl_native_l2_lp_table_result_wide_t entry;
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_native_l2_lp_table_wide_entry_payload_t element);
std::string to_short_string(npl_native_l2_lp_table_wide_entry_payload_t element);

struct npl_native_l2_lp_table_key_t
{
    npl_l2_dlp_t l2_dlp;
    
    npl_native_l2_lp_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_native_l2_lp_table_key_t element);
std::string to_short_string(struct npl_native_l2_lp_table_key_t element);

struct npl_native_l2_lp_table_value_t
{
    npl_native_l2_lp_table_action_e action;
    union npl_native_l2_lp_table_payloads_t {
        npl_native_l2_lp_table_narrow_entry_payload_t narrow_entry;
        npl_native_l2_lp_table_protected_entry_payload_t protected_entry;
        npl_native_l2_lp_table_wide_entry_payload_t wide_entry;
    } payloads;
    std::string npl_action_enum_to_string(const npl_native_l2_lp_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_NATIVE_L2_LP_TABLE_ACTION_NARROW_ENTRY:
            {
                return "NPL_NATIVE_L2_LP_TABLE_ACTION_NARROW_ENTRY(0x0)";
                break;
            }
            case NPL_NATIVE_L2_LP_TABLE_ACTION_PROTECTED_ENTRY:
            {
                return "NPL_NATIVE_L2_LP_TABLE_ACTION_PROTECTED_ENTRY(0x1)";
                break;
            }
            case NPL_NATIVE_L2_LP_TABLE_ACTION_WIDE_ENTRY:
            {
                return "NPL_NATIVE_L2_LP_TABLE_ACTION_WIDE_ENTRY(0x2)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_native_l2_lp_table_action_e");
        }
        return "";
    }
    npl_native_l2_lp_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_native_l2_lp_table_value_t element);
std::string to_short_string(struct npl_native_l2_lp_table_value_t element);

/// API-s for table: native_l2_lp_type_decoding_table

typedef enum
{
    NPL_NATIVE_L2_LP_TYPE_DECODING_TABLE_ACTION_WRITE = 0x0
} npl_native_l2_lp_type_decoding_table_action_e;

struct npl_native_l2_lp_type_decoding_table_key_t
{
    npl_native_l2_lp_entry_type_e type;
    
    npl_native_l2_lp_type_decoding_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_native_l2_lp_type_decoding_table_key_t element);
std::string to_short_string(struct npl_native_l2_lp_type_decoding_table_key_t element);

struct npl_native_l2_lp_type_decoding_table_value_t
{
    npl_native_l2_lp_type_decoding_table_action_e action;
    union npl_native_l2_lp_type_decoding_table_payloads_t {
        npl_resolution_type_decoding_table_result_t native_l2_lp_type_decoding_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_native_l2_lp_type_decoding_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_NATIVE_L2_LP_TYPE_DECODING_TABLE_ACTION_WRITE:
            {
                return "NPL_NATIVE_L2_LP_TYPE_DECODING_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_native_l2_lp_type_decoding_table_action_e");
        }
        return "";
    }
    npl_native_l2_lp_type_decoding_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_native_l2_lp_type_decoding_table_value_t element);
std::string to_short_string(struct npl_native_l2_lp_type_decoding_table_value_t element);

/// API-s for table: native_lb_group_size_table

typedef enum
{
    NPL_NATIVE_LB_GROUP_SIZE_TABLE_ACTION_WRITE = 0x0
} npl_native_lb_group_size_table_action_e;

struct npl_native_lb_group_size_table_key_t
{
    uint64_t ecmp_id : 13;
    
    npl_native_lb_group_size_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_native_lb_group_size_table_key_t element);
std::string to_short_string(struct npl_native_lb_group_size_table_key_t element);

struct npl_native_lb_group_size_table_value_t
{
    npl_native_lb_group_size_table_action_e action;
    union npl_native_lb_group_size_table_payloads_t {
        npl_lb_group_size_table_result_t native_lb_group_size_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_native_lb_group_size_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_NATIVE_LB_GROUP_SIZE_TABLE_ACTION_WRITE:
            {
                return "NPL_NATIVE_LB_GROUP_SIZE_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_native_lb_group_size_table_action_e");
        }
        return "";
    }
    npl_native_lb_group_size_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_native_lb_group_size_table_value_t element);
std::string to_short_string(struct npl_native_lb_group_size_table_value_t element);

/// API-s for table: native_lb_table

typedef enum
{
    NPL_NATIVE_LB_TABLE_ACTION_WRITE = 0x0
} npl_native_lb_table_action_e;

struct npl_native_lb_table_key_t
{
    uint64_t member_id : 16;
    uint64_t group_id : 14;
    
    npl_native_lb_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_native_lb_table_key_t element);
std::string to_short_string(struct npl_native_lb_table_key_t element);

struct npl_native_lb_table_value_t
{
    npl_native_lb_table_action_e action;
    union npl_native_lb_table_payloads_t {
        npl_native_lb_table_result_t native_lb_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_native_lb_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_NATIVE_LB_TABLE_ACTION_WRITE:
            {
                return "NPL_NATIVE_LB_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_native_lb_table_action_e");
        }
        return "";
    }
    npl_native_lb_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_native_lb_table_value_t element);
std::string to_short_string(struct npl_native_lb_table_value_t element);

/// API-s for table: native_lb_type_decoding_table

typedef enum
{
    NPL_NATIVE_LB_TYPE_DECODING_TABLE_ACTION_WRITE = 0x0
} npl_native_lb_type_decoding_table_action_e;

struct npl_native_lb_type_decoding_table_key_t
{
    npl_native_lb_entry_type_e type;
    
    npl_native_lb_type_decoding_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_native_lb_type_decoding_table_key_t element);
std::string to_short_string(struct npl_native_lb_type_decoding_table_key_t element);

struct npl_native_lb_type_decoding_table_value_t
{
    npl_native_lb_type_decoding_table_action_e action;
    union npl_native_lb_type_decoding_table_payloads_t {
        npl_resolution_type_decoding_table_result_t native_lb_type_decoding_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_native_lb_type_decoding_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_NATIVE_LB_TYPE_DECODING_TABLE_ACTION_WRITE:
            {
                return "NPL_NATIVE_LB_TYPE_DECODING_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_native_lb_type_decoding_table_action_e");
        }
        return "";
    }
    npl_native_lb_type_decoding_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_native_lb_type_decoding_table_value_t element);
std::string to_short_string(struct npl_native_lb_type_decoding_table_value_t element);

/// API-s for table: native_lp_is_pbts_prefix_table

typedef enum
{
    NPL_NATIVE_LP_IS_PBTS_PREFIX_TABLE_ACTION_WRITE = 0x0
} npl_native_lp_is_pbts_prefix_table_action_e;

struct npl_native_lp_is_pbts_prefix_table_key_t
{
    uint64_t prefix : 5;
    
    npl_native_lp_is_pbts_prefix_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_native_lp_is_pbts_prefix_table_key_t element);
std::string to_short_string(struct npl_native_lp_is_pbts_prefix_table_key_t element);

struct npl_native_lp_is_pbts_prefix_table_value_t
{
    npl_native_lp_is_pbts_prefix_table_action_e action;
    union npl_native_lp_is_pbts_prefix_table_payloads_t {
        npl_is_pbts_prefix_t native_lp_is_pbts_prefix_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_native_lp_is_pbts_prefix_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_NATIVE_LP_IS_PBTS_PREFIX_TABLE_ACTION_WRITE:
            {
                return "NPL_NATIVE_LP_IS_PBTS_PREFIX_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_native_lp_is_pbts_prefix_table_action_e");
        }
        return "";
    }
    npl_native_lp_is_pbts_prefix_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_native_lp_is_pbts_prefix_table_value_t element);
std::string to_short_string(struct npl_native_lp_is_pbts_prefix_table_value_t element);

/// API-s for table: native_lp_pbts_map_table

typedef enum
{
    NPL_NATIVE_LP_PBTS_MAP_TABLE_ACTION_WRITE = 0x0
} npl_native_lp_pbts_map_table_action_e;

struct npl_native_lp_pbts_map_table_key_t
{
    npl_pbts_map_table_key_t pbts_map_key;
    
    npl_native_lp_pbts_map_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_native_lp_pbts_map_table_key_t element);
std::string to_short_string(struct npl_native_lp_pbts_map_table_key_t element);

struct npl_native_lp_pbts_map_table_value_t
{
    npl_native_lp_pbts_map_table_action_e action;
    union npl_native_lp_pbts_map_table_payloads_t {
        npl_pbts_map_table_result_t native_lp_pbts_map_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_native_lp_pbts_map_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_NATIVE_LP_PBTS_MAP_TABLE_ACTION_WRITE:
            {
                return "NPL_NATIVE_LP_PBTS_MAP_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_native_lp_pbts_map_table_action_e");
        }
        return "";
    }
    npl_native_lp_pbts_map_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_native_lp_pbts_map_table_value_t element);
std::string to_short_string(struct npl_native_lp_pbts_map_table_value_t element);

/// API-s for table: native_protection_table

typedef enum
{
    NPL_NATIVE_PROTECTION_TABLE_ACTION_WRITE = 0x0
} npl_native_protection_table_action_e;

struct npl_native_protection_table_key_t
{
    npl_native_protection_id_t id;
    
    npl_native_protection_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_native_protection_table_key_t element);
std::string to_short_string(struct npl_native_protection_table_key_t element);

struct npl_native_protection_table_value_t
{
    npl_native_protection_table_action_e action;
    union npl_native_protection_table_payloads_t {
        npl_protection_selector_t native_protection_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_native_protection_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_NATIVE_PROTECTION_TABLE_ACTION_WRITE:
            {
                return "NPL_NATIVE_PROTECTION_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_native_protection_table_action_e");
        }
        return "";
    }
    npl_native_protection_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_native_protection_table_value_t element);
std::string to_short_string(struct npl_native_protection_table_value_t element);

/// API-s for table: next_header_1_is_l4_over_ipv4_static_table

typedef enum
{
    NPL_NEXT_HEADER_1_IS_L4_OVER_IPV4_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_next_header_1_is_l4_over_ipv4_static_table_action_e;

struct npl_next_header_1_is_l4_over_ipv4_static_table_key_t
{
    uint64_t is_l4 : 1;
    uint64_t fragmented : 1;
    
    npl_next_header_1_is_l4_over_ipv4_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_next_header_1_is_l4_over_ipv4_static_table_key_t element);
std::string to_short_string(struct npl_next_header_1_is_l4_over_ipv4_static_table_key_t element);

struct npl_next_header_1_is_l4_over_ipv4_static_table_value_t
{
    npl_next_header_1_is_l4_over_ipv4_static_table_action_e action;
    union npl_next_header_1_is_l4_over_ipv4_static_table_payloads_t {
        npl_bool_t next_header_1_is_l4_over_ipv4;
    } payloads;
    std::string npl_action_enum_to_string(const npl_next_header_1_is_l4_over_ipv4_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_NEXT_HEADER_1_IS_L4_OVER_IPV4_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_NEXT_HEADER_1_IS_L4_OVER_IPV4_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_next_header_1_is_l4_over_ipv4_static_table_action_e");
        }
        return "";
    }
    npl_next_header_1_is_l4_over_ipv4_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_next_header_1_is_l4_over_ipv4_static_table_value_t element);
std::string to_short_string(struct npl_next_header_1_is_l4_over_ipv4_static_table_value_t element);

/// API-s for table: nh_macro_code_to_id_l6_static_table

typedef enum
{
    NPL_NH_MACRO_CODE_TO_ID_L6_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_nh_macro_code_to_id_l6_static_table_action_e;

struct npl_nh_macro_code_to_id_l6_static_table_key_t
{
    npl_nh_ene_macro_code_e l3_dlp_attributes_nh_ene_macro_code;
    
    npl_nh_macro_code_to_id_l6_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_nh_macro_code_to_id_l6_static_table_key_t element);
std::string to_short_string(struct npl_nh_macro_code_to_id_l6_static_table_key_t element);

struct npl_nh_macro_code_to_id_l6_static_table_value_t
{
    npl_nh_macro_code_to_id_l6_static_table_action_e action;
    union npl_nh_macro_code_to_id_l6_static_table_payloads_t {
        npl_ene_macro_id_t l3_tx_local_vars_nh_encap_ene_macro_id;
    } payloads;
    std::string npl_action_enum_to_string(const npl_nh_macro_code_to_id_l6_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_NH_MACRO_CODE_TO_ID_L6_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_NH_MACRO_CODE_TO_ID_L6_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_nh_macro_code_to_id_l6_static_table_action_e");
        }
        return "";
    }
    npl_nh_macro_code_to_id_l6_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_nh_macro_code_to_id_l6_static_table_value_t element);
std::string to_short_string(struct npl_nh_macro_code_to_id_l6_static_table_value_t element);

/// API-s for table: nhlfe_type_mapping_static_table

typedef enum
{
    NPL_NHLFE_TYPE_MAPPING_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_nhlfe_type_mapping_static_table_action_e;

struct npl_nhlfe_type_mapping_static_table_key_t
{
    npl_nhlfe_type_e mpls_relay_local_vars_nhlfe_type;
    
    npl_nhlfe_type_mapping_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_nhlfe_type_mapping_static_table_key_t element);
std::string to_short_string(struct npl_nhlfe_type_mapping_static_table_key_t element);

struct npl_nhlfe_type_mapping_static_table_value_t
{
    npl_nhlfe_type_mapping_static_table_action_e action;
    union npl_nhlfe_type_mapping_static_table_payloads_t {
        npl_nhlfe_type_attributes_t mpls_relay_local_vars_nhlfe_attributes;
    } payloads;
    std::string npl_action_enum_to_string(const npl_nhlfe_type_mapping_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_NHLFE_TYPE_MAPPING_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_NHLFE_TYPE_MAPPING_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_nhlfe_type_mapping_static_table_action_e");
        }
        return "";
    }
    npl_nhlfe_type_mapping_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_nhlfe_type_mapping_static_table_value_t element);
std::string to_short_string(struct npl_nhlfe_type_mapping_static_table_value_t element);

/// API-s for table: null_rtf_next_macro_static_table

typedef enum
{
    NPL_NULL_RTF_NEXT_MACRO_STATIC_TABLE_ACTION_SET_MACRO = 0x0
} npl_null_rtf_next_macro_static_table_action_e;

struct npl_null_rtf_next_macro_static_table_set_macro_payload_t
{
    uint64_t pl_inc : 2;
    uint64_t macro_id : 8;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_null_rtf_next_macro_static_table_set_macro_payload_t element);
std::string to_short_string(npl_null_rtf_next_macro_static_table_set_macro_payload_t element);

struct npl_null_rtf_next_macro_static_table_key_t
{
    npl_protocol_type_e next_prot_type;
    npl_ipv4_ipv6_init_rtf_stage_t pd_tunnel_ipv4_ipv6_init_rtf_stage;
    uint64_t acl_outer : 1;
    
    npl_null_rtf_next_macro_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_null_rtf_next_macro_static_table_key_t element);
std::string to_short_string(struct npl_null_rtf_next_macro_static_table_key_t element);

struct npl_null_rtf_next_macro_static_table_value_t
{
    npl_null_rtf_next_macro_static_table_action_e action;
    union npl_null_rtf_next_macro_static_table_payloads_t {
        npl_null_rtf_next_macro_static_table_set_macro_payload_t set_macro;
    } payloads;
    std::string npl_action_enum_to_string(const npl_null_rtf_next_macro_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_NULL_RTF_NEXT_MACRO_STATIC_TABLE_ACTION_SET_MACRO:
            {
                return "NPL_NULL_RTF_NEXT_MACRO_STATIC_TABLE_ACTION_SET_MACRO(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_null_rtf_next_macro_static_table_action_e");
        }
        return "";
    }
    npl_null_rtf_next_macro_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_null_rtf_next_macro_static_table_value_t element);
std::string to_short_string(struct npl_null_rtf_next_macro_static_table_value_t element);

/// API-s for table: nw_smcid_threshold_table

typedef enum
{
    NPL_NW_SMCID_THRESHOLD_TABLE_ACTION_WRITE = 0x0
} npl_nw_smcid_threshold_table_action_e;

struct npl_nw_smcid_threshold_table_key_t
{
    uint64_t dummy : 1;
    
    npl_nw_smcid_threshold_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_nw_smcid_threshold_table_key_t element);
std::string to_short_string(struct npl_nw_smcid_threshold_table_key_t element);

struct npl_nw_smcid_threshold_table_value_t
{
    npl_nw_smcid_threshold_table_action_e action;
    union npl_nw_smcid_threshold_table_payloads_t {
        npl_mcid_t smcid_threshold;
    } payloads;
    std::string npl_action_enum_to_string(const npl_nw_smcid_threshold_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_NW_SMCID_THRESHOLD_TABLE_ACTION_WRITE:
            {
                return "NPL_NW_SMCID_THRESHOLD_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_nw_smcid_threshold_table_action_e");
        }
        return "";
    }
    npl_nw_smcid_threshold_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_nw_smcid_threshold_table_value_t element);
std::string to_short_string(struct npl_nw_smcid_threshold_table_value_t element);

/// API-s for table: oamp_drop_destination_static_table

typedef enum
{
    NPL_OAMP_DROP_DESTINATION_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_oamp_drop_destination_static_table_action_e;

struct npl_oamp_drop_destination_static_table_key_t
{
    
    
    npl_oamp_drop_destination_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_oamp_drop_destination_static_table_key_t element);
std::string to_short_string(struct npl_oamp_drop_destination_static_table_key_t element);

struct npl_oamp_drop_destination_static_table_value_t
{
    npl_oamp_drop_destination_static_table_action_e action;
    union npl_oamp_drop_destination_static_table_payloads_t {
        npl_destination_t drop_dest;
    } payloads;
    std::string npl_action_enum_to_string(const npl_oamp_drop_destination_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_OAMP_DROP_DESTINATION_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_OAMP_DROP_DESTINATION_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_oamp_drop_destination_static_table_action_e");
        }
        return "";
    }
    npl_oamp_drop_destination_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_oamp_drop_destination_static_table_value_t element);
std::string to_short_string(struct npl_oamp_drop_destination_static_table_value_t element);

/// API-s for table: oamp_event_queue_table

typedef enum
{
    NPL_OAMP_EVENT_QUEUE_TABLE_ACTION_NO_OP = 0x0
} npl_oamp_event_queue_table_action_e;

struct npl_oamp_event_queue_table_key_t
{
    uint64_t rmep_id : 13;
    uint64_t mep_id : 13;
    npl_oamp_event_type_e oamp_event;
    
    npl_oamp_event_queue_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_oamp_event_queue_table_key_t element);
std::string to_short_string(struct npl_oamp_event_queue_table_key_t element);

struct npl_oamp_event_queue_table_value_t
{
    npl_oamp_event_queue_table_action_e action;
    std::string npl_action_enum_to_string(const npl_oamp_event_queue_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_OAMP_EVENT_QUEUE_TABLE_ACTION_NO_OP:
            {
                return "NPL_OAMP_EVENT_QUEUE_TABLE_ACTION_NO_OP(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_oamp_event_queue_table_action_e");
        }
        return "";
    }
    npl_oamp_event_queue_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_oamp_event_queue_table_value_t element);
std::string to_short_string(struct npl_oamp_event_queue_table_value_t element);

/// API-s for table: oamp_redirect_get_counter_table

typedef enum
{
    NPL_OAMP_REDIRECT_GET_COUNTER_TABLE_ACTION_WRITE = 0x0
} npl_oamp_redirect_get_counter_table_action_e;

struct npl_oamp_redirect_get_counter_table_key_t
{
    uint64_t redirect_code : 8;
    
    npl_oamp_redirect_get_counter_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_oamp_redirect_get_counter_table_key_t element);
std::string to_short_string(struct npl_oamp_redirect_get_counter_table_key_t element);

struct npl_oamp_redirect_get_counter_table_value_t
{
    npl_oamp_redirect_get_counter_table_action_e action;
    union npl_oamp_redirect_get_counter_table_payloads_t {
        npl_counter_ptr_t counter_ptr;
    } payloads;
    std::string npl_action_enum_to_string(const npl_oamp_redirect_get_counter_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_OAMP_REDIRECT_GET_COUNTER_TABLE_ACTION_WRITE:
            {
                return "NPL_OAMP_REDIRECT_GET_COUNTER_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_oamp_redirect_get_counter_table_action_e");
        }
        return "";
    }
    npl_oamp_redirect_get_counter_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_oamp_redirect_get_counter_table_value_t element);
std::string to_short_string(struct npl_oamp_redirect_get_counter_table_value_t element);

/// API-s for table: oamp_redirect_punt_eth_hdr_1_table

typedef enum
{
    NPL_OAMP_REDIRECT_PUNT_ETH_HDR_1_TABLE_ACTION_SET_INJECT_ETH = 0x0
} npl_oamp_redirect_punt_eth_hdr_1_table_action_e;

struct npl_oamp_redirect_punt_eth_hdr_1_table_set_inject_eth_payload_t
{
    uint64_t da : 32;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_oamp_redirect_punt_eth_hdr_1_table_set_inject_eth_payload_t element);
std::string to_short_string(npl_oamp_redirect_punt_eth_hdr_1_table_set_inject_eth_payload_t element);

struct npl_oamp_redirect_punt_eth_hdr_1_table_key_t
{
    uint64_t encap_selector : 2;
    
    npl_oamp_redirect_punt_eth_hdr_1_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_oamp_redirect_punt_eth_hdr_1_table_key_t element);
std::string to_short_string(struct npl_oamp_redirect_punt_eth_hdr_1_table_key_t element);

struct npl_oamp_redirect_punt_eth_hdr_1_table_value_t
{
    npl_oamp_redirect_punt_eth_hdr_1_table_action_e action;
    union npl_oamp_redirect_punt_eth_hdr_1_table_payloads_t {
        npl_oamp_redirect_punt_eth_hdr_1_table_set_inject_eth_payload_t set_inject_eth;
    } payloads;
    std::string npl_action_enum_to_string(const npl_oamp_redirect_punt_eth_hdr_1_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_OAMP_REDIRECT_PUNT_ETH_HDR_1_TABLE_ACTION_SET_INJECT_ETH:
            {
                return "NPL_OAMP_REDIRECT_PUNT_ETH_HDR_1_TABLE_ACTION_SET_INJECT_ETH(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_oamp_redirect_punt_eth_hdr_1_table_action_e");
        }
        return "";
    }
    npl_oamp_redirect_punt_eth_hdr_1_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_oamp_redirect_punt_eth_hdr_1_table_value_t element);
std::string to_short_string(struct npl_oamp_redirect_punt_eth_hdr_1_table_value_t element);

/// API-s for table: oamp_redirect_punt_eth_hdr_2_table

typedef enum
{
    NPL_OAMP_REDIRECT_PUNT_ETH_HDR_2_TABLE_ACTION_SET_INJECT_ETH = 0x0
} npl_oamp_redirect_punt_eth_hdr_2_table_action_e;

struct npl_oamp_redirect_punt_eth_hdr_2_table_set_inject_eth_payload_t
{
    uint64_t da : 16;
    uint64_t sa : 16;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_oamp_redirect_punt_eth_hdr_2_table_set_inject_eth_payload_t element);
std::string to_short_string(npl_oamp_redirect_punt_eth_hdr_2_table_set_inject_eth_payload_t element);

struct npl_oamp_redirect_punt_eth_hdr_2_table_key_t
{
    uint64_t encap_selector : 2;
    
    npl_oamp_redirect_punt_eth_hdr_2_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_oamp_redirect_punt_eth_hdr_2_table_key_t element);
std::string to_short_string(struct npl_oamp_redirect_punt_eth_hdr_2_table_key_t element);

struct npl_oamp_redirect_punt_eth_hdr_2_table_value_t
{
    npl_oamp_redirect_punt_eth_hdr_2_table_action_e action;
    union npl_oamp_redirect_punt_eth_hdr_2_table_payloads_t {
        npl_oamp_redirect_punt_eth_hdr_2_table_set_inject_eth_payload_t set_inject_eth;
    } payloads;
    std::string npl_action_enum_to_string(const npl_oamp_redirect_punt_eth_hdr_2_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_OAMP_REDIRECT_PUNT_ETH_HDR_2_TABLE_ACTION_SET_INJECT_ETH:
            {
                return "NPL_OAMP_REDIRECT_PUNT_ETH_HDR_2_TABLE_ACTION_SET_INJECT_ETH(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_oamp_redirect_punt_eth_hdr_2_table_action_e");
        }
        return "";
    }
    npl_oamp_redirect_punt_eth_hdr_2_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_oamp_redirect_punt_eth_hdr_2_table_value_t element);
std::string to_short_string(struct npl_oamp_redirect_punt_eth_hdr_2_table_value_t element);

/// API-s for table: oamp_redirect_punt_eth_hdr_3_table

typedef enum
{
    NPL_OAMP_REDIRECT_PUNT_ETH_HDR_3_TABLE_ACTION_SET_INJECT_ETH = 0x0
} npl_oamp_redirect_punt_eth_hdr_3_table_action_e;

struct npl_oamp_redirect_punt_eth_hdr_3_table_set_inject_eth_payload_t
{
    uint64_t sa : 32;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_oamp_redirect_punt_eth_hdr_3_table_set_inject_eth_payload_t element);
std::string to_short_string(npl_oamp_redirect_punt_eth_hdr_3_table_set_inject_eth_payload_t element);

struct npl_oamp_redirect_punt_eth_hdr_3_table_key_t
{
    uint64_t encap_selector : 2;
    
    npl_oamp_redirect_punt_eth_hdr_3_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_oamp_redirect_punt_eth_hdr_3_table_key_t element);
std::string to_short_string(struct npl_oamp_redirect_punt_eth_hdr_3_table_key_t element);

struct npl_oamp_redirect_punt_eth_hdr_3_table_value_t
{
    npl_oamp_redirect_punt_eth_hdr_3_table_action_e action;
    union npl_oamp_redirect_punt_eth_hdr_3_table_payloads_t {
        npl_oamp_redirect_punt_eth_hdr_3_table_set_inject_eth_payload_t set_inject_eth;
    } payloads;
    std::string npl_action_enum_to_string(const npl_oamp_redirect_punt_eth_hdr_3_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_OAMP_REDIRECT_PUNT_ETH_HDR_3_TABLE_ACTION_SET_INJECT_ETH:
            {
                return "NPL_OAMP_REDIRECT_PUNT_ETH_HDR_3_TABLE_ACTION_SET_INJECT_ETH(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_oamp_redirect_punt_eth_hdr_3_table_action_e");
        }
        return "";
    }
    npl_oamp_redirect_punt_eth_hdr_3_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_oamp_redirect_punt_eth_hdr_3_table_value_t element);
std::string to_short_string(struct npl_oamp_redirect_punt_eth_hdr_3_table_value_t element);

/// API-s for table: oamp_redirect_punt_eth_hdr_4_table

typedef enum
{
    NPL_OAMP_REDIRECT_PUNT_ETH_HDR_4_TABLE_ACTION_SET_INJECT_ETH = 0x0
} npl_oamp_redirect_punt_eth_hdr_4_table_action_e;

struct npl_oamp_redirect_punt_eth_hdr_4_table_set_inject_eth_payload_t
{
    uint64_t dei_vid : 16;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_oamp_redirect_punt_eth_hdr_4_table_set_inject_eth_payload_t element);
std::string to_short_string(npl_oamp_redirect_punt_eth_hdr_4_table_set_inject_eth_payload_t element);

struct npl_oamp_redirect_punt_eth_hdr_4_table_key_t
{
    uint64_t encap_selector : 2;
    
    npl_oamp_redirect_punt_eth_hdr_4_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_oamp_redirect_punt_eth_hdr_4_table_key_t element);
std::string to_short_string(struct npl_oamp_redirect_punt_eth_hdr_4_table_key_t element);

struct npl_oamp_redirect_punt_eth_hdr_4_table_value_t
{
    npl_oamp_redirect_punt_eth_hdr_4_table_action_e action;
    union npl_oamp_redirect_punt_eth_hdr_4_table_payloads_t {
        npl_oamp_redirect_punt_eth_hdr_4_table_set_inject_eth_payload_t set_inject_eth;
    } payloads;
    std::string npl_action_enum_to_string(const npl_oamp_redirect_punt_eth_hdr_4_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_OAMP_REDIRECT_PUNT_ETH_HDR_4_TABLE_ACTION_SET_INJECT_ETH:
            {
                return "NPL_OAMP_REDIRECT_PUNT_ETH_HDR_4_TABLE_ACTION_SET_INJECT_ETH(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_oamp_redirect_punt_eth_hdr_4_table_action_e");
        }
        return "";
    }
    npl_oamp_redirect_punt_eth_hdr_4_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_oamp_redirect_punt_eth_hdr_4_table_value_t element);
std::string to_short_string(struct npl_oamp_redirect_punt_eth_hdr_4_table_value_t element);

/// API-s for table: oamp_redirect_table

typedef enum
{
    NPL_OAMP_REDIRECT_TABLE_ACTION_OAMP_REDIRECT_ACTION = 0x0
} npl_oamp_redirect_table_action_e;

struct npl_oamp_redirect_table_oamp_redirect_action_payload_t
{
    npl_destination_t destination;
    npl_phb_t phb;
    uint64_t encap_ptr : 2;
    uint64_t keep_counter : 1;
    uint64_t drop : 1;
    npl_inject_header_type_e type;
    uint64_t ifg : 4;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_oamp_redirect_table_oamp_redirect_action_payload_t element);
std::string to_short_string(npl_oamp_redirect_table_oamp_redirect_action_payload_t element);

struct npl_oamp_redirect_table_key_t
{
    uint64_t redirect_code : 8;
    
    npl_oamp_redirect_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_oamp_redirect_table_key_t element);
std::string to_short_string(struct npl_oamp_redirect_table_key_t element);

struct npl_oamp_redirect_table_value_t
{
    npl_oamp_redirect_table_action_e action;
    union npl_oamp_redirect_table_payloads_t {
        npl_oamp_redirect_table_oamp_redirect_action_payload_t oamp_redirect_action;
    } payloads;
    std::string npl_action_enum_to_string(const npl_oamp_redirect_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_OAMP_REDIRECT_TABLE_ACTION_OAMP_REDIRECT_ACTION:
            {
                return "NPL_OAMP_REDIRECT_TABLE_ACTION_OAMP_REDIRECT_ACTION(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_oamp_redirect_table_action_e");
        }
        return "";
    }
    npl_oamp_redirect_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_oamp_redirect_table_value_t element);
std::string to_short_string(struct npl_oamp_redirect_table_value_t element);

/// API-s for table: obm_next_macro_static_table

typedef enum
{
    NPL_OBM_NEXT_MACRO_STATIC_TABLE_ACTION_UPDATE_NEXT_MACRO_ACTION = 0x0
} npl_obm_next_macro_static_table_action_e;

struct npl_obm_next_macro_static_table_update_next_macro_action_payload_t
{
    uint64_t pl_inc : 2;
    uint64_t macro_id : 8;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_obm_next_macro_static_table_update_next_macro_action_payload_t element);
std::string to_short_string(npl_obm_next_macro_static_table_update_next_macro_action_payload_t element);

struct npl_obm_next_macro_static_table_key_t
{
    uint64_t rcy_data_suffix : 5;
    npl_protocol_type_e has_punt_header;
    
    npl_obm_next_macro_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_obm_next_macro_static_table_key_t element);
std::string to_short_string(struct npl_obm_next_macro_static_table_key_t element);

struct npl_obm_next_macro_static_table_value_t
{
    npl_obm_next_macro_static_table_action_e action;
    union npl_obm_next_macro_static_table_payloads_t {
        npl_obm_next_macro_static_table_update_next_macro_action_payload_t update_next_macro_action;
    } payloads;
    std::string npl_action_enum_to_string(const npl_obm_next_macro_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_OBM_NEXT_MACRO_STATIC_TABLE_ACTION_UPDATE_NEXT_MACRO_ACTION:
            {
                return "NPL_OBM_NEXT_MACRO_STATIC_TABLE_ACTION_UPDATE_NEXT_MACRO_ACTION(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_obm_next_macro_static_table_action_e");
        }
        return "";
    }
    npl_obm_next_macro_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_obm_next_macro_static_table_value_t element);
std::string to_short_string(struct npl_obm_next_macro_static_table_value_t element);

/// API-s for table: og_next_macro_static_table

typedef enum
{
    NPL_OG_NEXT_MACRO_STATIC_TABLE_ACTION_SET_MACRO = 0x0
} npl_og_next_macro_static_table_action_e;

struct npl_og_next_macro_static_table_set_macro_payload_t
{
    uint64_t pl_inc : 2;
    uint64_t macro_id : 8;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_og_next_macro_static_table_set_macro_payload_t element);
std::string to_short_string(npl_og_next_macro_static_table_set_macro_payload_t element);

struct npl_og_next_macro_static_table_key_t
{
    npl_ip_version_e ip_version;
    
    npl_og_next_macro_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_og_next_macro_static_table_key_t element);
std::string to_short_string(struct npl_og_next_macro_static_table_key_t element);

struct npl_og_next_macro_static_table_value_t
{
    npl_og_next_macro_static_table_action_e action;
    union npl_og_next_macro_static_table_payloads_t {
        npl_og_next_macro_static_table_set_macro_payload_t set_macro;
    } payloads;
    std::string npl_action_enum_to_string(const npl_og_next_macro_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_OG_NEXT_MACRO_STATIC_TABLE_ACTION_SET_MACRO:
            {
                return "NPL_OG_NEXT_MACRO_STATIC_TABLE_ACTION_SET_MACRO(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_og_next_macro_static_table_action_e");
        }
        return "";
    }
    npl_og_next_macro_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_og_next_macro_static_table_value_t element);
std::string to_short_string(struct npl_og_next_macro_static_table_value_t element);

/// API-s for table: outer_tpid_table

typedef enum
{
    NPL_OUTER_TPID_TABLE_ACTION_WRITE = 0x0
} npl_outer_tpid_table_action_e;

struct npl_outer_tpid_table_key_t
{
    uint64_t tpid_ptr : 4;
    
    npl_outer_tpid_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_outer_tpid_table_key_t element);
std::string to_short_string(struct npl_outer_tpid_table_key_t element);

struct npl_outer_tpid_table_value_t
{
    npl_outer_tpid_table_action_e action;
    union npl_outer_tpid_table_payloads_t {
        uint64_t tpid : 16;
    } payloads;
    std::string npl_action_enum_to_string(const npl_outer_tpid_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_OUTER_TPID_TABLE_ACTION_WRITE:
            {
                return "NPL_OUTER_TPID_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_outer_tpid_table_action_e");
        }
        return "";
    }
    npl_outer_tpid_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_outer_tpid_table_value_t element);
std::string to_short_string(struct npl_outer_tpid_table_value_t element);

/// API-s for table: overlay_ipv4_sip_table

typedef enum
{
    NPL_OVERLAY_IPV4_SIP_TABLE_ACTION_WRITE = 0x0
} npl_overlay_ipv4_sip_table_action_e;

struct npl_overlay_ipv4_sip_table_key_t
{
    uint64_t sip : 32;
    uint64_t vxlan_tunnel_loopback : 4;
    
    npl_overlay_ipv4_sip_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_overlay_ipv4_sip_table_key_t element);
std::string to_short_string(struct npl_overlay_ipv4_sip_table_key_t element);

struct npl_overlay_ipv4_sip_table_value_t
{
    npl_overlay_ipv4_sip_table_action_e action;
    union npl_overlay_ipv4_sip_table_payloads_t {
        npl_lp_id_t slp_id;
    } payloads;
    std::string npl_action_enum_to_string(const npl_overlay_ipv4_sip_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_OVERLAY_IPV4_SIP_TABLE_ACTION_WRITE:
            {
                return "NPL_OVERLAY_IPV4_SIP_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_overlay_ipv4_sip_table_action_e");
        }
        return "";
    }
    npl_overlay_ipv4_sip_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_overlay_ipv4_sip_table_value_t element);
std::string to_short_string(struct npl_overlay_ipv4_sip_table_value_t element);

/// API-s for table: pad_mtu_inj_check_static_table

typedef enum
{
    NPL_PAD_MTU_INJ_CHECK_STATIC_TABLE_ACTION_DEFAULT_PAD_MTU_INJ_ACTION = 0x0,
    NPL_PAD_MTU_INJ_CHECK_STATIC_TABLE_ACTION_PAD_MTU_INJ_NEXT_MACRO_ACTION = 0x1
} npl_pad_mtu_inj_check_static_table_action_e;

struct npl_pad_mtu_inj_check_static_table_pad_mtu_inj_next_macro_action_payload_t
{
    uint64_t pl_inc : 2;
    uint64_t macro_id : 8;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_pad_mtu_inj_check_static_table_pad_mtu_inj_next_macro_action_payload_t element);
std::string to_short_string(npl_pad_mtu_inj_check_static_table_pad_mtu_inj_next_macro_action_payload_t element);

struct npl_pad_mtu_inj_check_static_table_key_t
{
    npl_bool_t tx_npu_header_is_inject_up;
    uint64_t l3_tx_local_vars_fwd_pkt_size : 14;
    
    npl_pad_mtu_inj_check_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_pad_mtu_inj_check_static_table_key_t element);
std::string to_short_string(struct npl_pad_mtu_inj_check_static_table_key_t element);

struct npl_pad_mtu_inj_check_static_table_value_t
{
    npl_pad_mtu_inj_check_static_table_action_e action;
    union npl_pad_mtu_inj_check_static_table_payloads_t {
        npl_pad_mtu_inj_check_static_table_pad_mtu_inj_next_macro_action_payload_t pad_mtu_inj_next_macro_action;
    } payloads;
    std::string npl_action_enum_to_string(const npl_pad_mtu_inj_check_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PAD_MTU_INJ_CHECK_STATIC_TABLE_ACTION_DEFAULT_PAD_MTU_INJ_ACTION:
            {
                return "NPL_PAD_MTU_INJ_CHECK_STATIC_TABLE_ACTION_DEFAULT_PAD_MTU_INJ_ACTION(0x0)";
                break;
            }
            case NPL_PAD_MTU_INJ_CHECK_STATIC_TABLE_ACTION_PAD_MTU_INJ_NEXT_MACRO_ACTION:
            {
                return "NPL_PAD_MTU_INJ_CHECK_STATIC_TABLE_ACTION_PAD_MTU_INJ_NEXT_MACRO_ACTION(0x1)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_pad_mtu_inj_check_static_table_action_e");
        }
        return "";
    }
    npl_pad_mtu_inj_check_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_pad_mtu_inj_check_static_table_value_t element);
std::string to_short_string(struct npl_pad_mtu_inj_check_static_table_value_t element);

/// API-s for table: path_lb_type_decoding_table

typedef enum
{
    NPL_PATH_LB_TYPE_DECODING_TABLE_ACTION_WRITE = 0x0
} npl_path_lb_type_decoding_table_action_e;

struct npl_path_lb_type_decoding_table_key_t
{
    npl_path_lb_entry_type_e type;
    
    npl_path_lb_type_decoding_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_path_lb_type_decoding_table_key_t element);
std::string to_short_string(struct npl_path_lb_type_decoding_table_key_t element);

struct npl_path_lb_type_decoding_table_value_t
{
    npl_path_lb_type_decoding_table_action_e action;
    union npl_path_lb_type_decoding_table_payloads_t {
        npl_resolution_type_decoding_table_result_t path_lb_type_decoding_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_path_lb_type_decoding_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PATH_LB_TYPE_DECODING_TABLE_ACTION_WRITE:
            {
                return "NPL_PATH_LB_TYPE_DECODING_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_path_lb_type_decoding_table_action_e");
        }
        return "";
    }
    npl_path_lb_type_decoding_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_path_lb_type_decoding_table_value_t element);
std::string to_short_string(struct npl_path_lb_type_decoding_table_value_t element);

/// API-s for table: path_lp_is_pbts_prefix_table

typedef enum
{
    NPL_PATH_LP_IS_PBTS_PREFIX_TABLE_ACTION_WRITE = 0x0
} npl_path_lp_is_pbts_prefix_table_action_e;

struct npl_path_lp_is_pbts_prefix_table_key_t
{
    uint64_t prefix : 5;
    
    npl_path_lp_is_pbts_prefix_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_path_lp_is_pbts_prefix_table_key_t element);
std::string to_short_string(struct npl_path_lp_is_pbts_prefix_table_key_t element);

struct npl_path_lp_is_pbts_prefix_table_value_t
{
    npl_path_lp_is_pbts_prefix_table_action_e action;
    union npl_path_lp_is_pbts_prefix_table_payloads_t {
        npl_is_pbts_prefix_t path_lp_is_pbts_prefix_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_path_lp_is_pbts_prefix_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PATH_LP_IS_PBTS_PREFIX_TABLE_ACTION_WRITE:
            {
                return "NPL_PATH_LP_IS_PBTS_PREFIX_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_path_lp_is_pbts_prefix_table_action_e");
        }
        return "";
    }
    npl_path_lp_is_pbts_prefix_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_path_lp_is_pbts_prefix_table_value_t element);
std::string to_short_string(struct npl_path_lp_is_pbts_prefix_table_value_t element);

/// API-s for table: path_lp_pbts_map_table

typedef enum
{
    NPL_PATH_LP_PBTS_MAP_TABLE_ACTION_WRITE = 0x0
} npl_path_lp_pbts_map_table_action_e;

struct npl_path_lp_pbts_map_table_key_t
{
    npl_pbts_map_table_key_t pbts_map_key;
    
    npl_path_lp_pbts_map_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_path_lp_pbts_map_table_key_t element);
std::string to_short_string(struct npl_path_lp_pbts_map_table_key_t element);

struct npl_path_lp_pbts_map_table_value_t
{
    npl_path_lp_pbts_map_table_action_e action;
    union npl_path_lp_pbts_map_table_payloads_t {
        npl_pbts_map_table_result_t path_lp_pbts_map_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_path_lp_pbts_map_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PATH_LP_PBTS_MAP_TABLE_ACTION_WRITE:
            {
                return "NPL_PATH_LP_PBTS_MAP_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_path_lp_pbts_map_table_action_e");
        }
        return "";
    }
    npl_path_lp_pbts_map_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_path_lp_pbts_map_table_value_t element);
std::string to_short_string(struct npl_path_lp_pbts_map_table_value_t element);

/// API-s for table: path_lp_table

typedef enum
{
    NPL_PATH_LP_TABLE_ACTION_NARROW_ENTRY = 0x0,
    NPL_PATH_LP_TABLE_ACTION_PROTECTED_ENTRY = 0x1,
    NPL_PATH_LP_TABLE_ACTION_WIDE_ENTRY = 0x2
} npl_path_lp_table_action_e;

struct npl_path_lp_table_narrow_entry_payload_t
{
    npl_path_lp_table_result_narrow_t entry;
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_path_lp_table_narrow_entry_payload_t element);
std::string to_short_string(npl_path_lp_table_narrow_entry_payload_t element);

struct npl_path_lp_table_protected_entry_payload_t
{
    npl_path_lp_table_result_protected_t data;
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_path_lp_table_protected_entry_payload_t element);
std::string to_short_string(npl_path_lp_table_protected_entry_payload_t element);

struct npl_path_lp_table_wide_entry_payload_t
{
    npl_path_lp_table_result_wide_t entry;
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_path_lp_table_wide_entry_payload_t element);
std::string to_short_string(npl_path_lp_table_wide_entry_payload_t element);

struct npl_path_lp_table_key_t
{
    npl_tunnel_dlp_t tunnel_dlp;
    
    npl_path_lp_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_path_lp_table_key_t element);
std::string to_short_string(struct npl_path_lp_table_key_t element);

struct npl_path_lp_table_value_t
{
    npl_path_lp_table_action_e action;
    union npl_path_lp_table_payloads_t {
        npl_path_lp_table_narrow_entry_payload_t narrow_entry;
        npl_path_lp_table_protected_entry_payload_t protected_entry;
        npl_path_lp_table_wide_entry_payload_t wide_entry;
    } payloads;
    std::string npl_action_enum_to_string(const npl_path_lp_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PATH_LP_TABLE_ACTION_NARROW_ENTRY:
            {
                return "NPL_PATH_LP_TABLE_ACTION_NARROW_ENTRY(0x0)";
                break;
            }
            case NPL_PATH_LP_TABLE_ACTION_PROTECTED_ENTRY:
            {
                return "NPL_PATH_LP_TABLE_ACTION_PROTECTED_ENTRY(0x1)";
                break;
            }
            case NPL_PATH_LP_TABLE_ACTION_WIDE_ENTRY:
            {
                return "NPL_PATH_LP_TABLE_ACTION_WIDE_ENTRY(0x2)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_path_lp_table_action_e");
        }
        return "";
    }
    npl_path_lp_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_path_lp_table_value_t element);
std::string to_short_string(struct npl_path_lp_table_value_t element);

/// API-s for table: path_lp_type_decoding_table

typedef enum
{
    NPL_PATH_LP_TYPE_DECODING_TABLE_ACTION_WRITE = 0x0
} npl_path_lp_type_decoding_table_action_e;

struct npl_path_lp_type_decoding_table_key_t
{
    npl_path_lp_entry_type_e type;
    
    npl_path_lp_type_decoding_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_path_lp_type_decoding_table_key_t element);
std::string to_short_string(struct npl_path_lp_type_decoding_table_key_t element);

struct npl_path_lp_type_decoding_table_value_t
{
    npl_path_lp_type_decoding_table_action_e action;
    union npl_path_lp_type_decoding_table_payloads_t {
        npl_resolution_type_decoding_table_result_t path_lp_type_decoding_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_path_lp_type_decoding_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PATH_LP_TYPE_DECODING_TABLE_ACTION_WRITE:
            {
                return "NPL_PATH_LP_TYPE_DECODING_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_path_lp_type_decoding_table_action_e");
        }
        return "";
    }
    npl_path_lp_type_decoding_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_path_lp_type_decoding_table_value_t element);
std::string to_short_string(struct npl_path_lp_type_decoding_table_value_t element);

/// API-s for table: path_protection_table

typedef enum
{
    NPL_PATH_PROTECTION_TABLE_ACTION_WRITE = 0x0
} npl_path_protection_table_action_e;

struct npl_path_protection_table_key_t
{
    npl_path_protection_id_t id;
    
    npl_path_protection_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_path_protection_table_key_t element);
std::string to_short_string(struct npl_path_protection_table_key_t element);

struct npl_path_protection_table_value_t
{
    npl_path_protection_table_action_e action;
    union npl_path_protection_table_payloads_t {
        npl_protection_selector_t path_protection_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_path_protection_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PATH_PROTECTION_TABLE_ACTION_WRITE:
            {
                return "NPL_PATH_PROTECTION_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_path_protection_table_action_e");
        }
        return "";
    }
    npl_path_protection_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_path_protection_table_value_t element);
std::string to_short_string(struct npl_path_protection_table_value_t element);

/// API-s for table: pdoq_oq_ifc_mapping

typedef enum
{
    NPL_PDOQ_OQ_IFC_MAPPING_ACTION_WRITE = 0x0
} npl_pdoq_oq_ifc_mapping_action_e;

struct npl_pdoq_oq_ifc_mapping_key_t
{
    uint64_t dest_oq : 9;
    
    npl_pdoq_oq_ifc_mapping_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_pdoq_oq_ifc_mapping_key_t element);
std::string to_short_string(struct npl_pdoq_oq_ifc_mapping_key_t element);

struct npl_pdoq_oq_ifc_mapping_value_t
{
    npl_pdoq_oq_ifc_mapping_action_e action;
    union npl_pdoq_oq_ifc_mapping_payloads_t {
        npl_pdoq_oq_ifc_mapping_result_t pdoq_oq_ifc_mapping_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_pdoq_oq_ifc_mapping_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PDOQ_OQ_IFC_MAPPING_ACTION_WRITE:
            {
                return "NPL_PDOQ_OQ_IFC_MAPPING_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_pdoq_oq_ifc_mapping_action_e");
        }
        return "";
    }
    npl_pdoq_oq_ifc_mapping_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_pdoq_oq_ifc_mapping_value_t element);
std::string to_short_string(struct npl_pdoq_oq_ifc_mapping_value_t element);

/// API-s for table: pdvoq_bank_pair_offset_table

typedef enum
{
    NPL_PDVOQ_BANK_PAIR_OFFSET_TABLE_ACTION_WRITE = 0x0
} npl_pdvoq_bank_pair_offset_table_action_e;

struct npl_pdvoq_bank_pair_offset_table_key_t
{
    
    
    npl_pdvoq_bank_pair_offset_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_pdvoq_bank_pair_offset_table_key_t element);
std::string to_short_string(struct npl_pdvoq_bank_pair_offset_table_key_t element);

struct npl_pdvoq_bank_pair_offset_table_value_t
{
    npl_pdvoq_bank_pair_offset_table_action_e action;
    union npl_pdvoq_bank_pair_offset_table_payloads_t {
        npl_pdvoq_bank_pair_offset_result_t pdvoq_bank_pair_offset_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_pdvoq_bank_pair_offset_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PDVOQ_BANK_PAIR_OFFSET_TABLE_ACTION_WRITE:
            {
                return "NPL_PDVOQ_BANK_PAIR_OFFSET_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_pdvoq_bank_pair_offset_table_action_e");
        }
        return "";
    }
    npl_pdvoq_bank_pair_offset_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_pdvoq_bank_pair_offset_table_value_t element);
std::string to_short_string(struct npl_pdvoq_bank_pair_offset_table_value_t element);

/// API-s for table: pdvoq_slice_voq_properties_table

typedef enum
{
    NPL_PDVOQ_SLICE_VOQ_PROPERTIES_TABLE_ACTION_WRITE = 0x0
} npl_pdvoq_slice_voq_properties_table_action_e;

struct npl_pdvoq_slice_voq_properties_table_key_t
{
    uint64_t voq_num : 16;
    
    npl_pdvoq_slice_voq_properties_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_pdvoq_slice_voq_properties_table_key_t element);
std::string to_short_string(struct npl_pdvoq_slice_voq_properties_table_key_t element);

struct npl_pdvoq_slice_voq_properties_table_value_t
{
    npl_pdvoq_slice_voq_properties_table_action_e action;
    union npl_pdvoq_slice_voq_properties_table_payloads_t {
        npl_pdvoq_slice_voq_properties_result_t pdvoq_slice_voq_properties_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_pdvoq_slice_voq_properties_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PDVOQ_SLICE_VOQ_PROPERTIES_TABLE_ACTION_WRITE:
            {
                return "NPL_PDVOQ_SLICE_VOQ_PROPERTIES_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_pdvoq_slice_voq_properties_table_action_e");
        }
        return "";
    }
    npl_pdvoq_slice_voq_properties_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_pdvoq_slice_voq_properties_table_value_t element);
std::string to_short_string(struct npl_pdvoq_slice_voq_properties_table_value_t element);

/// API-s for table: per_asbr_and_dpe_table

typedef enum
{
    NPL_PER_ASBR_AND_DPE_TABLE_ACTION_WRITE = 0x0
} npl_per_asbr_and_dpe_table_action_e;

struct npl_per_asbr_and_dpe_table_key_t
{
    uint64_t dpe : 16;
    uint64_t asbr : 16;
    
    npl_per_asbr_and_dpe_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_per_asbr_and_dpe_table_key_t element);
std::string to_short_string(struct npl_per_asbr_and_dpe_table_key_t element);

struct npl_per_asbr_and_dpe_table_value_t
{
    npl_per_asbr_and_dpe_table_action_e action;
    union npl_per_asbr_and_dpe_table_payloads_t {
        npl_large_em_label_encap_data_and_counter_ptr_t large_em_label_encap_data_and_counter_ptr;
    } payloads;
    std::string npl_action_enum_to_string(const npl_per_asbr_and_dpe_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PER_ASBR_AND_DPE_TABLE_ACTION_WRITE:
            {
                return "NPL_PER_ASBR_AND_DPE_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_per_asbr_and_dpe_table_action_e");
        }
        return "";
    }
    npl_per_asbr_and_dpe_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_per_asbr_and_dpe_table_value_t element);
std::string to_short_string(struct npl_per_asbr_and_dpe_table_value_t element);

/// API-s for table: per_pe_and_prefix_vpn_key_large_table

typedef enum
{
    NPL_PER_PE_AND_PREFIX_VPN_KEY_LARGE_TABLE_ACTION_WRITE = 0x0
} npl_per_pe_and_prefix_vpn_key_large_table_action_e;

struct npl_per_pe_and_prefix_vpn_key_large_table_key_t
{
    uint64_t ip_prefix_id : 17;
    uint64_t lsp_destination : 16;
    
    npl_per_pe_and_prefix_vpn_key_large_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_per_pe_and_prefix_vpn_key_large_table_key_t element);
std::string to_short_string(struct npl_per_pe_and_prefix_vpn_key_large_table_key_t element);

struct npl_per_pe_and_prefix_vpn_key_large_table_value_t
{
    npl_per_pe_and_prefix_vpn_key_large_table_action_e action;
    union npl_per_pe_and_prefix_vpn_key_large_table_payloads_t {
        npl_vpn_label_encap_data_t vpn_encap_data;
    } payloads;
    std::string npl_action_enum_to_string(const npl_per_pe_and_prefix_vpn_key_large_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PER_PE_AND_PREFIX_VPN_KEY_LARGE_TABLE_ACTION_WRITE:
            {
                return "NPL_PER_PE_AND_PREFIX_VPN_KEY_LARGE_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_per_pe_and_prefix_vpn_key_large_table_action_e");
        }
        return "";
    }
    npl_per_pe_and_prefix_vpn_key_large_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_per_pe_and_prefix_vpn_key_large_table_value_t element);
std::string to_short_string(struct npl_per_pe_and_prefix_vpn_key_large_table_value_t element);

/// API-s for table: per_pe_and_vrf_vpn_key_large_table

typedef enum
{
    NPL_PER_PE_AND_VRF_VPN_KEY_LARGE_TABLE_ACTION_WRITE = 0x0
} npl_per_pe_and_vrf_vpn_key_large_table_action_e;

struct npl_per_pe_and_vrf_vpn_key_large_table_key_t
{
    npl_l3_relay_id_t l3_relay_id;
    uint64_t lsp_destination : 16;
    
    npl_per_pe_and_vrf_vpn_key_large_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_per_pe_and_vrf_vpn_key_large_table_key_t element);
std::string to_short_string(struct npl_per_pe_and_vrf_vpn_key_large_table_key_t element);

struct npl_per_pe_and_vrf_vpn_key_large_table_value_t
{
    npl_per_pe_and_vrf_vpn_key_large_table_action_e action;
    union npl_per_pe_and_vrf_vpn_key_large_table_payloads_t {
        npl_vpn_label_encap_data_t vpn_encap_data;
    } payloads;
    std::string npl_action_enum_to_string(const npl_per_pe_and_vrf_vpn_key_large_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PER_PE_AND_VRF_VPN_KEY_LARGE_TABLE_ACTION_WRITE:
            {
                return "NPL_PER_PE_AND_VRF_VPN_KEY_LARGE_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_per_pe_and_vrf_vpn_key_large_table_action_e");
        }
        return "";
    }
    npl_per_pe_and_vrf_vpn_key_large_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_per_pe_and_vrf_vpn_key_large_table_value_t element);
std::string to_short_string(struct npl_per_pe_and_vrf_vpn_key_large_table_value_t element);

/// API-s for table: per_port_destination_table

typedef enum
{
    NPL_PER_PORT_DESTINATION_TABLE_ACTION_WRITE = 0x0
} npl_per_port_destination_table_action_e;

struct npl_per_port_destination_table_key_t
{
    uint64_t device_rx_source_if_pif : 5;
    uint64_t device_rx_source_if_ifg : 1;
    
    npl_per_port_destination_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_per_port_destination_table_key_t element);
std::string to_short_string(struct npl_per_port_destination_table_key_t element);

struct npl_per_port_destination_table_value_t
{
    npl_per_port_destination_table_action_e action;
    union npl_per_port_destination_table_payloads_t {
        uint64_t destination_local_vars_fwd_destination : 20;
    } payloads;
    std::string npl_action_enum_to_string(const npl_per_port_destination_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PER_PORT_DESTINATION_TABLE_ACTION_WRITE:
            {
                return "NPL_PER_PORT_DESTINATION_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_per_port_destination_table_action_e");
        }
        return "";
    }
    npl_per_port_destination_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_per_port_destination_table_value_t element);
std::string to_short_string(struct npl_per_port_destination_table_value_t element);

/// API-s for table: per_vrf_mpls_forwarding_table

typedef enum
{
    NPL_PER_VRF_MPLS_FORWARDING_TABLE_ACTION_WRITE = 0x0
} npl_per_vrf_mpls_forwarding_table_action_e;

struct npl_per_vrf_mpls_forwarding_table_key_t
{
    uint64_t label : 20;
    npl_l3_relay_id_t vrf_id;
    
    npl_per_vrf_mpls_forwarding_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_per_vrf_mpls_forwarding_table_key_t element);
std::string to_short_string(struct npl_per_vrf_mpls_forwarding_table_key_t element);

struct npl_per_vrf_mpls_forwarding_table_value_t
{
    npl_per_vrf_mpls_forwarding_table_action_e action;
    union npl_per_vrf_mpls_forwarding_table_payloads_t {
        npl_nhlfe_t nhlfe;
    } payloads;
    std::string npl_action_enum_to_string(const npl_per_vrf_mpls_forwarding_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PER_VRF_MPLS_FORWARDING_TABLE_ACTION_WRITE:
            {
                return "NPL_PER_VRF_MPLS_FORWARDING_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_per_vrf_mpls_forwarding_table_action_e");
        }
        return "";
    }
    npl_per_vrf_mpls_forwarding_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_per_vrf_mpls_forwarding_table_value_t element);
std::string to_short_string(struct npl_per_vrf_mpls_forwarding_table_value_t element);

/// API-s for table: pfc_destination_table

typedef enum
{
    NPL_PFC_DESTINATION_TABLE_ACTION_WRITE = 0x0
} npl_pfc_destination_table_action_e;

struct npl_pfc_destination_table_key_t
{
    uint64_t ssp1 : 16;
    uint64_t ssp2 : 16;
    uint64_t redirect1 : 8;
    uint64_t redirect2 : 8;
    
    npl_pfc_destination_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_pfc_destination_table_key_t element);
std::string to_short_string(struct npl_pfc_destination_table_key_t element);

struct npl_pfc_destination_table_value_t
{
    npl_pfc_destination_table_action_e action;
    union npl_pfc_destination_table_payloads_t {
        npl_pfc_em_lookup_t pfc_em_lookup_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_pfc_destination_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PFC_DESTINATION_TABLE_ACTION_WRITE:
            {
                return "NPL_PFC_DESTINATION_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_pfc_destination_table_action_e");
        }
        return "";
    }
    npl_pfc_destination_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_pfc_destination_table_value_t element);
std::string to_short_string(struct npl_pfc_destination_table_value_t element);

/// API-s for table: pfc_event_queue_table

typedef enum
{
    NPL_PFC_EVENT_QUEUE_TABLE_ACTION_NO_OP = 0x0
} npl_pfc_event_queue_table_action_e;

struct npl_pfc_event_queue_table_key_t
{
    uint64_t slice : 3;
    npl_bool_t cong_state;
    uint64_t tc : 3;
    uint64_t destination : 12;
    
    npl_pfc_event_queue_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_pfc_event_queue_table_key_t element);
std::string to_short_string(struct npl_pfc_event_queue_table_key_t element);

struct npl_pfc_event_queue_table_value_t
{
    npl_pfc_event_queue_table_action_e action;
    std::string npl_action_enum_to_string(const npl_pfc_event_queue_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PFC_EVENT_QUEUE_TABLE_ACTION_NO_OP:
            {
                return "NPL_PFC_EVENT_QUEUE_TABLE_ACTION_NO_OP(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_pfc_event_queue_table_action_e");
        }
        return "";
    }
    npl_pfc_event_queue_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_pfc_event_queue_table_value_t element);
std::string to_short_string(struct npl_pfc_event_queue_table_value_t element);

/// API-s for table: pfc_filter_wd_table

typedef enum
{
    NPL_PFC_FILTER_WD_TABLE_ACTION_PFC_FILTER_WD_ACTION = 0x0
} npl_pfc_filter_wd_table_action_e;

struct npl_pfc_filter_wd_table_pfc_filter_wd_action_payload_t
{
    uint64_t destination : 20;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_pfc_filter_wd_table_pfc_filter_wd_action_payload_t element);
std::string to_short_string(npl_pfc_filter_wd_table_pfc_filter_wd_action_payload_t element);

struct npl_pfc_filter_wd_table_key_t
{
    uint64_t tc : 3;
    uint64_t dsp : 12;
    
    npl_pfc_filter_wd_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_pfc_filter_wd_table_key_t element);
std::string to_short_string(struct npl_pfc_filter_wd_table_key_t element);

struct npl_pfc_filter_wd_table_value_t
{
    npl_pfc_filter_wd_table_action_e action;
    union npl_pfc_filter_wd_table_payloads_t {
        npl_pfc_filter_wd_table_pfc_filter_wd_action_payload_t pfc_filter_wd_action;
    } payloads;
    std::string npl_action_enum_to_string(const npl_pfc_filter_wd_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PFC_FILTER_WD_TABLE_ACTION_PFC_FILTER_WD_ACTION:
            {
                return "NPL_PFC_FILTER_WD_TABLE_ACTION_PFC_FILTER_WD_ACTION(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_pfc_filter_wd_table_action_e");
        }
        return "";
    }
    npl_pfc_filter_wd_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_pfc_filter_wd_table_value_t element);
std::string to_short_string(struct npl_pfc_filter_wd_table_value_t element);

/// API-s for table: pfc_offset_from_vector_static_table

typedef enum
{
    NPL_PFC_OFFSET_FROM_VECTOR_STATIC_TABLE_ACTION_UPDATE_MIRROR_COMMANDS = 0x0
} npl_pfc_offset_from_vector_static_table_action_e;

struct npl_pfc_offset_from_vector_static_table_update_mirror_commands_payload_t
{
    npl_pfc_rx_counter_offset_t offset;
    uint64_t trap : 1;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_pfc_offset_from_vector_static_table_update_mirror_commands_payload_t element);
std::string to_short_string(npl_pfc_offset_from_vector_static_table_update_mirror_commands_payload_t element);

struct npl_pfc_offset_from_vector_static_table_key_t
{
    uint64_t vector : 8;
    
    npl_pfc_offset_from_vector_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_pfc_offset_from_vector_static_table_key_t element);
std::string to_short_string(struct npl_pfc_offset_from_vector_static_table_key_t element);

struct npl_pfc_offset_from_vector_static_table_value_t
{
    npl_pfc_offset_from_vector_static_table_action_e action;
    union npl_pfc_offset_from_vector_static_table_payloads_t {
        npl_pfc_offset_from_vector_static_table_update_mirror_commands_payload_t update_mirror_commands;
    } payloads;
    std::string npl_action_enum_to_string(const npl_pfc_offset_from_vector_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PFC_OFFSET_FROM_VECTOR_STATIC_TABLE_ACTION_UPDATE_MIRROR_COMMANDS:
            {
                return "NPL_PFC_OFFSET_FROM_VECTOR_STATIC_TABLE_ACTION_UPDATE_MIRROR_COMMANDS(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_pfc_offset_from_vector_static_table_action_e");
        }
        return "";
    }
    npl_pfc_offset_from_vector_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_pfc_offset_from_vector_static_table_value_t element);
std::string to_short_string(struct npl_pfc_offset_from_vector_static_table_value_t element);

/// API-s for table: pfc_ssp_slice_map_table

typedef enum
{
    NPL_PFC_SSP_SLICE_MAP_TABLE_ACTION_WRITE = 0x0
} npl_pfc_ssp_slice_map_table_action_e;

struct npl_pfc_ssp_slice_map_table_key_t
{
    uint64_t ssp : 16;
    
    npl_pfc_ssp_slice_map_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_pfc_ssp_slice_map_table_key_t element);
std::string to_short_string(struct npl_pfc_ssp_slice_map_table_key_t element);

struct npl_pfc_ssp_slice_map_table_value_t
{
    npl_pfc_ssp_slice_map_table_action_e action;
    union npl_pfc_ssp_slice_map_table_payloads_t {
        npl_pfc_ssp_info_table_t pfc_ssp_info;
    } payloads;
    std::string npl_action_enum_to_string(const npl_pfc_ssp_slice_map_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PFC_SSP_SLICE_MAP_TABLE_ACTION_WRITE:
            {
                return "NPL_PFC_SSP_SLICE_MAP_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_pfc_ssp_slice_map_table_action_e");
        }
        return "";
    }
    npl_pfc_ssp_slice_map_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_pfc_ssp_slice_map_table_value_t element);
std::string to_short_string(struct npl_pfc_ssp_slice_map_table_value_t element);

/// API-s for table: pfc_tc_latency_table

typedef enum
{
    NPL_PFC_TC_LATENCY_TABLE_ACTION_WRITE = 0x0
} npl_pfc_tc_latency_table_action_e;

struct npl_pfc_tc_latency_table_key_t
{
    uint64_t tc : 3;
    
    npl_pfc_tc_latency_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_pfc_tc_latency_table_key_t element);
std::string to_short_string(struct npl_pfc_tc_latency_table_key_t element);

struct npl_pfc_tc_latency_table_value_t
{
    npl_pfc_tc_latency_table_action_e action;
    union npl_pfc_tc_latency_table_payloads_t {
        npl_pfc_latency_t pfc_latency_threshold;
    } payloads;
    std::string npl_action_enum_to_string(const npl_pfc_tc_latency_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PFC_TC_LATENCY_TABLE_ACTION_WRITE:
            {
                return "NPL_PFC_TC_LATENCY_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_pfc_tc_latency_table_action_e");
        }
        return "";
    }
    npl_pfc_tc_latency_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_pfc_tc_latency_table_value_t element);
std::string to_short_string(struct npl_pfc_tc_latency_table_value_t element);

/// API-s for table: pfc_tc_table

typedef enum
{
    NPL_PFC_TC_TABLE_ACTION_WRITE = 0x0
} npl_pfc_tc_table_action_e;

struct npl_pfc_tc_table_key_t
{
    uint64_t profile : 2;
    uint64_t index : 2;
    
    npl_pfc_tc_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_pfc_tc_table_key_t element);
std::string to_short_string(struct npl_pfc_tc_table_key_t element);

struct npl_pfc_tc_table_value_t
{
    npl_pfc_tc_table_action_e action;
    union npl_pfc_tc_table_payloads_t {
        npl_pfc_quanta_table_result_t pfc_quanta_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_pfc_tc_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PFC_TC_TABLE_ACTION_WRITE:
            {
                return "NPL_PFC_TC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_pfc_tc_table_action_e");
        }
        return "";
    }
    npl_pfc_tc_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_pfc_tc_table_value_t element);
std::string to_short_string(struct npl_pfc_tc_table_value_t element);

/// API-s for table: pfc_tc_wrap_latency_table

typedef enum
{
    NPL_PFC_TC_WRAP_LATENCY_TABLE_ACTION_WRITE = 0x0
} npl_pfc_tc_wrap_latency_table_action_e;

struct npl_pfc_tc_wrap_latency_table_key_t
{
    uint64_t tc : 3;
    
    npl_pfc_tc_wrap_latency_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_pfc_tc_wrap_latency_table_key_t element);
std::string to_short_string(struct npl_pfc_tc_wrap_latency_table_key_t element);

struct npl_pfc_tc_wrap_latency_table_value_t
{
    npl_pfc_tc_wrap_latency_table_action_e action;
    union npl_pfc_tc_wrap_latency_table_payloads_t {
        npl_pfc_latency_t pfc_wrap_latency_threshold;
    } payloads;
    std::string npl_action_enum_to_string(const npl_pfc_tc_wrap_latency_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PFC_TC_WRAP_LATENCY_TABLE_ACTION_WRITE:
            {
                return "NPL_PFC_TC_WRAP_LATENCY_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_pfc_tc_wrap_latency_table_action_e");
        }
        return "";
    }
    npl_pfc_tc_wrap_latency_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_pfc_tc_wrap_latency_table_value_t element);
std::string to_short_string(struct npl_pfc_tc_wrap_latency_table_value_t element);

/// API-s for table: pfc_vector_static_table

typedef enum
{
    NPL_PFC_VECTOR_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_pfc_vector_static_table_action_e;

struct npl_pfc_vector_static_table_key_t
{
    uint64_t tc : 3;
    
    npl_pfc_vector_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_pfc_vector_static_table_key_t element);
std::string to_short_string(struct npl_pfc_vector_static_table_key_t element);

struct npl_pfc_vector_static_table_value_t
{
    npl_pfc_vector_static_table_action_e action;
    union npl_pfc_vector_static_table_payloads_t {
        uint64_t pd_pd_npu_host_receive_fields_pfc_priority_table_vector : 8;
    } payloads;
    std::string npl_action_enum_to_string(const npl_pfc_vector_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PFC_VECTOR_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_PFC_VECTOR_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_pfc_vector_static_table_action_e");
        }
        return "";
    }
    npl_pfc_vector_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_pfc_vector_static_table_value_t element);
std::string to_short_string(struct npl_pfc_vector_static_table_value_t element);

/// API-s for table: pin_start_offset_macros

typedef enum
{
    NPL_PIN_START_OFFSET_MACROS_ACTION_WRITE = 0x0
} npl_pin_start_offset_macros_action_e;

struct npl_pin_start_offset_macros_key_t
{
    
    
    npl_pin_start_offset_macros_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_pin_start_offset_macros_key_t element);
std::string to_short_string(struct npl_pin_start_offset_macros_key_t element);

struct npl_pin_start_offset_macros_value_t
{
    npl_pin_start_offset_macros_action_e action;
    union npl_pin_start_offset_macros_payloads_t {
        npl_select_macros_t select_macros;
    } payloads;
    std::string npl_action_enum_to_string(const npl_pin_start_offset_macros_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PIN_START_OFFSET_MACROS_ACTION_WRITE:
            {
                return "NPL_PIN_START_OFFSET_MACROS_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_pin_start_offset_macros_action_e");
        }
        return "";
    }
    npl_pin_start_offset_macros_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_pin_start_offset_macros_value_t element);
std::string to_short_string(struct npl_pin_start_offset_macros_value_t element);

/// API-s for table: pma_loopback_table

typedef enum
{
    NPL_PMA_LOOPBACK_TABLE_ACTION_WRITE = 0x0
} npl_pma_loopback_table_action_e;

struct npl_pma_loopback_table_key_t
{
    uint64_t device_packet_info_ifg : 1;
    uint64_t device_packet_info_pif : 5;
    
    npl_pma_loopback_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_pma_loopback_table_key_t element);
std::string to_short_string(struct npl_pma_loopback_table_key_t element);

struct npl_pma_loopback_table_value_t
{
    npl_pma_loopback_table_action_e action;
    union npl_pma_loopback_table_payloads_t {
        npl_pma_loopback_data_t pma_loopback_data;
    } payloads;
    std::string npl_action_enum_to_string(const npl_pma_loopback_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PMA_LOOPBACK_TABLE_ACTION_WRITE:
            {
                return "NPL_PMA_LOOPBACK_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_pma_loopback_table_action_e");
        }
        return "";
    }
    npl_pma_loopback_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_pma_loopback_table_value_t element);
std::string to_short_string(struct npl_pma_loopback_table_value_t element);

/// API-s for table: port_dspa_group_size_table

typedef enum
{
    NPL_PORT_DSPA_GROUP_SIZE_TABLE_ACTION_WRITE = 0x0
} npl_port_dspa_group_size_table_action_e;

struct npl_port_dspa_group_size_table_key_t
{
    uint64_t dspa : 13;
    
    npl_port_dspa_group_size_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_port_dspa_group_size_table_key_t element);
std::string to_short_string(struct npl_port_dspa_group_size_table_key_t element);

struct npl_port_dspa_group_size_table_value_t
{
    npl_port_dspa_group_size_table_action_e action;
    union npl_port_dspa_group_size_table_payloads_t {
        npl_lb_group_size_table_result_t dspa_group_size_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_port_dspa_group_size_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PORT_DSPA_GROUP_SIZE_TABLE_ACTION_WRITE:
            {
                return "NPL_PORT_DSPA_GROUP_SIZE_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_port_dspa_group_size_table_action_e");
        }
        return "";
    }
    npl_port_dspa_group_size_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_port_dspa_group_size_table_value_t element);
std::string to_short_string(struct npl_port_dspa_group_size_table_value_t element);

/// API-s for table: port_dspa_table

typedef enum
{
    NPL_PORT_DSPA_TABLE_ACTION_WRITE = 0x0
} npl_port_dspa_table_action_e;

struct npl_port_dspa_table_key_t
{
    uint64_t member_id : 16;
    uint64_t group_id : 14;
    
    npl_port_dspa_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_port_dspa_table_key_t element);
std::string to_short_string(struct npl_port_dspa_table_key_t element);

struct npl_port_dspa_table_value_t
{
    npl_port_dspa_table_action_e action;
    union npl_port_dspa_table_payloads_t {
        npl_port_dspa_table_result_t port_dspa_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_port_dspa_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PORT_DSPA_TABLE_ACTION_WRITE:
            {
                return "NPL_PORT_DSPA_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_port_dspa_table_action_e");
        }
        return "";
    }
    npl_port_dspa_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_port_dspa_table_value_t element);
std::string to_short_string(struct npl_port_dspa_table_value_t element);

/// API-s for table: port_dspa_type_decoding_table

typedef enum
{
    NPL_PORT_DSPA_TYPE_DECODING_TABLE_ACTION_WRITE = 0x0
} npl_port_dspa_type_decoding_table_action_e;

struct npl_port_dspa_type_decoding_table_key_t
{
    npl_port_dspa_entry_type_e type;
    
    npl_port_dspa_type_decoding_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_port_dspa_type_decoding_table_key_t element);
std::string to_short_string(struct npl_port_dspa_type_decoding_table_key_t element);

struct npl_port_dspa_type_decoding_table_value_t
{
    npl_port_dspa_type_decoding_table_action_e action;
    union npl_port_dspa_type_decoding_table_payloads_t {
        npl_resolution_type_decoding_table_result_t port_dspa_type_decoding_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_port_dspa_type_decoding_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PORT_DSPA_TYPE_DECODING_TABLE_ACTION_WRITE:
            {
                return "NPL_PORT_DSPA_TYPE_DECODING_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_port_dspa_type_decoding_table_action_e");
        }
        return "";
    }
    npl_port_dspa_type_decoding_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_port_dspa_type_decoding_table_value_t element);
std::string to_short_string(struct npl_port_dspa_type_decoding_table_value_t element);

/// API-s for table: port_npp_protection_table

typedef enum
{
    NPL_PORT_NPP_PROTECTION_TABLE_ACTION_PROTECTED_DATA = 0x0
} npl_port_npp_protection_table_action_e;

struct npl_port_npp_protection_table_protected_data_payload_t
{
    npl_port_npp_protection_table_result_protected_t data;
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_port_npp_protection_table_protected_data_payload_t element);
std::string to_short_string(npl_port_npp_protection_table_protected_data_payload_t element);

struct npl_port_npp_protection_table_key_t
{
    npl_npp_protection_t npp_protection_id;
    
    npl_port_npp_protection_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_port_npp_protection_table_key_t element);
std::string to_short_string(struct npl_port_npp_protection_table_key_t element);

struct npl_port_npp_protection_table_value_t
{
    npl_port_npp_protection_table_action_e action;
    union npl_port_npp_protection_table_payloads_t {
        npl_port_npp_protection_table_protected_data_payload_t protected_data;
    } payloads;
    std::string npl_action_enum_to_string(const npl_port_npp_protection_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PORT_NPP_PROTECTION_TABLE_ACTION_PROTECTED_DATA:
            {
                return "NPL_PORT_NPP_PROTECTION_TABLE_ACTION_PROTECTED_DATA(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_port_npp_protection_table_action_e");
        }
        return "";
    }
    npl_port_npp_protection_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_port_npp_protection_table_value_t element);
std::string to_short_string(struct npl_port_npp_protection_table_value_t element);

/// API-s for table: port_npp_protection_type_decoding_table

typedef enum
{
    NPL_PORT_NPP_PROTECTION_TYPE_DECODING_TABLE_ACTION_WRITE = 0x0
} npl_port_npp_protection_type_decoding_table_action_e;

struct npl_port_npp_protection_type_decoding_table_key_t
{
    npl_port_npp_protection_entry_type_e type;
    
    npl_port_npp_protection_type_decoding_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_port_npp_protection_type_decoding_table_key_t element);
std::string to_short_string(struct npl_port_npp_protection_type_decoding_table_key_t element);

struct npl_port_npp_protection_type_decoding_table_value_t
{
    npl_port_npp_protection_type_decoding_table_action_e action;
    union npl_port_npp_protection_type_decoding_table_payloads_t {
        npl_resolution_type_decoding_table_result_t port_npp_protection_type_decoding_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_port_npp_protection_type_decoding_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PORT_NPP_PROTECTION_TYPE_DECODING_TABLE_ACTION_WRITE:
            {
                return "NPL_PORT_NPP_PROTECTION_TYPE_DECODING_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_port_npp_protection_type_decoding_table_action_e");
        }
        return "";
    }
    npl_port_npp_protection_type_decoding_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_port_npp_protection_type_decoding_table_value_t element);
std::string to_short_string(struct npl_port_npp_protection_type_decoding_table_value_t element);

/// API-s for table: port_protection_table

typedef enum
{
    NPL_PORT_PROTECTION_TABLE_ACTION_WRITE = 0x0
} npl_port_protection_table_action_e;

struct npl_port_protection_table_key_t
{
    npl_port_protection_id_t id;
    
    npl_port_protection_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_port_protection_table_key_t element);
std::string to_short_string(struct npl_port_protection_table_key_t element);

struct npl_port_protection_table_value_t
{
    npl_port_protection_table_action_e action;
    union npl_port_protection_table_payloads_t {
        npl_protection_selector_t port_protection_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_port_protection_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PORT_PROTECTION_TABLE_ACTION_WRITE:
            {
                return "NPL_PORT_PROTECTION_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_port_protection_table_action_e");
        }
        return "";
    }
    npl_port_protection_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_port_protection_table_value_t element);
std::string to_short_string(struct npl_port_protection_table_value_t element);

/// API-s for table: punt_ethertype_static_table

typedef enum
{
    NPL_PUNT_ETHERTYPE_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_punt_ethertype_static_table_action_e;

struct npl_punt_ethertype_static_table_key_t
{
    uint64_t punt_nw_encap_type : 3;
    npl_punt_header_format_type_e punt_format;
    
    npl_punt_ethertype_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_punt_ethertype_static_table_key_t element);
std::string to_short_string(struct npl_punt_ethertype_static_table_key_t element);

struct npl_punt_ethertype_static_table_value_t
{
    npl_punt_ethertype_static_table_action_e action;
    union npl_punt_ethertype_static_table_payloads_t {
        uint64_t pd_ene_encap_data_punt_ethertype : 16;
    } payloads;
    std::string npl_action_enum_to_string(const npl_punt_ethertype_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PUNT_ETHERTYPE_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_PUNT_ETHERTYPE_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_punt_ethertype_static_table_action_e");
        }
        return "";
    }
    npl_punt_ethertype_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_punt_ethertype_static_table_value_t element);
std::string to_short_string(struct npl_punt_ethertype_static_table_value_t element);

/// API-s for table: punt_rcy_inject_header_ene_encap_table

typedef enum
{
    NPL_PUNT_RCY_INJECT_HEADER_ENE_ENCAP_TABLE_ACTION_FOUND = 0x0
} npl_punt_rcy_inject_header_ene_encap_table_action_e;

struct npl_punt_rcy_inject_header_ene_encap_table_found_payload_t
{
    npl_ene_inject_down_payload_t ene_inject_down_payload;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_punt_rcy_inject_header_ene_encap_table_found_payload_t element);
std::string to_short_string(npl_punt_rcy_inject_header_ene_encap_table_found_payload_t element);

struct npl_punt_rcy_inject_header_ene_encap_table_key_t
{
    npl_punt_nw_encap_ptr_t punt_nw_encap_ptr;
    
    npl_punt_rcy_inject_header_ene_encap_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_punt_rcy_inject_header_ene_encap_table_key_t element);
std::string to_short_string(struct npl_punt_rcy_inject_header_ene_encap_table_key_t element);

struct npl_punt_rcy_inject_header_ene_encap_table_value_t
{
    npl_punt_rcy_inject_header_ene_encap_table_action_e action;
    union npl_punt_rcy_inject_header_ene_encap_table_payloads_t {
        npl_punt_rcy_inject_header_ene_encap_table_found_payload_t found;
    } payloads;
    std::string npl_action_enum_to_string(const npl_punt_rcy_inject_header_ene_encap_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PUNT_RCY_INJECT_HEADER_ENE_ENCAP_TABLE_ACTION_FOUND:
            {
                return "NPL_PUNT_RCY_INJECT_HEADER_ENE_ENCAP_TABLE_ACTION_FOUND(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_punt_rcy_inject_header_ene_encap_table_action_e");
        }
        return "";
    }
    npl_punt_rcy_inject_header_ene_encap_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_punt_rcy_inject_header_ene_encap_table_value_t element);
std::string to_short_string(struct npl_punt_rcy_inject_header_ene_encap_table_value_t element);

/// API-s for table: punt_select_nw_ene_static_table

typedef enum
{
    NPL_PUNT_SELECT_NW_ENE_STATIC_TABLE_ACTION_TX_PUNT_SET_ENE_MACRO = 0x0
} npl_punt_select_nw_ene_static_table_action_e;

struct npl_punt_select_nw_ene_static_table_tx_punt_set_ene_macro_payload_t
{
    npl_ene_macro_id_t first_ene_macro;
    npl_ene_macro_id_t ene_macro_0;
    npl_ene_macro_id_t ene_macro_1;
    npl_ene_macro_id_t ene_macro_2;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_punt_select_nw_ene_static_table_tx_punt_set_ene_macro_payload_t element);
std::string to_short_string(npl_punt_select_nw_ene_static_table_tx_punt_set_ene_macro_payload_t element);

struct npl_punt_select_nw_ene_static_table_key_t
{
    uint64_t is_punt_rcy : 1;
    npl_punt_nw_encap_type_e punt_nw_encap_type;
    
    npl_punt_select_nw_ene_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_punt_select_nw_ene_static_table_key_t element);
std::string to_short_string(struct npl_punt_select_nw_ene_static_table_key_t element);

struct npl_punt_select_nw_ene_static_table_value_t
{
    npl_punt_select_nw_ene_static_table_action_e action;
    union npl_punt_select_nw_ene_static_table_payloads_t {
        npl_punt_select_nw_ene_static_table_tx_punt_set_ene_macro_payload_t tx_punt_set_ene_macro;
    } payloads;
    std::string npl_action_enum_to_string(const npl_punt_select_nw_ene_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PUNT_SELECT_NW_ENE_STATIC_TABLE_ACTION_TX_PUNT_SET_ENE_MACRO:
            {
                return "NPL_PUNT_SELECT_NW_ENE_STATIC_TABLE_ACTION_TX_PUNT_SET_ENE_MACRO(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_punt_select_nw_ene_static_table_action_e");
        }
        return "";
    }
    npl_punt_select_nw_ene_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_punt_select_nw_ene_static_table_value_t element);
std::string to_short_string(struct npl_punt_select_nw_ene_static_table_value_t element);

/// API-s for table: punt_tunnel_transport_encap_table

typedef enum
{
    NPL_PUNT_TUNNEL_TRANSPORT_ENCAP_TABLE_ACTION_IP_GRE = 0x0
} npl_punt_tunnel_transport_encap_table_action_e;

struct npl_punt_tunnel_transport_encap_table_ip_gre_payload_t
{
    uint64_t tos : 8;
    npl_ip_encap_data_t ip_encap_data;
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_punt_tunnel_transport_encap_table_ip_gre_payload_t element);
std::string to_short_string(npl_punt_tunnel_transport_encap_table_ip_gre_payload_t element);

struct npl_punt_tunnel_transport_encap_table_key_t
{
    npl_punt_nw_encap_ptr_t punt_nw_encap_ptr;
    
    npl_punt_tunnel_transport_encap_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_punt_tunnel_transport_encap_table_key_t element);
std::string to_short_string(struct npl_punt_tunnel_transport_encap_table_key_t element);

struct npl_punt_tunnel_transport_encap_table_value_t
{
    npl_punt_tunnel_transport_encap_table_action_e action;
    union npl_punt_tunnel_transport_encap_table_payloads_t {
        npl_punt_tunnel_transport_encap_table_ip_gre_payload_t ip_gre;
    } payloads;
    std::string npl_action_enum_to_string(const npl_punt_tunnel_transport_encap_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PUNT_TUNNEL_TRANSPORT_ENCAP_TABLE_ACTION_IP_GRE:
            {
                return "NPL_PUNT_TUNNEL_TRANSPORT_ENCAP_TABLE_ACTION_IP_GRE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_punt_tunnel_transport_encap_table_action_e");
        }
        return "";
    }
    npl_punt_tunnel_transport_encap_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_punt_tunnel_transport_encap_table_value_t element);
std::string to_short_string(struct npl_punt_tunnel_transport_encap_table_value_t element);

/// API-s for table: punt_tunnel_transport_extended_encap_table

typedef enum
{
    NPL_PUNT_TUNNEL_TRANSPORT_EXTENDED_ENCAP_TABLE_ACTION_WRITE = 0x0
} npl_punt_tunnel_transport_extended_encap_table_action_e;

struct npl_punt_tunnel_transport_extended_encap_table_key_t
{
    npl_punt_nw_encap_ptr_t punt_nw_encap_ptr;
    
    npl_punt_tunnel_transport_extended_encap_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_punt_tunnel_transport_extended_encap_table_key_t element);
std::string to_short_string(struct npl_punt_tunnel_transport_extended_encap_table_key_t element);

struct npl_punt_tunnel_transport_extended_encap_table_value_t
{
    npl_punt_tunnel_transport_extended_encap_table_action_e action;
    union npl_punt_tunnel_transport_extended_encap_table_payloads_t {
        npl_extended_encap_data_t extended_encap_data;
    } payloads;
    std::string npl_action_enum_to_string(const npl_punt_tunnel_transport_extended_encap_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PUNT_TUNNEL_TRANSPORT_EXTENDED_ENCAP_TABLE_ACTION_WRITE:
            {
                return "NPL_PUNT_TUNNEL_TRANSPORT_EXTENDED_ENCAP_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_punt_tunnel_transport_extended_encap_table_action_e");
        }
        return "";
    }
    npl_punt_tunnel_transport_extended_encap_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_punt_tunnel_transport_extended_encap_table_value_t element);
std::string to_short_string(struct npl_punt_tunnel_transport_extended_encap_table_value_t element);

/// API-s for table: punt_tunnel_transport_extended_encap_table2

typedef enum
{
    NPL_PUNT_TUNNEL_TRANSPORT_EXTENDED_ENCAP_TABLE2_ACTION_WRITE = 0x0
} npl_punt_tunnel_transport_extended_encap_table2_action_e;

struct npl_punt_tunnel_transport_extended_encap_table2_key_t
{
    npl_punt_nw_encap_ptr_t punt_nw_encap_ptr;
    
    npl_punt_tunnel_transport_extended_encap_table2_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_punt_tunnel_transport_extended_encap_table2_key_t element);
std::string to_short_string(struct npl_punt_tunnel_transport_extended_encap_table2_key_t element);

struct npl_punt_tunnel_transport_extended_encap_table2_value_t
{
    npl_punt_tunnel_transport_extended_encap_table2_action_e action;
    union npl_punt_tunnel_transport_extended_encap_table2_payloads_t {
        npl_extended_encap_data2_t extended_encap_data2;
    } payloads;
    std::string npl_action_enum_to_string(const npl_punt_tunnel_transport_extended_encap_table2_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PUNT_TUNNEL_TRANSPORT_EXTENDED_ENCAP_TABLE2_ACTION_WRITE:
            {
                return "NPL_PUNT_TUNNEL_TRANSPORT_EXTENDED_ENCAP_TABLE2_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_punt_tunnel_transport_extended_encap_table2_action_e");
        }
        return "";
    }
    npl_punt_tunnel_transport_extended_encap_table2_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_punt_tunnel_transport_extended_encap_table2_value_t element);
std::string to_short_string(struct npl_punt_tunnel_transport_extended_encap_table2_value_t element);

/// API-s for table: pwe_label_table

typedef enum
{
    NPL_PWE_LABEL_TABLE_ACTION_WRITE = 0x0
} npl_pwe_label_table_action_e;

struct npl_pwe_label_table_key_t
{
    uint64_t pwe_id : 14;
    
    npl_pwe_label_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_pwe_label_table_key_t element);
std::string to_short_string(struct npl_pwe_label_table_key_t element);

struct npl_pwe_label_table_value_t
{
    npl_pwe_label_table_action_e action;
    union npl_pwe_label_table_payloads_t {
        npl_vpn_label_encap_data_t vpn_encap_data;
    } payloads;
    std::string npl_action_enum_to_string(const npl_pwe_label_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PWE_LABEL_TABLE_ACTION_WRITE:
            {
                return "NPL_PWE_LABEL_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_pwe_label_table_action_e");
        }
        return "";
    }
    npl_pwe_label_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_pwe_label_table_value_t element);
std::string to_short_string(struct npl_pwe_label_table_value_t element);

/// API-s for table: pwe_to_l3_dest_table

typedef enum
{
    NPL_PWE_TO_L3_DEST_TABLE_ACTION_WRITE = 0x0
} npl_pwe_to_l3_dest_table_action_e;

struct npl_pwe_to_l3_dest_table_key_t
{
    uint64_t pwe_l2_dlp : 20;
    
    npl_pwe_to_l3_dest_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_pwe_to_l3_dest_table_key_t element);
std::string to_short_string(struct npl_pwe_to_l3_dest_table_key_t element);

struct npl_pwe_to_l3_dest_table_value_t
{
    npl_pwe_to_l3_dest_table_action_e action;
    union npl_pwe_to_l3_dest_table_payloads_t {
        npl_pwe_to_l3_lookup_result_t l3_destination;
    } payloads;
    std::string npl_action_enum_to_string(const npl_pwe_to_l3_dest_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PWE_TO_L3_DEST_TABLE_ACTION_WRITE:
            {
                return "NPL_PWE_TO_L3_DEST_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_pwe_to_l3_dest_table_action_e");
        }
        return "";
    }
    npl_pwe_to_l3_dest_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_pwe_to_l3_dest_table_value_t element);
std::string to_short_string(struct npl_pwe_to_l3_dest_table_value_t element);

/// API-s for table: pwe_vpls_label_table

typedef enum
{
    NPL_PWE_VPLS_LABEL_TABLE_ACTION_WRITE = 0x0
} npl_pwe_vpls_label_table_action_e;

struct npl_pwe_vpls_label_table_key_t
{
    npl_l2_relay_id_t l2_relay_id;
    uint64_t lsp_destination : 16;
    
    npl_pwe_vpls_label_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_pwe_vpls_label_table_key_t element);
std::string to_short_string(struct npl_pwe_vpls_label_table_key_t element);

struct npl_pwe_vpls_label_table_value_t
{
    npl_pwe_vpls_label_table_action_e action;
    union npl_pwe_vpls_label_table_payloads_t {
        npl_vpn_label_encap_data_t vpn_encap_data;
    } payloads;
    std::string npl_action_enum_to_string(const npl_pwe_vpls_label_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PWE_VPLS_LABEL_TABLE_ACTION_WRITE:
            {
                return "NPL_PWE_VPLS_LABEL_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_pwe_vpls_label_table_action_e");
        }
        return "";
    }
    npl_pwe_vpls_label_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_pwe_vpls_label_table_value_t element);
std::string to_short_string(struct npl_pwe_vpls_label_table_value_t element);

/// API-s for table: pwe_vpls_tunnel_label_table

typedef enum
{
    NPL_PWE_VPLS_TUNNEL_LABEL_TABLE_ACTION_WRITE = 0x0
} npl_pwe_vpls_tunnel_label_table_action_e;

struct npl_pwe_vpls_tunnel_label_table_key_t
{
    npl_l2_relay_id_t l2_relay_id;
    uint64_t te_tunnel : 16;
    
    npl_pwe_vpls_tunnel_label_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_pwe_vpls_tunnel_label_table_key_t element);
std::string to_short_string(struct npl_pwe_vpls_tunnel_label_table_key_t element);

struct npl_pwe_vpls_tunnel_label_table_value_t
{
    npl_pwe_vpls_tunnel_label_table_action_e action;
    union npl_pwe_vpls_tunnel_label_table_payloads_t {
        npl_vpn_label_encap_data_t vpn_encap_data;
    } payloads;
    std::string npl_action_enum_to_string(const npl_pwe_vpls_tunnel_label_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_PWE_VPLS_TUNNEL_LABEL_TABLE_ACTION_WRITE:
            {
                return "NPL_PWE_VPLS_TUNNEL_LABEL_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_pwe_vpls_tunnel_label_table_action_e");
        }
        return "";
    }
    npl_pwe_vpls_tunnel_label_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_pwe_vpls_tunnel_label_table_value_t element);
std::string to_short_string(struct npl_pwe_vpls_tunnel_label_table_value_t element);

/// API-s for table: reassembly_source_port_map_table

typedef enum
{
    NPL_REASSEMBLY_SOURCE_PORT_MAP_TABLE_ACTION_WRITE = 0x0
} npl_reassembly_source_port_map_table_action_e;

struct npl_reassembly_source_port_map_table_key_t
{
    npl_reassembly_source_port_map_key_t source_if;
    
    npl_reassembly_source_port_map_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_reassembly_source_port_map_table_key_t element);
std::string to_short_string(struct npl_reassembly_source_port_map_table_key_t element);

struct npl_reassembly_source_port_map_table_value_t
{
    npl_reassembly_source_port_map_table_action_e action;
    union npl_reassembly_source_port_map_table_payloads_t {
        npl_reassembly_source_port_map_result_t reassembly_source_port_map_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_reassembly_source_port_map_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_REASSEMBLY_SOURCE_PORT_MAP_TABLE_ACTION_WRITE:
            {
                return "NPL_REASSEMBLY_SOURCE_PORT_MAP_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_reassembly_source_port_map_table_action_e");
        }
        return "";
    }
    npl_reassembly_source_port_map_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_reassembly_source_port_map_table_value_t element);
std::string to_short_string(struct npl_reassembly_source_port_map_table_value_t element);

/// API-s for table: recycle_override_table

typedef enum
{
    NPL_RECYCLE_OVERRIDE_TABLE_ACTION_INIT_RX_DATA = 0x0
} npl_recycle_override_table_action_e;

struct npl_recycle_override_table_init_rx_data_payload_t
{
    uint64_t override_source_port_table : 1;
    uint64_t initial_layer_index : 4;
    npl_pd_rx_nw_app_t_anonymous_union_init_recycle_fields_union_t initial_rx_data;
    npl_tag_swap_cmd_e tag_swap_cmd;
    uint64_t np_macro_id : 5;
    uint64_t fi_macro_id : 6;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_recycle_override_table_init_rx_data_payload_t element);
std::string to_short_string(npl_recycle_override_table_init_rx_data_payload_t element);

struct npl_recycle_override_table_key_t
{
    uint64_t rxpp_npu_input_rcy_code_1_ : 1;
    uint64_t packet_is_rescheduled_recycle : 1;
    uint64_t rxpp_npu_input_tx_to_rx_rcy_data_3_0_ : 4;
    
    npl_recycle_override_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_recycle_override_table_key_t element);
std::string to_short_string(struct npl_recycle_override_table_key_t element);

struct npl_recycle_override_table_value_t
{
    npl_recycle_override_table_action_e action;
    union npl_recycle_override_table_payloads_t {
        npl_recycle_override_table_init_rx_data_payload_t init_rx_data;
    } payloads;
    std::string npl_action_enum_to_string(const npl_recycle_override_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RECYCLE_OVERRIDE_TABLE_ACTION_INIT_RX_DATA:
            {
                return "NPL_RECYCLE_OVERRIDE_TABLE_ACTION_INIT_RX_DATA(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_recycle_override_table_action_e");
        }
        return "";
    }
    npl_recycle_override_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_recycle_override_table_value_t element);
std::string to_short_string(struct npl_recycle_override_table_value_t element);

/// API-s for table: recycled_inject_up_info_table

typedef enum
{
    NPL_RECYCLED_INJECT_UP_INFO_TABLE_ACTION_UPDATE_DATA = 0x0
} npl_recycled_inject_up_info_table_action_e;

struct npl_recycled_inject_up_info_table_update_data_payload_t
{
    uint64_t ssp : 12;
    npl_phb_t phb;
    npl_init_data_selector_e init_data_selector;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_recycled_inject_up_info_table_update_data_payload_t element);
std::string to_short_string(npl_recycled_inject_up_info_table_update_data_payload_t element);

struct npl_recycled_inject_up_info_table_key_t
{
    uint64_t tx_to_rx_rcy_data : 6;
    
    npl_recycled_inject_up_info_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_recycled_inject_up_info_table_key_t element);
std::string to_short_string(struct npl_recycled_inject_up_info_table_key_t element);

struct npl_recycled_inject_up_info_table_value_t
{
    npl_recycled_inject_up_info_table_action_e action;
    union npl_recycled_inject_up_info_table_payloads_t {
        npl_recycled_inject_up_info_table_update_data_payload_t update_data;
    } payloads;
    std::string npl_action_enum_to_string(const npl_recycled_inject_up_info_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RECYCLED_INJECT_UP_INFO_TABLE_ACTION_UPDATE_DATA:
            {
                return "NPL_RECYCLED_INJECT_UP_INFO_TABLE_ACTION_UPDATE_DATA(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_recycled_inject_up_info_table_action_e");
        }
        return "";
    }
    npl_recycled_inject_up_info_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_recycled_inject_up_info_table_value_t element);
std::string to_short_string(struct npl_recycled_inject_up_info_table_value_t element);

/// API-s for table: redirect_destination_table

typedef enum
{
    NPL_REDIRECT_DESTINATION_TABLE_ACTION_WRITE = 0x0
} npl_redirect_destination_table_action_e;

struct npl_redirect_destination_table_key_t
{
    uint64_t device_packet_info_ifg : 1;
    
    npl_redirect_destination_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_redirect_destination_table_key_t element);
std::string to_short_string(struct npl_redirect_destination_table_key_t element);

struct npl_redirect_destination_table_value_t
{
    npl_redirect_destination_table_action_e action;
    union npl_redirect_destination_table_payloads_t {
        npl_redirect_destination_reg_t redirect_destination_reg;
    } payloads;
    std::string npl_action_enum_to_string(const npl_redirect_destination_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_REDIRECT_DESTINATION_TABLE_ACTION_WRITE:
            {
                return "NPL_REDIRECT_DESTINATION_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_redirect_destination_table_action_e");
        }
        return "";
    }
    npl_redirect_destination_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_redirect_destination_table_value_t element);
std::string to_short_string(struct npl_redirect_destination_table_value_t element);

/// API-s for table: redirect_table

typedef enum
{
    NPL_REDIRECT_TABLE_ACTION_WRITE = 0x0
} npl_redirect_table_action_e;

struct npl_redirect_table_key_t
{
    npl_traps_t traps;
    npl_trap_conditions_t trap_conditions;
    
    npl_redirect_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector384_t pack(void) const;
    void unpack(bit_vector384_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_redirect_table_key_t element);
std::string to_short_string(struct npl_redirect_table_key_t element);

struct npl_redirect_table_value_t
{
    npl_redirect_table_action_e action;
    union npl_redirect_table_payloads_t {
        npl_redirect_code_t redirect_code;
    } payloads;
    std::string npl_action_enum_to_string(const npl_redirect_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_REDIRECT_TABLE_ACTION_WRITE:
            {
                return "NPL_REDIRECT_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_redirect_table_action_e");
        }
        return "";
    }
    npl_redirect_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_redirect_table_value_t element);
std::string to_short_string(struct npl_redirect_table_value_t element);

/// API-s for table: resolution_pfc_select_table

typedef enum
{
    NPL_RESOLUTION_PFC_SELECT_TABLE_ACTION_UPDATE_PFC = 0x0
} npl_resolution_pfc_select_table_action_e;

struct npl_resolution_pfc_select_table_update_pfc_payload_t
{
    npl_bool_t pfc_enable;
    uint64_t pfc_sample : 1;
    uint64_t pfc_direct_sample : 1;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_resolution_pfc_select_table_update_pfc_payload_t element);
std::string to_short_string(npl_resolution_pfc_select_table_update_pfc_payload_t element);

struct npl_resolution_pfc_select_table_key_t
{
    uint64_t rx_time : 4;
    uint64_t tc : 3;
    
    npl_resolution_pfc_select_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_resolution_pfc_select_table_key_t element);
std::string to_short_string(struct npl_resolution_pfc_select_table_key_t element);

struct npl_resolution_pfc_select_table_value_t
{
    npl_resolution_pfc_select_table_action_e action;
    union npl_resolution_pfc_select_table_payloads_t {
        npl_resolution_pfc_select_table_update_pfc_payload_t update_pfc;
    } payloads;
    std::string npl_action_enum_to_string(const npl_resolution_pfc_select_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RESOLUTION_PFC_SELECT_TABLE_ACTION_UPDATE_PFC:
            {
                return "NPL_RESOLUTION_PFC_SELECT_TABLE_ACTION_UPDATE_PFC(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_resolution_pfc_select_table_action_e");
        }
        return "";
    }
    npl_resolution_pfc_select_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_resolution_pfc_select_table_value_t element);
std::string to_short_string(struct npl_resolution_pfc_select_table_value_t element);

/// API-s for table: resolution_set_next_macro_table

typedef enum
{
    NPL_RESOLUTION_SET_NEXT_MACRO_TABLE_ACTION_RESOLUTION_SET_NEXT_MACRO = 0x0
} npl_resolution_set_next_macro_table_action_e;

struct npl_resolution_set_next_macro_table_resolution_set_next_macro_payload_t
{
    uint64_t next_is_fwd_done : 1;
    uint64_t pl_inc : 2;
    uint64_t macro_id : 8;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_resolution_set_next_macro_table_resolution_set_next_macro_payload_t element);
std::string to_short_string(npl_resolution_set_next_macro_table_resolution_set_next_macro_payload_t element);

struct npl_resolution_set_next_macro_table_key_t
{
    npl_bool_t is_inject_up;
    uint64_t is_pfc_enable : 1;
    
    npl_resolution_set_next_macro_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_resolution_set_next_macro_table_key_t element);
std::string to_short_string(struct npl_resolution_set_next_macro_table_key_t element);

struct npl_resolution_set_next_macro_table_value_t
{
    npl_resolution_set_next_macro_table_action_e action;
    union npl_resolution_set_next_macro_table_payloads_t {
        npl_resolution_set_next_macro_table_resolution_set_next_macro_payload_t resolution_set_next_macro;
    } payloads;
    std::string npl_action_enum_to_string(const npl_resolution_set_next_macro_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RESOLUTION_SET_NEXT_MACRO_TABLE_ACTION_RESOLUTION_SET_NEXT_MACRO:
            {
                return "NPL_RESOLUTION_SET_NEXT_MACRO_TABLE_ACTION_RESOLUTION_SET_NEXT_MACRO(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_resolution_set_next_macro_table_action_e");
        }
        return "";
    }
    npl_resolution_set_next_macro_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_resolution_set_next_macro_table_value_t element);
std::string to_short_string(struct npl_resolution_set_next_macro_table_value_t element);

/// API-s for table: rewrite_sa_prefix_index_table

typedef enum
{
    NPL_REWRITE_SA_PREFIX_INDEX_TABLE_ACTION_WRITE = 0x0
} npl_rewrite_sa_prefix_index_table_action_e;

struct npl_rewrite_sa_prefix_index_table_key_t
{
    uint64_t rewrite_sa_index : 4;
    
    npl_rewrite_sa_prefix_index_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rewrite_sa_prefix_index_table_key_t element);
std::string to_short_string(struct npl_rewrite_sa_prefix_index_table_key_t element);

struct npl_rewrite_sa_prefix_index_table_value_t
{
    npl_rewrite_sa_prefix_index_table_action_e action;
    union npl_rewrite_sa_prefix_index_table_payloads_t {
        uint64_t sa_msb : 32;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rewrite_sa_prefix_index_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_REWRITE_SA_PREFIX_INDEX_TABLE_ACTION_WRITE:
            {
                return "NPL_REWRITE_SA_PREFIX_INDEX_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rewrite_sa_prefix_index_table_action_e");
        }
        return "";
    }
    npl_rewrite_sa_prefix_index_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rewrite_sa_prefix_index_table_value_t element);
std::string to_short_string(struct npl_rewrite_sa_prefix_index_table_value_t element);

/// API-s for table: rmep_last_time_table

typedef enum
{
    NPL_RMEP_LAST_TIME_TABLE_ACTION_WRITE = 0x0
} npl_rmep_last_time_table_action_e;

struct npl_rmep_last_time_table_key_t
{
    npl_scanner_id_t rmep_key;
    
    npl_rmep_last_time_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rmep_last_time_table_key_t element);
std::string to_short_string(struct npl_rmep_last_time_table_key_t element);

struct npl_rmep_last_time_table_value_t
{
    npl_rmep_last_time_table_action_e action;
    union npl_rmep_last_time_table_payloads_t {
        uint64_t rmep_result_rmep_last_time_result : 32;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rmep_last_time_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RMEP_LAST_TIME_TABLE_ACTION_WRITE:
            {
                return "NPL_RMEP_LAST_TIME_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rmep_last_time_table_action_e");
        }
        return "";
    }
    npl_rmep_last_time_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rmep_last_time_table_value_t element);
std::string to_short_string(struct npl_rmep_last_time_table_value_t element);

/// API-s for table: rmep_state_table

typedef enum
{
    NPL_RMEP_STATE_TABLE_ACTION_WRITE = 0x0
} npl_rmep_state_table_action_e;

struct npl_rmep_state_table_key_t
{
    npl_scanner_id_t rmep_key;
    
    npl_rmep_state_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rmep_state_table_key_t element);
std::string to_short_string(struct npl_rmep_state_table_key_t element);

struct npl_rmep_state_table_value_t
{
    npl_rmep_state_table_action_e action;
    union npl_rmep_state_table_payloads_t {
        npl_rmep_data_t rmep_result_rmep_state_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rmep_state_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RMEP_STATE_TABLE_ACTION_WRITE:
            {
                return "NPL_RMEP_STATE_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rmep_state_table_action_e");
        }
        return "";
    }
    npl_rmep_state_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rmep_state_table_value_t element);
std::string to_short_string(struct npl_rmep_state_table_value_t element);

/// API-s for table: rpf_fec_access_map_table

typedef enum
{
    NPL_RPF_FEC_ACCESS_MAP_TABLE_ACTION_WRITE = 0x0
} npl_rpf_fec_access_map_table_action_e;

struct npl_rpf_fec_access_map_table_key_t
{
    uint64_t prefix : 5;
    
    npl_rpf_fec_access_map_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rpf_fec_access_map_table_key_t element);
std::string to_short_string(struct npl_rpf_fec_access_map_table_key_t element);

struct npl_rpf_fec_access_map_table_value_t
{
    npl_rpf_fec_access_map_table_action_e action;
    union npl_rpf_fec_access_map_table_payloads_t {
        npl_lpm_prefix_fec_access_map_output_t lpm_prefix_fec_access_map;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rpf_fec_access_map_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RPF_FEC_ACCESS_MAP_TABLE_ACTION_WRITE:
            {
                return "NPL_RPF_FEC_ACCESS_MAP_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rpf_fec_access_map_table_action_e");
        }
        return "";
    }
    npl_rpf_fec_access_map_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rpf_fec_access_map_table_value_t element);
std::string to_short_string(struct npl_rpf_fec_access_map_table_value_t element);

/// API-s for table: rpf_fec_table

typedef enum
{
    NPL_RPF_FEC_TABLE_ACTION_FOUND = 0x0
} npl_rpf_fec_table_action_e;

struct npl_rpf_fec_table_found_payload_t
{
    npl_destination_t dst;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_rpf_fec_table_found_payload_t element);
std::string to_short_string(npl_rpf_fec_table_found_payload_t element);

struct npl_rpf_fec_table_key_t
{
    uint64_t fec : 12;
    
    npl_rpf_fec_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rpf_fec_table_key_t element);
std::string to_short_string(struct npl_rpf_fec_table_key_t element);

struct npl_rpf_fec_table_value_t
{
    npl_rpf_fec_table_action_e action;
    union npl_rpf_fec_table_payloads_t {
        npl_rpf_fec_table_found_payload_t found;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rpf_fec_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RPF_FEC_TABLE_ACTION_FOUND:
            {
                return "NPL_RPF_FEC_TABLE_ACTION_FOUND(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rpf_fec_table_action_e");
        }
        return "";
    }
    npl_rpf_fec_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rpf_fec_table_value_t element);
std::string to_short_string(struct npl_rpf_fec_table_value_t element);

/// API-s for table: rtf_conf_set_to_og_pcl_compress_bits_mapping_table

typedef enum
{
    NPL_RTF_CONF_SET_TO_OG_PCL_COMPRESS_BITS_MAPPING_TABLE_ACTION_WRITE = 0x0
} npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_action_e;

struct npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_key_t
{
    npl_lp_rtf_conf_set_t lp_rtf_conf_set;
    npl_rtf_step_t rtf_step;
    
    npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_key_t element);
std::string to_short_string(struct npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_key_t element);

struct npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_value_t
{
    npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_action_e action;
    union npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_payloads_t {
        npl_per_rtf_step_og_pcl_compress_bits_t per_rtf_step_og_pcl_compress_bits;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RTF_CONF_SET_TO_OG_PCL_COMPRESS_BITS_MAPPING_TABLE_ACTION_WRITE:
            {
                return "NPL_RTF_CONF_SET_TO_OG_PCL_COMPRESS_BITS_MAPPING_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_action_e");
        }
        return "";
    }
    npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_value_t element);
std::string to_short_string(struct npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_value_t element);

/// API-s for table: rtf_conf_set_to_og_pcl_ids_mapping_table

typedef enum
{
    NPL_RTF_CONF_SET_TO_OG_PCL_IDS_MAPPING_TABLE_ACTION_WRITE = 0x0
} npl_rtf_conf_set_to_og_pcl_ids_mapping_table_action_e;

struct npl_rtf_conf_set_to_og_pcl_ids_mapping_table_key_t
{
    npl_lp_rtf_conf_set_t lp_rtf_conf_set;
    npl_rtf_step_t rtf_step;
    
    npl_rtf_conf_set_to_og_pcl_ids_mapping_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rtf_conf_set_to_og_pcl_ids_mapping_table_key_t element);
std::string to_short_string(struct npl_rtf_conf_set_to_og_pcl_ids_mapping_table_key_t element);

struct npl_rtf_conf_set_to_og_pcl_ids_mapping_table_value_t
{
    npl_rtf_conf_set_to_og_pcl_ids_mapping_table_action_e action;
    union npl_rtf_conf_set_to_og_pcl_ids_mapping_table_payloads_t {
        npl_per_rtf_step_og_pcl_ids_t per_rtf_step_og_pcl_ids;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rtf_conf_set_to_og_pcl_ids_mapping_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RTF_CONF_SET_TO_OG_PCL_IDS_MAPPING_TABLE_ACTION_WRITE:
            {
                return "NPL_RTF_CONF_SET_TO_OG_PCL_IDS_MAPPING_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rtf_conf_set_to_og_pcl_ids_mapping_table_action_e");
        }
        return "";
    }
    npl_rtf_conf_set_to_og_pcl_ids_mapping_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rtf_conf_set_to_og_pcl_ids_mapping_table_value_t element);
std::string to_short_string(struct npl_rtf_conf_set_to_og_pcl_ids_mapping_table_value_t element);

/// API-s for table: rtf_conf_set_to_post_fwd_stage_mapping_table

typedef enum
{
    NPL_RTF_CONF_SET_TO_POST_FWD_STAGE_MAPPING_TABLE_ACTION_WRITE = 0x0
} npl_rtf_conf_set_to_post_fwd_stage_mapping_table_action_e;

struct npl_rtf_conf_set_to_post_fwd_stage_mapping_table_key_t
{
    npl_lp_rtf_conf_set_t lp_rtf_conf_set;
    npl_ip_version_e ip_version;
    
    npl_rtf_conf_set_to_post_fwd_stage_mapping_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rtf_conf_set_to_post_fwd_stage_mapping_table_key_t element);
std::string to_short_string(struct npl_rtf_conf_set_to_post_fwd_stage_mapping_table_key_t element);

struct npl_rtf_conf_set_to_post_fwd_stage_mapping_table_value_t
{
    npl_rtf_conf_set_to_post_fwd_stage_mapping_table_action_e action;
    union npl_rtf_conf_set_to_post_fwd_stage_mapping_table_payloads_t {
        npl_post_fwd_params_t post_fwd_params;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rtf_conf_set_to_post_fwd_stage_mapping_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RTF_CONF_SET_TO_POST_FWD_STAGE_MAPPING_TABLE_ACTION_WRITE:
            {
                return "NPL_RTF_CONF_SET_TO_POST_FWD_STAGE_MAPPING_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rtf_conf_set_to_post_fwd_stage_mapping_table_action_e");
        }
        return "";
    }
    npl_rtf_conf_set_to_post_fwd_stage_mapping_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rtf_conf_set_to_post_fwd_stage_mapping_table_value_t element);
std::string to_short_string(struct npl_rtf_conf_set_to_post_fwd_stage_mapping_table_value_t element);

/// API-s for table: rtf_next_macro_static_table

typedef enum
{
    NPL_RTF_NEXT_MACRO_STATIC_TABLE_ACTION_SET_MACRO = 0x0
} npl_rtf_next_macro_static_table_action_e;

struct npl_rtf_next_macro_static_table_set_macro_payload_t
{
    uint64_t jump_to_fwd : 1;
    uint64_t pl_inc : 2;
    uint64_t macro_id : 8;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_rtf_next_macro_static_table_set_macro_payload_t element);
std::string to_short_string(npl_rtf_next_macro_static_table_set_macro_payload_t element);

struct npl_rtf_next_macro_static_table_key_t
{
    npl_curr_and_next_prot_type_t curr_and_next_prot_type;
    npl_ipv4_ipv6_init_rtf_stage_t pd_tunnel_ipv4_ipv6_init_rtf_stage;
    npl_rtf_stage_and_type_e next_rtf_stage;
    npl_rtf_compressed_fields_for_next_macro_t rtf_indications;
    
    npl_rtf_next_macro_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rtf_next_macro_static_table_key_t element);
std::string to_short_string(struct npl_rtf_next_macro_static_table_key_t element);

struct npl_rtf_next_macro_static_table_value_t
{
    npl_rtf_next_macro_static_table_action_e action;
    union npl_rtf_next_macro_static_table_payloads_t {
        npl_rtf_next_macro_static_table_set_macro_payload_t set_macro;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rtf_next_macro_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RTF_NEXT_MACRO_STATIC_TABLE_ACTION_SET_MACRO:
            {
                return "NPL_RTF_NEXT_MACRO_STATIC_TABLE_ACTION_SET_MACRO(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rtf_next_macro_static_table_action_e");
        }
        return "";
    }
    npl_rtf_next_macro_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rtf_next_macro_static_table_value_t element);
std::string to_short_string(struct npl_rtf_next_macro_static_table_value_t element);

/// API-s for table: rx_counters_block_config_table

typedef enum
{
    NPL_RX_COUNTERS_BLOCK_CONFIG_TABLE_ACTION_CONFIG = 0x0
} npl_rx_counters_block_config_table_action_e;

struct npl_rx_counters_block_config_table_config_payload_t
{
    uint64_t inc_bank_for_ifg_b : 1;
    uint64_t inc_addr_for_set : 1;
    npl_rx_counters_set_type_e bank_set_type;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_rx_counters_block_config_table_config_payload_t element);
std::string to_short_string(npl_rx_counters_block_config_table_config_payload_t element);

struct npl_rx_counters_block_config_table_key_t
{
    uint64_t counter_block_id : 7;
    
    npl_rx_counters_block_config_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rx_counters_block_config_table_key_t element);
std::string to_short_string(struct npl_rx_counters_block_config_table_key_t element);

struct npl_rx_counters_block_config_table_value_t
{
    npl_rx_counters_block_config_table_action_e action;
    union npl_rx_counters_block_config_table_payloads_t {
        npl_rx_counters_block_config_table_config_payload_t config;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rx_counters_block_config_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RX_COUNTERS_BLOCK_CONFIG_TABLE_ACTION_CONFIG:
            {
                return "NPL_RX_COUNTERS_BLOCK_CONFIG_TABLE_ACTION_CONFIG(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rx_counters_block_config_table_action_e");
        }
        return "";
    }
    npl_rx_counters_block_config_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rx_counters_block_config_table_value_t element);
std::string to_short_string(struct npl_rx_counters_block_config_table_value_t element);

/// API-s for table: rx_fwd_error_handling_counter_table

typedef enum
{
    NPL_RX_FWD_ERROR_HANDLING_COUNTER_TABLE_ACTION_UPDATE_RESULT = 0x0
} npl_rx_fwd_error_handling_counter_table_action_e;

struct npl_rx_fwd_error_handling_counter_table_update_result_payload_t
{
    npl_counter_ptr_t counter;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_rx_fwd_error_handling_counter_table_update_result_payload_t element);
std::string to_short_string(npl_rx_fwd_error_handling_counter_table_update_result_payload_t element);

struct npl_rx_fwd_error_handling_counter_table_key_t
{
    uint64_t ser : 1;
    uint64_t pd_source_if_pif : 5;
    
    npl_rx_fwd_error_handling_counter_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rx_fwd_error_handling_counter_table_key_t element);
std::string to_short_string(struct npl_rx_fwd_error_handling_counter_table_key_t element);

struct npl_rx_fwd_error_handling_counter_table_value_t
{
    npl_rx_fwd_error_handling_counter_table_action_e action;
    union npl_rx_fwd_error_handling_counter_table_payloads_t {
        npl_rx_fwd_error_handling_counter_table_update_result_payload_t update_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rx_fwd_error_handling_counter_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RX_FWD_ERROR_HANDLING_COUNTER_TABLE_ACTION_UPDATE_RESULT:
            {
                return "NPL_RX_FWD_ERROR_HANDLING_COUNTER_TABLE_ACTION_UPDATE_RESULT(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rx_fwd_error_handling_counter_table_action_e");
        }
        return "";
    }
    npl_rx_fwd_error_handling_counter_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rx_fwd_error_handling_counter_table_value_t element);
std::string to_short_string(struct npl_rx_fwd_error_handling_counter_table_value_t element);

/// API-s for table: rx_fwd_error_handling_destination_table

typedef enum
{
    NPL_RX_FWD_ERROR_HANDLING_DESTINATION_TABLE_ACTION_UPDATE_RESULT = 0x0
} npl_rx_fwd_error_handling_destination_table_action_e;

struct npl_rx_fwd_error_handling_destination_table_update_result_payload_t
{
    uint64_t destination : 20;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_rx_fwd_error_handling_destination_table_update_result_payload_t element);
std::string to_short_string(npl_rx_fwd_error_handling_destination_table_update_result_payload_t element);

struct npl_rx_fwd_error_handling_destination_table_key_t
{
    uint64_t ser : 1;
    
    npl_rx_fwd_error_handling_destination_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rx_fwd_error_handling_destination_table_key_t element);
std::string to_short_string(struct npl_rx_fwd_error_handling_destination_table_key_t element);

struct npl_rx_fwd_error_handling_destination_table_value_t
{
    npl_rx_fwd_error_handling_destination_table_action_e action;
    union npl_rx_fwd_error_handling_destination_table_payloads_t {
        npl_rx_fwd_error_handling_destination_table_update_result_payload_t update_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rx_fwd_error_handling_destination_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RX_FWD_ERROR_HANDLING_DESTINATION_TABLE_ACTION_UPDATE_RESULT:
            {
                return "NPL_RX_FWD_ERROR_HANDLING_DESTINATION_TABLE_ACTION_UPDATE_RESULT(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rx_fwd_error_handling_destination_table_action_e");
        }
        return "";
    }
    npl_rx_fwd_error_handling_destination_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rx_fwd_error_handling_destination_table_value_t element);
std::string to_short_string(struct npl_rx_fwd_error_handling_destination_table_value_t element);

/// API-s for table: rx_ip_p_counter_offset_static_table

typedef enum
{
    NPL_RX_IP_P_COUNTER_OFFSET_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_rx_ip_p_counter_offset_static_table_action_e;

struct npl_rx_ip_p_counter_offset_static_table_key_t
{
    npl_ip_ver_mc_t ip_ver_mc;
    uint64_t per_protocol_count : 1;
    
    npl_rx_ip_p_counter_offset_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rx_ip_p_counter_offset_static_table_key_t element);
std::string to_short_string(struct npl_rx_ip_p_counter_offset_static_table_key_t element);

struct npl_rx_ip_p_counter_offset_static_table_value_t
{
    npl_rx_ip_p_counter_offset_static_table_action_e action;
    union npl_rx_ip_p_counter_offset_static_table_payloads_t {
        uint64_t macro_counters_update_counter_0_offset : 3;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rx_ip_p_counter_offset_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RX_IP_P_COUNTER_OFFSET_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_RX_IP_P_COUNTER_OFFSET_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rx_ip_p_counter_offset_static_table_action_e");
        }
        return "";
    }
    npl_rx_ip_p_counter_offset_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rx_ip_p_counter_offset_static_table_value_t element);
std::string to_short_string(struct npl_rx_ip_p_counter_offset_static_table_value_t element);

/// API-s for table: rx_map_npp_to_ssp_table

typedef enum
{
    NPL_RX_MAP_NPP_TO_SSP_TABLE_ACTION_WRITE = 0x0
} npl_rx_map_npp_to_ssp_table_action_e;

struct npl_rx_map_npp_to_ssp_table_key_t
{
    uint64_t npp_attributes_index : 8;
    
    npl_rx_map_npp_to_ssp_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rx_map_npp_to_ssp_table_key_t element);
std::string to_short_string(struct npl_rx_map_npp_to_ssp_table_key_t element);

struct npl_rx_map_npp_to_ssp_table_value_t
{
    npl_rx_map_npp_to_ssp_table_action_e action;
    union npl_rx_map_npp_to_ssp_table_payloads_t {
        npl_punt_ssp_attributes_t local_npp_to_ssp_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rx_map_npp_to_ssp_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RX_MAP_NPP_TO_SSP_TABLE_ACTION_WRITE:
            {
                return "NPL_RX_MAP_NPP_TO_SSP_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rx_map_npp_to_ssp_table_action_e");
        }
        return "";
    }
    npl_rx_map_npp_to_ssp_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rx_map_npp_to_ssp_table_value_t element);
std::string to_short_string(struct npl_rx_map_npp_to_ssp_table_value_t element);

/// API-s for table: rx_meter_block_meter_attribute_table

typedef enum
{
    NPL_RX_METER_BLOCK_METER_ATTRIBUTE_TABLE_ACTION_WRITE = 0x0
} npl_rx_meter_block_meter_attribute_table_action_e;

struct npl_rx_meter_block_meter_attribute_table_key_t
{
    npl_exact_bank_index_len_t bank_index;
    npl_exact_meter_index_len_t meter_index;
    
    npl_rx_meter_block_meter_attribute_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rx_meter_block_meter_attribute_table_key_t element);
std::string to_short_string(struct npl_rx_meter_block_meter_attribute_table_key_t element);

struct npl_rx_meter_block_meter_attribute_table_value_t
{
    npl_rx_meter_block_meter_attribute_table_action_e action;
    union npl_rx_meter_block_meter_attribute_table_payloads_t {
        npl_rx_meter_block_meter_attribute_result_t rx_meter_block_meter_attribute_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rx_meter_block_meter_attribute_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RX_METER_BLOCK_METER_ATTRIBUTE_TABLE_ACTION_WRITE:
            {
                return "NPL_RX_METER_BLOCK_METER_ATTRIBUTE_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rx_meter_block_meter_attribute_table_action_e");
        }
        return "";
    }
    npl_rx_meter_block_meter_attribute_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rx_meter_block_meter_attribute_table_value_t element);
std::string to_short_string(struct npl_rx_meter_block_meter_attribute_table_value_t element);

/// API-s for table: rx_meter_block_meter_profile_table

typedef enum
{
    NPL_RX_METER_BLOCK_METER_PROFILE_TABLE_ACTION_WRITE = 0x0
} npl_rx_meter_block_meter_profile_table_action_e;

struct npl_rx_meter_block_meter_profile_table_key_t
{
    npl_exact_bank_index_len_t bank_index;
    npl_meter_profile_len_t meter_profile_index;
    
    npl_rx_meter_block_meter_profile_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rx_meter_block_meter_profile_table_key_t element);
std::string to_short_string(struct npl_rx_meter_block_meter_profile_table_key_t element);

struct npl_rx_meter_block_meter_profile_table_value_t
{
    npl_rx_meter_block_meter_profile_table_action_e action;
    union npl_rx_meter_block_meter_profile_table_payloads_t {
        npl_rx_meter_block_meter_profile_result_t rx_meter_block_meter_profile_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rx_meter_block_meter_profile_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RX_METER_BLOCK_METER_PROFILE_TABLE_ACTION_WRITE:
            {
                return "NPL_RX_METER_BLOCK_METER_PROFILE_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rx_meter_block_meter_profile_table_action_e");
        }
        return "";
    }
    npl_rx_meter_block_meter_profile_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rx_meter_block_meter_profile_table_value_t element);
std::string to_short_string(struct npl_rx_meter_block_meter_profile_table_value_t element);

/// API-s for table: rx_meter_block_meter_shaper_configuration_table

typedef enum
{
    NPL_RX_METER_BLOCK_METER_SHAPER_CONFIGURATION_TABLE_ACTION_WRITE = 0x0
} npl_rx_meter_block_meter_shaper_configuration_table_action_e;

struct npl_rx_meter_block_meter_shaper_configuration_table_key_t
{
    npl_exact_bank_index_len_t bank_index;
    npl_exact_meter_index_len_t meter_index;
    
    npl_rx_meter_block_meter_shaper_configuration_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rx_meter_block_meter_shaper_configuration_table_key_t element);
std::string to_short_string(struct npl_rx_meter_block_meter_shaper_configuration_table_key_t element);

struct npl_rx_meter_block_meter_shaper_configuration_table_value_t
{
    npl_rx_meter_block_meter_shaper_configuration_table_action_e action;
    union npl_rx_meter_block_meter_shaper_configuration_table_payloads_t {
        npl_rx_meter_block_meter_shaper_configuration_result_t rx_meter_block_meter_shaper_configuration_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rx_meter_block_meter_shaper_configuration_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RX_METER_BLOCK_METER_SHAPER_CONFIGURATION_TABLE_ACTION_WRITE:
            {
                return "NPL_RX_METER_BLOCK_METER_SHAPER_CONFIGURATION_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rx_meter_block_meter_shaper_configuration_table_action_e");
        }
        return "";
    }
    npl_rx_meter_block_meter_shaper_configuration_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rx_meter_block_meter_shaper_configuration_table_value_t element);
std::string to_short_string(struct npl_rx_meter_block_meter_shaper_configuration_table_value_t element);

/// API-s for table: rx_meter_distributed_meter_profile_table

typedef enum
{
    NPL_RX_METER_DISTRIBUTED_METER_PROFILE_TABLE_ACTION_WRITE = 0x0
} npl_rx_meter_distributed_meter_profile_table_action_e;

struct npl_rx_meter_distributed_meter_profile_table_key_t
{
    npl_stat_bank_index_len_t bank_index;
    npl_meter_profile_len_t meter_profile_index;
    
    npl_rx_meter_distributed_meter_profile_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rx_meter_distributed_meter_profile_table_key_t element);
std::string to_short_string(struct npl_rx_meter_distributed_meter_profile_table_key_t element);

struct npl_rx_meter_distributed_meter_profile_table_value_t
{
    npl_rx_meter_distributed_meter_profile_table_action_e action;
    union npl_rx_meter_distributed_meter_profile_table_payloads_t {
        npl_rx_meter_distributed_meter_profile_result_t rx_meter_distributed_meter_profile_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rx_meter_distributed_meter_profile_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RX_METER_DISTRIBUTED_METER_PROFILE_TABLE_ACTION_WRITE:
            {
                return "NPL_RX_METER_DISTRIBUTED_METER_PROFILE_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rx_meter_distributed_meter_profile_table_action_e");
        }
        return "";
    }
    npl_rx_meter_distributed_meter_profile_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rx_meter_distributed_meter_profile_table_value_t element);
std::string to_short_string(struct npl_rx_meter_distributed_meter_profile_table_value_t element);

/// API-s for table: rx_meter_exact_meter_decision_mapping_table

typedef enum
{
    NPL_RX_METER_EXACT_METER_DECISION_MAPPING_TABLE_ACTION_WRITE = 0x0
} npl_rx_meter_exact_meter_decision_mapping_table_action_e;

struct npl_rx_meter_exact_meter_decision_mapping_table_key_t
{
    npl_ifg_len_t ifg;
    npl_meter_action_profile_len_t meter_action_profile_index;
    npl_color_len_t rate_limiter_result_color;
    npl_color_len_t meter_result_color;
    
    npl_rx_meter_exact_meter_decision_mapping_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rx_meter_exact_meter_decision_mapping_table_key_t element);
std::string to_short_string(struct npl_rx_meter_exact_meter_decision_mapping_table_key_t element);

struct npl_rx_meter_exact_meter_decision_mapping_table_value_t
{
    npl_rx_meter_exact_meter_decision_mapping_table_action_e action;
    union npl_rx_meter_exact_meter_decision_mapping_table_payloads_t {
        npl_rx_meter_exact_meter_decision_mapping_result_t rx_meter_exact_meter_decision_mapping_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rx_meter_exact_meter_decision_mapping_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RX_METER_EXACT_METER_DECISION_MAPPING_TABLE_ACTION_WRITE:
            {
                return "NPL_RX_METER_EXACT_METER_DECISION_MAPPING_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rx_meter_exact_meter_decision_mapping_table_action_e");
        }
        return "";
    }
    npl_rx_meter_exact_meter_decision_mapping_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rx_meter_exact_meter_decision_mapping_table_value_t element);
std::string to_short_string(struct npl_rx_meter_exact_meter_decision_mapping_table_value_t element);

/// API-s for table: rx_meter_meter_profile_table

typedef enum
{
    NPL_RX_METER_METER_PROFILE_TABLE_ACTION_WRITE = 0x0
} npl_rx_meter_meter_profile_table_action_e;

struct npl_rx_meter_meter_profile_table_key_t
{
    npl_stat_bank_index_len_t bank_index;
    npl_meter_profile_len_t meter_profile_index;
    
    npl_rx_meter_meter_profile_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rx_meter_meter_profile_table_key_t element);
std::string to_short_string(struct npl_rx_meter_meter_profile_table_key_t element);

struct npl_rx_meter_meter_profile_table_value_t
{
    npl_rx_meter_meter_profile_table_action_e action;
    union npl_rx_meter_meter_profile_table_payloads_t {
        npl_rx_meter_meter_profile_result_t rx_meter_meter_profile_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rx_meter_meter_profile_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RX_METER_METER_PROFILE_TABLE_ACTION_WRITE:
            {
                return "NPL_RX_METER_METER_PROFILE_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rx_meter_meter_profile_table_action_e");
        }
        return "";
    }
    npl_rx_meter_meter_profile_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rx_meter_meter_profile_table_value_t element);
std::string to_short_string(struct npl_rx_meter_meter_profile_table_value_t element);

/// API-s for table: rx_meter_meter_shaper_configuration_table

typedef enum
{
    NPL_RX_METER_METER_SHAPER_CONFIGURATION_TABLE_ACTION_WRITE = 0x0
} npl_rx_meter_meter_shaper_configuration_table_action_e;

struct npl_rx_meter_meter_shaper_configuration_table_key_t
{
    npl_stat_bank_index_len_t bank_index;
    npl_stat_meter_index_len_t meter_index;
    
    npl_rx_meter_meter_shaper_configuration_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rx_meter_meter_shaper_configuration_table_key_t element);
std::string to_short_string(struct npl_rx_meter_meter_shaper_configuration_table_key_t element);

struct npl_rx_meter_meter_shaper_configuration_table_value_t
{
    npl_rx_meter_meter_shaper_configuration_table_action_e action;
    union npl_rx_meter_meter_shaper_configuration_table_payloads_t {
        npl_rx_meter_meter_shaper_configuration_result_t rx_meter_meter_shaper_configuration_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rx_meter_meter_shaper_configuration_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RX_METER_METER_SHAPER_CONFIGURATION_TABLE_ACTION_WRITE:
            {
                return "NPL_RX_METER_METER_SHAPER_CONFIGURATION_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rx_meter_meter_shaper_configuration_table_action_e");
        }
        return "";
    }
    npl_rx_meter_meter_shaper_configuration_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rx_meter_meter_shaper_configuration_table_value_t element);
std::string to_short_string(struct npl_rx_meter_meter_shaper_configuration_table_value_t element);

/// API-s for table: rx_meter_meters_attribute_table

typedef enum
{
    NPL_RX_METER_METERS_ATTRIBUTE_TABLE_ACTION_WRITE = 0x0
} npl_rx_meter_meters_attribute_table_action_e;

struct npl_rx_meter_meters_attribute_table_key_t
{
    npl_stat_bank_index_len_t bank_index;
    npl_stat_meter_index_len_t meter_index;
    
    npl_rx_meter_meters_attribute_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rx_meter_meters_attribute_table_key_t element);
std::string to_short_string(struct npl_rx_meter_meters_attribute_table_key_t element);

struct npl_rx_meter_meters_attribute_table_value_t
{
    npl_rx_meter_meters_attribute_table_action_e action;
    union npl_rx_meter_meters_attribute_table_payloads_t {
        npl_rx_meter_meters_attribute_result_t rx_meter_meters_attribute_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rx_meter_meters_attribute_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RX_METER_METERS_ATTRIBUTE_TABLE_ACTION_WRITE:
            {
                return "NPL_RX_METER_METERS_ATTRIBUTE_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rx_meter_meters_attribute_table_action_e");
        }
        return "";
    }
    npl_rx_meter_meters_attribute_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rx_meter_meters_attribute_table_value_t element);
std::string to_short_string(struct npl_rx_meter_meters_attribute_table_value_t element);

/// API-s for table: rx_meter_rate_limiter_shaper_configuration_table

typedef enum
{
    NPL_RX_METER_RATE_LIMITER_SHAPER_CONFIGURATION_TABLE_ACTION_WRITE = 0x0
} npl_rx_meter_rate_limiter_shaper_configuration_table_action_e;

struct npl_rx_meter_rate_limiter_shaper_configuration_table_key_t
{
    npl_g_ifg_len_t table_index;
    npl_rate_limiters_port_packet_type_index_len_t table_entry_index;
    
    npl_rx_meter_rate_limiter_shaper_configuration_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rx_meter_rate_limiter_shaper_configuration_table_key_t element);
std::string to_short_string(struct npl_rx_meter_rate_limiter_shaper_configuration_table_key_t element);

struct npl_rx_meter_rate_limiter_shaper_configuration_table_value_t
{
    npl_rx_meter_rate_limiter_shaper_configuration_table_action_e action;
    union npl_rx_meter_rate_limiter_shaper_configuration_table_payloads_t {
        npl_rx_meter_rate_limiter_shaper_configuration_result_t rx_meter_rate_limiter_shaper_configuration_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rx_meter_rate_limiter_shaper_configuration_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RX_METER_RATE_LIMITER_SHAPER_CONFIGURATION_TABLE_ACTION_WRITE:
            {
                return "NPL_RX_METER_RATE_LIMITER_SHAPER_CONFIGURATION_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rx_meter_rate_limiter_shaper_configuration_table_action_e");
        }
        return "";
    }
    npl_rx_meter_rate_limiter_shaper_configuration_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rx_meter_rate_limiter_shaper_configuration_table_value_t element);
std::string to_short_string(struct npl_rx_meter_rate_limiter_shaper_configuration_table_value_t element);

/// API-s for table: rx_meter_stat_meter_decision_mapping_table

typedef enum
{
    NPL_RX_METER_STAT_METER_DECISION_MAPPING_TABLE_ACTION_WRITE = 0x0
} npl_rx_meter_stat_meter_decision_mapping_table_action_e;

struct npl_rx_meter_stat_meter_decision_mapping_table_key_t
{
    npl_stat_bank_index_len_t meter_bank_index;
    npl_meter_action_profile_len_t meter_action_profile_index;
    npl_color_len_t exact_meter_to_stat_meter_color;
    npl_color_len_t meter_result_color;
    
    npl_rx_meter_stat_meter_decision_mapping_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rx_meter_stat_meter_decision_mapping_table_key_t element);
std::string to_short_string(struct npl_rx_meter_stat_meter_decision_mapping_table_key_t element);

struct npl_rx_meter_stat_meter_decision_mapping_table_value_t
{
    npl_rx_meter_stat_meter_decision_mapping_table_action_e action;
    union npl_rx_meter_stat_meter_decision_mapping_table_payloads_t {
        npl_rx_meter_stat_meter_decision_mapping_result_t rx_meter_stat_meter_decision_mapping_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rx_meter_stat_meter_decision_mapping_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RX_METER_STAT_METER_DECISION_MAPPING_TABLE_ACTION_WRITE:
            {
                return "NPL_RX_METER_STAT_METER_DECISION_MAPPING_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rx_meter_stat_meter_decision_mapping_table_action_e");
        }
        return "";
    }
    npl_rx_meter_stat_meter_decision_mapping_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rx_meter_stat_meter_decision_mapping_table_value_t element);
std::string to_short_string(struct npl_rx_meter_stat_meter_decision_mapping_table_value_t element);

/// API-s for table: rx_npu_to_tm_dest_table

typedef enum
{
    NPL_RX_NPU_TO_TM_DEST_TABLE_ACTION_WRITE = 0x0
} npl_rx_npu_to_tm_dest_table_action_e;

struct npl_rx_npu_to_tm_dest_table_key_t
{
    uint64_t rxpp_pd_fwd_destination_19_14_ : 6;
    
    npl_rx_npu_to_tm_dest_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rx_npu_to_tm_dest_table_key_t element);
std::string to_short_string(struct npl_rx_npu_to_tm_dest_table_key_t element);

struct npl_rx_npu_to_tm_dest_table_value_t
{
    npl_rx_npu_to_tm_dest_table_action_e action;
    union npl_rx_npu_to_tm_dest_table_payloads_t {
        uint64_t pd_rx_tm_destination_prefix : 6;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rx_npu_to_tm_dest_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RX_NPU_TO_TM_DEST_TABLE_ACTION_WRITE:
            {
                return "NPL_RX_NPU_TO_TM_DEST_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rx_npu_to_tm_dest_table_action_e");
        }
        return "";
    }
    npl_rx_npu_to_tm_dest_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rx_npu_to_tm_dest_table_value_t element);
std::string to_short_string(struct npl_rx_npu_to_tm_dest_table_value_t element);

/// API-s for table: rx_obm_code_table

typedef enum
{
    NPL_RX_OBM_CODE_TABLE_ACTION_RX_OBM_ACTION = 0x0
} npl_rx_obm_code_table_action_e;

struct npl_rx_obm_code_table_rx_obm_action_payload_t
{
    npl_phb_t phb;
    npl_destination_t destination;
    npl_punt_encap_data_lsb_t punt_encap_data_lsb;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_rx_obm_code_table_rx_obm_action_payload_t element);
std::string to_short_string(npl_rx_obm_code_table_rx_obm_action_payload_t element);

struct npl_rx_obm_code_table_key_t
{
    npl_tx_to_rx_rcy_data_t tx_to_rx_rcy_data;
    
    npl_rx_obm_code_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rx_obm_code_table_key_t element);
std::string to_short_string(struct npl_rx_obm_code_table_key_t element);

struct npl_rx_obm_code_table_value_t
{
    npl_rx_obm_code_table_action_e action;
    union npl_rx_obm_code_table_payloads_t {
        npl_rx_obm_code_table_rx_obm_action_payload_t rx_obm_action;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rx_obm_code_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RX_OBM_CODE_TABLE_ACTION_RX_OBM_ACTION:
            {
                return "NPL_RX_OBM_CODE_TABLE_ACTION_RX_OBM_ACTION(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rx_obm_code_table_action_e");
        }
        return "";
    }
    npl_rx_obm_code_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rx_obm_code_table_value_t element);
std::string to_short_string(struct npl_rx_obm_code_table_value_t element);

/// API-s for table: rx_obm_punt_src_and_code_table

typedef enum
{
    NPL_RX_OBM_PUNT_SRC_AND_CODE_TABLE_ACTION_WRITE = 0x0
} npl_rx_obm_punt_src_and_code_table_action_e;

struct npl_rx_obm_punt_src_and_code_table_key_t
{
    npl_punt_nw_encap_type_e is_dma;
    uint64_t punt_src_and_code : 12;
    
    npl_rx_obm_punt_src_and_code_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rx_obm_punt_src_and_code_table_key_t element);
std::string to_short_string(struct npl_rx_obm_punt_src_and_code_table_key_t element);

struct npl_rx_obm_punt_src_and_code_table_value_t
{
    npl_rx_obm_punt_src_and_code_table_action_e action;
    union npl_rx_obm_punt_src_and_code_table_payloads_t {
        npl_rx_obm_punt_src_and_code_data_t rx_obm_punt_src_and_code_data;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rx_obm_punt_src_and_code_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RX_OBM_PUNT_SRC_AND_CODE_TABLE_ACTION_WRITE:
            {
                return "NPL_RX_OBM_PUNT_SRC_AND_CODE_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rx_obm_punt_src_and_code_table_action_e");
        }
        return "";
    }
    npl_rx_obm_punt_src_and_code_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rx_obm_punt_src_and_code_table_value_t element);
std::string to_short_string(struct npl_rx_obm_punt_src_and_code_table_value_t element);

/// API-s for table: rx_redirect_code_ext_table

typedef enum
{
    NPL_RX_REDIRECT_CODE_EXT_TABLE_ACTION_RX_REDIRECT_ACTION_EXT = 0x0
} npl_rx_redirect_code_ext_table_action_e;

struct npl_rx_redirect_code_ext_table_rx_redirect_action_ext_payload_t
{
    npl_counter_ptr_t meter_counter;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_rx_redirect_code_ext_table_rx_redirect_action_ext_payload_t element);
std::string to_short_string(npl_rx_redirect_code_ext_table_rx_redirect_action_ext_payload_t element);

struct npl_rx_redirect_code_ext_table_key_t
{
    uint64_t redirect_code : 8;
    
    npl_rx_redirect_code_ext_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rx_redirect_code_ext_table_key_t element);
std::string to_short_string(struct npl_rx_redirect_code_ext_table_key_t element);

struct npl_rx_redirect_code_ext_table_value_t
{
    npl_rx_redirect_code_ext_table_action_e action;
    union npl_rx_redirect_code_ext_table_payloads_t {
        npl_rx_redirect_code_ext_table_rx_redirect_action_ext_payload_t rx_redirect_action_ext;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rx_redirect_code_ext_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RX_REDIRECT_CODE_EXT_TABLE_ACTION_RX_REDIRECT_ACTION_EXT:
            {
                return "NPL_RX_REDIRECT_CODE_EXT_TABLE_ACTION_RX_REDIRECT_ACTION_EXT(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rx_redirect_code_ext_table_action_e");
        }
        return "";
    }
    npl_rx_redirect_code_ext_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rx_redirect_code_ext_table_value_t element);
std::string to_short_string(struct npl_rx_redirect_code_ext_table_value_t element);

/// API-s for table: rx_redirect_code_table

typedef enum
{
    NPL_RX_REDIRECT_CODE_TABLE_ACTION_RX_REDIRECT_ACTION = 0x0
} npl_rx_redirect_code_table_action_e;

struct npl_rx_redirect_code_table_rx_redirect_action_payload_t
{
    uint64_t override_phb : 1;
    npl_per_pif_trap_mode_e per_pif_trap_mode;
    npl_stamp_on_headers_e stamp_into_packet_header;
    uint64_t punt_sub_code : 4;
    uint64_t disable_snoop : 1;
    uint64_t is_l3_trap : 1;
    npl_phb_t phb;
    uint64_t destination : 20;
    npl_ts_command_t ts_cmd;
    npl_lm_command_t cntr_stamp_cmd;
    npl_punt_encap_data_lsb_t punt_encap_data_lsb;
    npl_counter_ptr_t redirect_counter;
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_rx_redirect_code_table_rx_redirect_action_payload_t element);
std::string to_short_string(npl_rx_redirect_code_table_rx_redirect_action_payload_t element);

struct npl_rx_redirect_code_table_key_t
{
    uint64_t redirect_code : 8;
    
    npl_rx_redirect_code_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rx_redirect_code_table_key_t element);
std::string to_short_string(struct npl_rx_redirect_code_table_key_t element);

struct npl_rx_redirect_code_table_value_t
{
    npl_rx_redirect_code_table_action_e action;
    union npl_rx_redirect_code_table_payloads_t {
        npl_rx_redirect_code_table_rx_redirect_action_payload_t rx_redirect_action;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rx_redirect_code_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RX_REDIRECT_CODE_TABLE_ACTION_RX_REDIRECT_ACTION:
            {
                return "NPL_RX_REDIRECT_CODE_TABLE_ACTION_RX_REDIRECT_ACTION(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rx_redirect_code_table_action_e");
        }
        return "";
    }
    npl_rx_redirect_code_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rx_redirect_code_table_value_t element);
std::string to_short_string(struct npl_rx_redirect_code_table_value_t element);

/// API-s for table: rx_redirect_next_macro_static_table

typedef enum
{
    NPL_RX_REDIRECT_NEXT_MACRO_STATIC_TABLE_ACTION_UPDATE_NEXT_MACRO = 0x0
} npl_rx_redirect_next_macro_static_table_action_e;

struct npl_rx_redirect_next_macro_static_table_update_next_macro_payload_t
{
    uint64_t is_last_rx_macro : 1;
    uint64_t pl_inc : 2;
    uint64_t macro_id : 8;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_rx_redirect_next_macro_static_table_update_next_macro_payload_t element);
std::string to_short_string(npl_rx_redirect_next_macro_static_table_update_next_macro_payload_t element);

struct npl_rx_redirect_next_macro_static_table_key_t
{
    npl_punt_cud_type_e cud_type;
    uint64_t redirect_code : 8;
    npl_protocol_type_e protocol_type;
    npl_protocol_type_e next_protocol_type;
    
    npl_rx_redirect_next_macro_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rx_redirect_next_macro_static_table_key_t element);
std::string to_short_string(struct npl_rx_redirect_next_macro_static_table_key_t element);

struct npl_rx_redirect_next_macro_static_table_value_t
{
    npl_rx_redirect_next_macro_static_table_action_e action;
    union npl_rx_redirect_next_macro_static_table_payloads_t {
        npl_rx_redirect_next_macro_static_table_update_next_macro_payload_t update_next_macro;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rx_redirect_next_macro_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RX_REDIRECT_NEXT_MACRO_STATIC_TABLE_ACTION_UPDATE_NEXT_MACRO:
            {
                return "NPL_RX_REDIRECT_NEXT_MACRO_STATIC_TABLE_ACTION_UPDATE_NEXT_MACRO(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rx_redirect_next_macro_static_table_action_e");
        }
        return "";
    }
    npl_rx_redirect_next_macro_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rx_redirect_next_macro_static_table_value_t element);
std::string to_short_string(struct npl_rx_redirect_next_macro_static_table_value_t element);

/// API-s for table: rx_term_error_handling_counter_table

typedef enum
{
    NPL_RX_TERM_ERROR_HANDLING_COUNTER_TABLE_ACTION_UPDATE_RESULT = 0x0
} npl_rx_term_error_handling_counter_table_action_e;

struct npl_rx_term_error_handling_counter_table_update_result_payload_t
{
    npl_counter_ptr_t counter;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_rx_term_error_handling_counter_table_update_result_payload_t element);
std::string to_short_string(npl_rx_term_error_handling_counter_table_update_result_payload_t element);

struct npl_rx_term_error_handling_counter_table_key_t
{
    uint64_t ser : 1;
    uint64_t pd_source_if_pif : 5;
    
    npl_rx_term_error_handling_counter_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rx_term_error_handling_counter_table_key_t element);
std::string to_short_string(struct npl_rx_term_error_handling_counter_table_key_t element);

struct npl_rx_term_error_handling_counter_table_value_t
{
    npl_rx_term_error_handling_counter_table_action_e action;
    union npl_rx_term_error_handling_counter_table_payloads_t {
        npl_rx_term_error_handling_counter_table_update_result_payload_t update_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rx_term_error_handling_counter_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RX_TERM_ERROR_HANDLING_COUNTER_TABLE_ACTION_UPDATE_RESULT:
            {
                return "NPL_RX_TERM_ERROR_HANDLING_COUNTER_TABLE_ACTION_UPDATE_RESULT(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rx_term_error_handling_counter_table_action_e");
        }
        return "";
    }
    npl_rx_term_error_handling_counter_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rx_term_error_handling_counter_table_value_t element);
std::string to_short_string(struct npl_rx_term_error_handling_counter_table_value_t element);

/// API-s for table: rx_term_error_handling_destination_table

typedef enum
{
    NPL_RX_TERM_ERROR_HANDLING_DESTINATION_TABLE_ACTION_UPDATE_RESULT = 0x0
} npl_rx_term_error_handling_destination_table_action_e;

struct npl_rx_term_error_handling_destination_table_update_result_payload_t
{
    uint64_t destination : 20;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_rx_term_error_handling_destination_table_update_result_payload_t element);
std::string to_short_string(npl_rx_term_error_handling_destination_table_update_result_payload_t element);

struct npl_rx_term_error_handling_destination_table_key_t
{
    uint64_t ser : 1;
    
    npl_rx_term_error_handling_destination_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rx_term_error_handling_destination_table_key_t element);
std::string to_short_string(struct npl_rx_term_error_handling_destination_table_key_t element);

struct npl_rx_term_error_handling_destination_table_value_t
{
    npl_rx_term_error_handling_destination_table_action_e action;
    union npl_rx_term_error_handling_destination_table_payloads_t {
        npl_rx_term_error_handling_destination_table_update_result_payload_t update_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rx_term_error_handling_destination_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RX_TERM_ERROR_HANDLING_DESTINATION_TABLE_ACTION_UPDATE_RESULT:
            {
                return "NPL_RX_TERM_ERROR_HANDLING_DESTINATION_TABLE_ACTION_UPDATE_RESULT(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rx_term_error_handling_destination_table_action_e");
        }
        return "";
    }
    npl_rx_term_error_handling_destination_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rx_term_error_handling_destination_table_value_t element);
std::string to_short_string(struct npl_rx_term_error_handling_destination_table_value_t element);

/// API-s for table: rxpdr_dsp_lookup_table

typedef enum
{
    NPL_RXPDR_DSP_LOOKUP_TABLE_ACTION_WRITE = 0x0
} npl_rxpdr_dsp_lookup_table_action_e;

struct npl_rxpdr_dsp_lookup_table_key_t
{
    uint64_t fwd_destination_lsb : 13;
    
    npl_rxpdr_dsp_lookup_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rxpdr_dsp_lookup_table_key_t element);
std::string to_short_string(struct npl_rxpdr_dsp_lookup_table_key_t element);

struct npl_rxpdr_dsp_lookup_table_value_t
{
    npl_rxpdr_dsp_lookup_table_action_e action;
    union npl_rxpdr_dsp_lookup_table_payloads_t {
        npl_rxpdr_dsp_lookup_table_entry_t rxpdr_dsp_lookup_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rxpdr_dsp_lookup_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RXPDR_DSP_LOOKUP_TABLE_ACTION_WRITE:
            {
                return "NPL_RXPDR_DSP_LOOKUP_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rxpdr_dsp_lookup_table_action_e");
        }
        return "";
    }
    npl_rxpdr_dsp_lookup_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rxpdr_dsp_lookup_table_value_t element);
std::string to_short_string(struct npl_rxpdr_dsp_lookup_table_value_t element);

/// API-s for table: rxpdr_dsp_tc_map

typedef enum
{
    NPL_RXPDR_DSP_TC_MAP_ACTION_WRITE = 0x0
} npl_rxpdr_dsp_tc_map_action_e;

struct npl_rxpdr_dsp_tc_map_key_t
{
    uint64_t rxpdr_dsp_lookup_table_result_tc_map_profile : 3;
    uint64_t rxpp_pd_tc : 3;
    
    npl_rxpdr_dsp_tc_map_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_rxpdr_dsp_tc_map_key_t element);
std::string to_short_string(struct npl_rxpdr_dsp_tc_map_key_t element);

struct npl_rxpdr_dsp_tc_map_value_t
{
    npl_rxpdr_dsp_tc_map_action_e action;
    union npl_rxpdr_dsp_tc_map_payloads_t {
        npl_rxpdr_dsp_tc_map_result_t rxpdr_dsp_tc_map_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_rxpdr_dsp_tc_map_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_RXPDR_DSP_TC_MAP_ACTION_WRITE:
            {
                return "NPL_RXPDR_DSP_TC_MAP_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_rxpdr_dsp_tc_map_action_e");
        }
        return "";
    }
    npl_rxpdr_dsp_tc_map_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_rxpdr_dsp_tc_map_value_t element);
std::string to_short_string(struct npl_rxpdr_dsp_tc_map_value_t element);

/// API-s for table: sch_oqse_cfg

typedef enum
{
    NPL_SCH_OQSE_CFG_ACTION_WRITE = 0x0
} npl_sch_oqse_cfg_action_e;

struct npl_sch_oqse_cfg_key_t
{
    npl_ifg_t ifg;
    npl_oqse_pair_t oqse_pair_index;
    
    npl_sch_oqse_cfg_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_sch_oqse_cfg_key_t element);
std::string to_short_string(struct npl_sch_oqse_cfg_key_t element);

struct npl_sch_oqse_cfg_value_t
{
    npl_sch_oqse_cfg_action_e action;
    union npl_sch_oqse_cfg_payloads_t {
        npl_sch_oqse_cfg_result_t sch_oqse_cfg_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_sch_oqse_cfg_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_SCH_OQSE_CFG_ACTION_WRITE:
            {
                return "NPL_SCH_OQSE_CFG_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_sch_oqse_cfg_action_e");
        }
        return "";
    }
    npl_sch_oqse_cfg_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_sch_oqse_cfg_value_t element);
std::string to_short_string(struct npl_sch_oqse_cfg_value_t element);

/// API-s for table: second_ene_static_table

typedef enum
{
    NPL_SECOND_ENE_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_second_ene_static_table_action_e;

struct npl_second_ene_static_table_key_t
{
    uint64_t second_ene_macro_code : 2;
    
    npl_second_ene_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_second_ene_static_table_key_t element);
std::string to_short_string(struct npl_second_ene_static_table_key_t element);

struct npl_second_ene_static_table_value_t
{
    npl_second_ene_static_table_action_e action;
    union npl_second_ene_static_table_payloads_t {
        npl_ene_macro_id_t second_ene_macro;
    } payloads;
    std::string npl_action_enum_to_string(const npl_second_ene_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_SECOND_ENE_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_SECOND_ENE_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_second_ene_static_table_action_e");
        }
        return "";
    }
    npl_second_ene_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_second_ene_static_table_value_t element);
std::string to_short_string(struct npl_second_ene_static_table_value_t element);

/// API-s for table: select_inject_next_macro_static_table

typedef enum
{
    NPL_SELECT_INJECT_NEXT_MACRO_STATIC_TABLE_ACTION_RX_INJECT_UP_NEXT_MACRO = 0x0
} npl_select_inject_next_macro_static_table_action_e;

struct npl_select_inject_next_macro_static_table_rx_inject_up_next_macro_payload_t
{
    uint64_t pl_inc : 2;
    uint64_t macro_id : 8;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_select_inject_next_macro_static_table_rx_inject_up_next_macro_payload_t element);
std::string to_short_string(npl_select_inject_next_macro_static_table_rx_inject_up_next_macro_payload_t element);

struct npl_select_inject_next_macro_static_table_key_t
{
    npl_inject_header_type_t local_inject_type_7_0_;
    npl_protocol_type_e protocol;
    
    npl_select_inject_next_macro_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_select_inject_next_macro_static_table_key_t element);
std::string to_short_string(struct npl_select_inject_next_macro_static_table_key_t element);

struct npl_select_inject_next_macro_static_table_value_t
{
    npl_select_inject_next_macro_static_table_action_e action;
    union npl_select_inject_next_macro_static_table_payloads_t {
        npl_select_inject_next_macro_static_table_rx_inject_up_next_macro_payload_t rx_inject_up_next_macro;
    } payloads;
    std::string npl_action_enum_to_string(const npl_select_inject_next_macro_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_SELECT_INJECT_NEXT_MACRO_STATIC_TABLE_ACTION_RX_INJECT_UP_NEXT_MACRO:
            {
                return "NPL_SELECT_INJECT_NEXT_MACRO_STATIC_TABLE_ACTION_RX_INJECT_UP_NEXT_MACRO(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_select_inject_next_macro_static_table_action_e");
        }
        return "";
    }
    npl_select_inject_next_macro_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_select_inject_next_macro_static_table_value_t element);
std::string to_short_string(struct npl_select_inject_next_macro_static_table_value_t element);

/// API-s for table: service_lp_attributes_table

typedef enum
{
    NPL_SERVICE_LP_ATTRIBUTES_TABLE_ACTION_WRITE = 0x0
} npl_service_lp_attributes_table_action_e;

struct npl_service_lp_attributes_table_write_payload_t
{
    npl_mac_lp_attributes_table_payload_t mac_lp_attributes_payload;
    
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_service_lp_attributes_table_write_payload_t element);
std::string to_short_string(npl_service_lp_attributes_table_write_payload_t element);

struct npl_service_lp_attributes_table_key_t
{
    npl_lp_id_t service_lp_attributes_table_key;
    
    npl_service_lp_attributes_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_service_lp_attributes_table_key_t element);
std::string to_short_string(struct npl_service_lp_attributes_table_key_t element);

struct npl_service_lp_attributes_table_value_t
{
    npl_service_lp_attributes_table_action_e action;
    union npl_service_lp_attributes_table_payloads_t {
        npl_service_lp_attributes_table_write_payload_t write;
    } payloads;
    std::string npl_action_enum_to_string(const npl_service_lp_attributes_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_SERVICE_LP_ATTRIBUTES_TABLE_ACTION_WRITE:
            {
                return "NPL_SERVICE_LP_ATTRIBUTES_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_service_lp_attributes_table_action_e");
        }
        return "";
    }
    npl_service_lp_attributes_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_service_lp_attributes_table_value_t element);
std::string to_short_string(struct npl_service_lp_attributes_table_value_t element);

/// API-s for table: service_mapping_em0_ac_port_table

typedef enum
{
    NPL_SERVICE_MAPPING_EM0_AC_PORT_TABLE_ACTION_SM = 0x0
} npl_service_mapping_em0_ac_port_table_action_e;

struct npl_service_mapping_em0_ac_port_table_sm_payload_t
{
    npl_lp_id_t lp_id;
    npl_relay_id_t relay_id;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_service_mapping_em0_ac_port_table_sm_payload_t element);
std::string to_short_string(npl_service_mapping_em0_ac_port_table_sm_payload_t element);

struct npl_service_mapping_em0_ac_port_table_key_t
{
    npl_lp_id_t local_slp_id;
    
    npl_service_mapping_em0_ac_port_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_service_mapping_em0_ac_port_table_key_t element);
std::string to_short_string(struct npl_service_mapping_em0_ac_port_table_key_t element);

struct npl_service_mapping_em0_ac_port_table_value_t
{
    npl_service_mapping_em0_ac_port_table_action_e action;
    union npl_service_mapping_em0_ac_port_table_payloads_t {
        npl_service_mapping_em0_ac_port_table_sm_payload_t sm;
    } payloads;
    std::string npl_action_enum_to_string(const npl_service_mapping_em0_ac_port_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_SERVICE_MAPPING_EM0_AC_PORT_TABLE_ACTION_SM:
            {
                return "NPL_SERVICE_MAPPING_EM0_AC_PORT_TABLE_ACTION_SM(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_service_mapping_em0_ac_port_table_action_e");
        }
        return "";
    }
    npl_service_mapping_em0_ac_port_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_service_mapping_em0_ac_port_table_value_t element);
std::string to_short_string(struct npl_service_mapping_em0_ac_port_table_value_t element);

/// API-s for table: service_mapping_em0_ac_port_tag_table

typedef enum
{
    NPL_SERVICE_MAPPING_EM0_AC_PORT_TAG_TABLE_ACTION_SM = 0x0
} npl_service_mapping_em0_ac_port_tag_table_action_e;

struct npl_service_mapping_em0_ac_port_tag_table_sm_payload_t
{
    npl_lp_id_t lp_id;
    npl_relay_id_t relay_id;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_service_mapping_em0_ac_port_tag_table_sm_payload_t element);
std::string to_short_string(npl_service_mapping_em0_ac_port_tag_table_sm_payload_t element);

struct npl_service_mapping_em0_ac_port_tag_table_key_t
{
    npl_vlan_id_t vid1;
    npl_lp_id_t local_slp_id;
    
    npl_service_mapping_em0_ac_port_tag_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_service_mapping_em0_ac_port_tag_table_key_t element);
std::string to_short_string(struct npl_service_mapping_em0_ac_port_tag_table_key_t element);

struct npl_service_mapping_em0_ac_port_tag_table_value_t
{
    npl_service_mapping_em0_ac_port_tag_table_action_e action;
    union npl_service_mapping_em0_ac_port_tag_table_payloads_t {
        npl_service_mapping_em0_ac_port_tag_table_sm_payload_t sm;
    } payloads;
    std::string npl_action_enum_to_string(const npl_service_mapping_em0_ac_port_tag_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_SERVICE_MAPPING_EM0_AC_PORT_TAG_TABLE_ACTION_SM:
            {
                return "NPL_SERVICE_MAPPING_EM0_AC_PORT_TAG_TABLE_ACTION_SM(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_service_mapping_em0_ac_port_tag_table_action_e");
        }
        return "";
    }
    npl_service_mapping_em0_ac_port_tag_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_service_mapping_em0_ac_port_tag_table_value_t element);
std::string to_short_string(struct npl_service_mapping_em0_ac_port_tag_table_value_t element);

/// API-s for table: service_mapping_em0_ac_port_tag_tag_table

typedef enum
{
    NPL_SERVICE_MAPPING_EM0_AC_PORT_TAG_TAG_TABLE_ACTION_SM = 0x0
} npl_service_mapping_em0_ac_port_tag_tag_table_action_e;

struct npl_service_mapping_em0_ac_port_tag_tag_table_sm_payload_t
{
    npl_lp_id_t lp_id;
    npl_relay_id_t relay_id;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_service_mapping_em0_ac_port_tag_tag_table_sm_payload_t element);
std::string to_short_string(npl_service_mapping_em0_ac_port_tag_tag_table_sm_payload_t element);

struct npl_service_mapping_em0_ac_port_tag_tag_table_key_t
{
    npl_vlan_id_t vid2;
    npl_vlan_id_t vid1;
    npl_lp_id_t local_slp_id;
    
    npl_service_mapping_em0_ac_port_tag_tag_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_service_mapping_em0_ac_port_tag_tag_table_key_t element);
std::string to_short_string(struct npl_service_mapping_em0_ac_port_tag_tag_table_key_t element);

struct npl_service_mapping_em0_ac_port_tag_tag_table_value_t
{
    npl_service_mapping_em0_ac_port_tag_tag_table_action_e action;
    union npl_service_mapping_em0_ac_port_tag_tag_table_payloads_t {
        npl_service_mapping_em0_ac_port_tag_tag_table_sm_payload_t sm;
    } payloads;
    std::string npl_action_enum_to_string(const npl_service_mapping_em0_ac_port_tag_tag_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_SERVICE_MAPPING_EM0_AC_PORT_TAG_TAG_TABLE_ACTION_SM:
            {
                return "NPL_SERVICE_MAPPING_EM0_AC_PORT_TAG_TAG_TABLE_ACTION_SM(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_service_mapping_em0_ac_port_tag_tag_table_action_e");
        }
        return "";
    }
    npl_service_mapping_em0_ac_port_tag_tag_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_service_mapping_em0_ac_port_tag_tag_table_value_t element);
std::string to_short_string(struct npl_service_mapping_em0_ac_port_tag_tag_table_value_t element);

/// API-s for table: service_mapping_em0_pwe_tag_table

typedef enum
{
    NPL_SERVICE_MAPPING_EM0_PWE_TAG_TABLE_ACTION_SM = 0x0
} npl_service_mapping_em0_pwe_tag_table_action_e;

struct npl_service_mapping_em0_pwe_tag_table_sm_payload_t
{
    npl_lp_id_t lp_id;
    npl_relay_id_t relay_id;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_service_mapping_em0_pwe_tag_table_sm_payload_t element);
std::string to_short_string(npl_service_mapping_em0_pwe_tag_table_sm_payload_t element);

struct npl_service_mapping_em0_pwe_tag_table_key_t
{
    npl_vlan_id_t vid1;
    npl_lp_id_t local_slp_id;
    
    npl_service_mapping_em0_pwe_tag_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_service_mapping_em0_pwe_tag_table_key_t element);
std::string to_short_string(struct npl_service_mapping_em0_pwe_tag_table_key_t element);

struct npl_service_mapping_em0_pwe_tag_table_value_t
{
    npl_service_mapping_em0_pwe_tag_table_action_e action;
    union npl_service_mapping_em0_pwe_tag_table_payloads_t {
        npl_service_mapping_em0_pwe_tag_table_sm_payload_t sm;
    } payloads;
    std::string npl_action_enum_to_string(const npl_service_mapping_em0_pwe_tag_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_SERVICE_MAPPING_EM0_PWE_TAG_TABLE_ACTION_SM:
            {
                return "NPL_SERVICE_MAPPING_EM0_PWE_TAG_TABLE_ACTION_SM(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_service_mapping_em0_pwe_tag_table_action_e");
        }
        return "";
    }
    npl_service_mapping_em0_pwe_tag_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_service_mapping_em0_pwe_tag_table_value_t element);
std::string to_short_string(struct npl_service_mapping_em0_pwe_tag_table_value_t element);

/// API-s for table: service_mapping_em1_ac_port_tag_table

typedef enum
{
    NPL_SERVICE_MAPPING_EM1_AC_PORT_TAG_TABLE_ACTION_SM = 0x0
} npl_service_mapping_em1_ac_port_tag_table_action_e;

struct npl_service_mapping_em1_ac_port_tag_table_sm_payload_t
{
    npl_lp_id_t lp_id;
    npl_relay_id_t relay_id;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_service_mapping_em1_ac_port_tag_table_sm_payload_t element);
std::string to_short_string(npl_service_mapping_em1_ac_port_tag_table_sm_payload_t element);

struct npl_service_mapping_em1_ac_port_tag_table_key_t
{
    npl_vlan_id_t vid1;
    npl_lp_id_t local_slp_id;
    
    npl_service_mapping_em1_ac_port_tag_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_service_mapping_em1_ac_port_tag_table_key_t element);
std::string to_short_string(struct npl_service_mapping_em1_ac_port_tag_table_key_t element);

struct npl_service_mapping_em1_ac_port_tag_table_value_t
{
    npl_service_mapping_em1_ac_port_tag_table_action_e action;
    union npl_service_mapping_em1_ac_port_tag_table_payloads_t {
        npl_service_mapping_em1_ac_port_tag_table_sm_payload_t sm;
    } payloads;
    std::string npl_action_enum_to_string(const npl_service_mapping_em1_ac_port_tag_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_SERVICE_MAPPING_EM1_AC_PORT_TAG_TABLE_ACTION_SM:
            {
                return "NPL_SERVICE_MAPPING_EM1_AC_PORT_TAG_TABLE_ACTION_SM(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_service_mapping_em1_ac_port_tag_table_action_e");
        }
        return "";
    }
    npl_service_mapping_em1_ac_port_tag_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_service_mapping_em1_ac_port_tag_table_value_t element);
std::string to_short_string(struct npl_service_mapping_em1_ac_port_tag_table_value_t element);

/// API-s for table: service_mapping_tcam_ac_port_table

typedef enum
{
    NPL_SERVICE_MAPPING_TCAM_AC_PORT_TABLE_ACTION_SM = 0x0
} npl_service_mapping_tcam_ac_port_table_action_e;

struct npl_service_mapping_tcam_ac_port_table_sm_payload_t
{
    npl_mac_lp_attributes_table_payload_t lp_attr;
    npl_lp_id_t lp_id;
    npl_relay_attr_table_payload_t relay_table_payload;
    uint64_t relay_id : 14;
    
    bit_vector384_t pack(void) const;
    void unpack(bit_vector384_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_service_mapping_tcam_ac_port_table_sm_payload_t element);
std::string to_short_string(npl_service_mapping_tcam_ac_port_table_sm_payload_t element);

struct npl_service_mapping_tcam_ac_port_table_key_t
{
    npl_lp_id_t local_slp_id;
    
    npl_service_mapping_tcam_ac_port_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_service_mapping_tcam_ac_port_table_key_t element);
std::string to_short_string(struct npl_service_mapping_tcam_ac_port_table_key_t element);

struct npl_service_mapping_tcam_ac_port_table_value_t
{
    npl_service_mapping_tcam_ac_port_table_action_e action;
    union npl_service_mapping_tcam_ac_port_table_payloads_t {
        npl_service_mapping_tcam_ac_port_table_sm_payload_t sm;
    } payloads;
    std::string npl_action_enum_to_string(const npl_service_mapping_tcam_ac_port_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_SERVICE_MAPPING_TCAM_AC_PORT_TABLE_ACTION_SM:
            {
                return "NPL_SERVICE_MAPPING_TCAM_AC_PORT_TABLE_ACTION_SM(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_service_mapping_tcam_ac_port_table_action_e");
        }
        return "";
    }
    npl_service_mapping_tcam_ac_port_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector384_t pack(void) const;
    void unpack(bit_vector384_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_service_mapping_tcam_ac_port_table_value_t element);
std::string to_short_string(struct npl_service_mapping_tcam_ac_port_table_value_t element);

/// API-s for table: service_mapping_tcam_ac_port_tag_table

typedef enum
{
    NPL_SERVICE_MAPPING_TCAM_AC_PORT_TAG_TABLE_ACTION_SM = 0x0
} npl_service_mapping_tcam_ac_port_tag_table_action_e;

struct npl_service_mapping_tcam_ac_port_tag_table_sm_payload_t
{
    npl_mac_lp_attributes_table_payload_t lp_attr;
    npl_lp_id_t lp_id;
    npl_relay_attr_table_payload_t relay_table_payload;
    uint64_t relay_id : 14;
    
    bit_vector384_t pack(void) const;
    void unpack(bit_vector384_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_service_mapping_tcam_ac_port_tag_table_sm_payload_t element);
std::string to_short_string(npl_service_mapping_tcam_ac_port_tag_table_sm_payload_t element);

struct npl_service_mapping_tcam_ac_port_tag_table_key_t
{
    npl_vlan_id_t vid1;
    npl_lp_id_t local_slp_id;
    
    npl_service_mapping_tcam_ac_port_tag_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_service_mapping_tcam_ac_port_tag_table_key_t element);
std::string to_short_string(struct npl_service_mapping_tcam_ac_port_tag_table_key_t element);

struct npl_service_mapping_tcam_ac_port_tag_table_value_t
{
    npl_service_mapping_tcam_ac_port_tag_table_action_e action;
    union npl_service_mapping_tcam_ac_port_tag_table_payloads_t {
        npl_service_mapping_tcam_ac_port_tag_table_sm_payload_t sm;
    } payloads;
    std::string npl_action_enum_to_string(const npl_service_mapping_tcam_ac_port_tag_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_SERVICE_MAPPING_TCAM_AC_PORT_TAG_TABLE_ACTION_SM:
            {
                return "NPL_SERVICE_MAPPING_TCAM_AC_PORT_TAG_TABLE_ACTION_SM(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_service_mapping_tcam_ac_port_tag_table_action_e");
        }
        return "";
    }
    npl_service_mapping_tcam_ac_port_tag_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector384_t pack(void) const;
    void unpack(bit_vector384_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_service_mapping_tcam_ac_port_tag_table_value_t element);
std::string to_short_string(struct npl_service_mapping_tcam_ac_port_tag_table_value_t element);

/// API-s for table: service_mapping_tcam_ac_port_tag_tag_table

typedef enum
{
    NPL_SERVICE_MAPPING_TCAM_AC_PORT_TAG_TAG_TABLE_ACTION_SM = 0x0
} npl_service_mapping_tcam_ac_port_tag_tag_table_action_e;

struct npl_service_mapping_tcam_ac_port_tag_tag_table_sm_payload_t
{
    npl_mac_lp_attributes_table_payload_t lp_attr;
    npl_lp_id_t lp_id;
    npl_relay_attr_table_payload_t relay_table_payload;
    uint64_t relay_id : 14;
    
    bit_vector384_t pack(void) const;
    void unpack(bit_vector384_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_service_mapping_tcam_ac_port_tag_tag_table_sm_payload_t element);
std::string to_short_string(npl_service_mapping_tcam_ac_port_tag_tag_table_sm_payload_t element);

struct npl_service_mapping_tcam_ac_port_tag_tag_table_key_t
{
    npl_vlan_id_t vid2;
    npl_vlan_id_t vid1;
    npl_lp_id_t local_slp_id;
    
    npl_service_mapping_tcam_ac_port_tag_tag_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_service_mapping_tcam_ac_port_tag_tag_table_key_t element);
std::string to_short_string(struct npl_service_mapping_tcam_ac_port_tag_tag_table_key_t element);

struct npl_service_mapping_tcam_ac_port_tag_tag_table_value_t
{
    npl_service_mapping_tcam_ac_port_tag_tag_table_action_e action;
    union npl_service_mapping_tcam_ac_port_tag_tag_table_payloads_t {
        npl_service_mapping_tcam_ac_port_tag_tag_table_sm_payload_t sm;
    } payloads;
    std::string npl_action_enum_to_string(const npl_service_mapping_tcam_ac_port_tag_tag_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_SERVICE_MAPPING_TCAM_AC_PORT_TAG_TAG_TABLE_ACTION_SM:
            {
                return "NPL_SERVICE_MAPPING_TCAM_AC_PORT_TAG_TAG_TABLE_ACTION_SM(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_service_mapping_tcam_ac_port_tag_tag_table_action_e");
        }
        return "";
    }
    npl_service_mapping_tcam_ac_port_tag_tag_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector384_t pack(void) const;
    void unpack(bit_vector384_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_service_mapping_tcam_ac_port_tag_tag_table_value_t element);
std::string to_short_string(struct npl_service_mapping_tcam_ac_port_tag_tag_table_value_t element);

/// API-s for table: service_mapping_tcam_pwe_tag_table

typedef enum
{
    NPL_SERVICE_MAPPING_TCAM_PWE_TAG_TABLE_ACTION_SM = 0x0
} npl_service_mapping_tcam_pwe_tag_table_action_e;

struct npl_service_mapping_tcam_pwe_tag_table_sm_payload_t
{
    npl_mac_lp_attributes_table_payload_t lp_attr;
    npl_lp_id_t lp_id;
    npl_relay_attr_table_payload_t relay_table_payload;
    uint64_t relay_id : 14;
    
    bit_vector384_t pack(void) const;
    void unpack(bit_vector384_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_service_mapping_tcam_pwe_tag_table_sm_payload_t element);
std::string to_short_string(npl_service_mapping_tcam_pwe_tag_table_sm_payload_t element);

struct npl_service_mapping_tcam_pwe_tag_table_key_t
{
    npl_vlan_id_t vid1;
    npl_lp_id_t local_slp_id;
    
    npl_service_mapping_tcam_pwe_tag_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_service_mapping_tcam_pwe_tag_table_key_t element);
std::string to_short_string(struct npl_service_mapping_tcam_pwe_tag_table_key_t element);

struct npl_service_mapping_tcam_pwe_tag_table_value_t
{
    npl_service_mapping_tcam_pwe_tag_table_action_e action;
    union npl_service_mapping_tcam_pwe_tag_table_payloads_t {
        npl_service_mapping_tcam_pwe_tag_table_sm_payload_t sm;
    } payloads;
    std::string npl_action_enum_to_string(const npl_service_mapping_tcam_pwe_tag_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_SERVICE_MAPPING_TCAM_PWE_TAG_TABLE_ACTION_SM:
            {
                return "NPL_SERVICE_MAPPING_TCAM_PWE_TAG_TABLE_ACTION_SM(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_service_mapping_tcam_pwe_tag_table_action_e");
        }
        return "";
    }
    npl_service_mapping_tcam_pwe_tag_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector384_t pack(void) const;
    void unpack(bit_vector384_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_service_mapping_tcam_pwe_tag_table_value_t element);
std::string to_short_string(struct npl_service_mapping_tcam_pwe_tag_table_value_t element);

/// API-s for table: service_relay_attributes_table

typedef enum
{
    NPL_SERVICE_RELAY_ATTRIBUTES_TABLE_ACTION_RELAY = 0x0
} npl_service_relay_attributes_table_action_e;

struct npl_service_relay_attributes_table_relay_payload_t
{
    npl_relay_attr_table_payload_t relay_table_payload;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_service_relay_attributes_table_relay_payload_t element);
std::string to_short_string(npl_service_relay_attributes_table_relay_payload_t element);

struct npl_service_relay_attributes_table_key_t
{
    npl_relay_id_t relay_id;
    
    npl_service_relay_attributes_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_service_relay_attributes_table_key_t element);
std::string to_short_string(struct npl_service_relay_attributes_table_key_t element);

struct npl_service_relay_attributes_table_value_t
{
    npl_service_relay_attributes_table_action_e action;
    union npl_service_relay_attributes_table_payloads_t {
        npl_service_relay_attributes_table_relay_payload_t relay;
    } payloads;
    std::string npl_action_enum_to_string(const npl_service_relay_attributes_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_SERVICE_RELAY_ATTRIBUTES_TABLE_ACTION_RELAY:
            {
                return "NPL_SERVICE_RELAY_ATTRIBUTES_TABLE_ACTION_RELAY(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_service_relay_attributes_table_action_e");
        }
        return "";
    }
    npl_service_relay_attributes_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_service_relay_attributes_table_value_t element);
std::string to_short_string(struct npl_service_relay_attributes_table_value_t element);

/// API-s for table: set_ene_macro_and_bytes_to_remove_table

typedef enum
{
    NPL_SET_ENE_MACRO_AND_BYTES_TO_REMOVE_TABLE_ACTION_SET_ENE_MACRO_AND_BYTES_TO_REMOVE_TABLE = 0x0
} npl_set_ene_macro_and_bytes_to_remove_table_action_e;

struct npl_set_ene_macro_and_bytes_to_remove_table_set_ene_macro_and_bytes_to_remove_table_payload_t
{
    uint64_t bytes_to_remove : 8;
    npl_fabric_header_type_e new_hdr_type;
    npl_ene_macro_ids_e ene_macro_id;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_set_ene_macro_and_bytes_to_remove_table_set_ene_macro_and_bytes_to_remove_table_payload_t element);
std::string to_short_string(npl_set_ene_macro_and_bytes_to_remove_table_set_ene_macro_and_bytes_to_remove_table_payload_t element);

struct npl_set_ene_macro_and_bytes_to_remove_table_key_t
{
    npl_fabric_header_type_e hdr_type;
    npl_plb_header_type_e plb_header_type;
    
    npl_set_ene_macro_and_bytes_to_remove_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_set_ene_macro_and_bytes_to_remove_table_key_t element);
std::string to_short_string(struct npl_set_ene_macro_and_bytes_to_remove_table_key_t element);

struct npl_set_ene_macro_and_bytes_to_remove_table_value_t
{
    npl_set_ene_macro_and_bytes_to_remove_table_action_e action;
    union npl_set_ene_macro_and_bytes_to_remove_table_payloads_t {
        npl_set_ene_macro_and_bytes_to_remove_table_set_ene_macro_and_bytes_to_remove_table_payload_t set_ene_macro_and_bytes_to_remove_table;
    } payloads;
    std::string npl_action_enum_to_string(const npl_set_ene_macro_and_bytes_to_remove_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_SET_ENE_MACRO_AND_BYTES_TO_REMOVE_TABLE_ACTION_SET_ENE_MACRO_AND_BYTES_TO_REMOVE_TABLE:
            {
                return "NPL_SET_ENE_MACRO_AND_BYTES_TO_REMOVE_TABLE_ACTION_SET_ENE_MACRO_AND_BYTES_TO_REMOVE_TABLE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_set_ene_macro_and_bytes_to_remove_table_action_e");
        }
        return "";
    }
    npl_set_ene_macro_and_bytes_to_remove_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_set_ene_macro_and_bytes_to_remove_table_value_t element);
std::string to_short_string(struct npl_set_ene_macro_and_bytes_to_remove_table_value_t element);

/// API-s for table: sgacl_table

typedef enum
{
    NPL_SGACL_TABLE_ACTION_WRITE = 0x0
} npl_sgacl_table_action_e;

struct npl_sgacl_table_key_t
{
    
    
    npl_sgacl_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_sgacl_table_key_t element);
std::string to_short_string(struct npl_sgacl_table_key_t element);

struct npl_sgacl_table_value_t
{
    npl_sgacl_table_action_e action;
    union npl_sgacl_table_payloads_t {
        npl_sgacl_payload_t sgacl_payload;
    } payloads;
    std::string npl_action_enum_to_string(const npl_sgacl_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_SGACL_TABLE_ACTION_WRITE:
            {
                return "NPL_SGACL_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_sgacl_table_action_e");
        }
        return "";
    }
    npl_sgacl_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_sgacl_table_value_t element);
std::string to_short_string(struct npl_sgacl_table_value_t element);

/// API-s for table: sip_index_table

typedef enum
{
    NPL_SIP_INDEX_TABLE_ACTION_WRITE = 0x0
} npl_sip_index_table_action_e;

struct npl_sip_index_table_key_t
{
    uint64_t sip_index : 4;
    
    npl_sip_index_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_sip_index_table_key_t element);
std::string to_short_string(struct npl_sip_index_table_key_t element);

struct npl_sip_index_table_value_t
{
    npl_sip_index_table_action_e action;
    union npl_sip_index_table_payloads_t {
        uint64_t sip : 32;
    } payloads;
    std::string npl_action_enum_to_string(const npl_sip_index_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_SIP_INDEX_TABLE_ACTION_WRITE:
            {
                return "NPL_SIP_INDEX_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_sip_index_table_action_e");
        }
        return "";
    }
    npl_sip_index_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_sip_index_table_value_t element);
std::string to_short_string(struct npl_sip_index_table_value_t element);

/// API-s for table: slice_modes_table

typedef enum
{
    NPL_SLICE_MODES_TABLE_ACTION_WRITE = 0x0
} npl_slice_modes_table_action_e;

struct npl_slice_modes_table_key_t
{
    uint64_t slice_id : 3;
    
    npl_slice_modes_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_slice_modes_table_key_t element);
std::string to_short_string(struct npl_slice_modes_table_key_t element);

struct npl_slice_modes_table_value_t
{
    npl_slice_modes_table_action_e action;
    union npl_slice_modes_table_payloads_t {
        npl_slice_mode_e slice_modes_table_in_out_vars_slice_mode;
    } payloads;
    std::string npl_action_enum_to_string(const npl_slice_modes_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_SLICE_MODES_TABLE_ACTION_WRITE:
            {
                return "NPL_SLICE_MODES_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_slice_modes_table_action_e");
        }
        return "";
    }
    npl_slice_modes_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_slice_modes_table_value_t element);
std::string to_short_string(struct npl_slice_modes_table_value_t element);

/// API-s for table: slp_based_forwarding_table

typedef enum
{
    NPL_SLP_BASED_FORWARDING_TABLE_ACTION_WRITE = 0x0
} npl_slp_based_forwarding_table_action_e;

struct npl_slp_based_forwarding_table_key_t
{
    npl_l3_slp_id_t slp_id;
    
    npl_slp_based_forwarding_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_slp_based_forwarding_table_key_t element);
std::string to_short_string(struct npl_slp_based_forwarding_table_key_t element);

struct npl_slp_based_forwarding_table_value_t
{
    npl_slp_based_forwarding_table_action_e action;
    union npl_slp_based_forwarding_table_payloads_t {
        npl_slp_fwd_result_t slp_fwd_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_slp_based_forwarding_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_SLP_BASED_FORWARDING_TABLE_ACTION_WRITE:
            {
                return "NPL_SLP_BASED_FORWARDING_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_slp_based_forwarding_table_action_e");
        }
        return "";
    }
    npl_slp_based_forwarding_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_slp_based_forwarding_table_value_t element);
std::string to_short_string(struct npl_slp_based_forwarding_table_value_t element);

/// API-s for table: small_encap_mpls_he_asbr_table

typedef enum
{
    NPL_SMALL_ENCAP_MPLS_HE_ASBR_TABLE_ACTION_WRITE = 0x0
} npl_small_encap_mpls_he_asbr_table_action_e;

struct npl_small_encap_mpls_he_asbr_table_key_t
{
    uint64_t asbr : 16;
    uint64_t nh_ptr : 12;
    
    npl_small_encap_mpls_he_asbr_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_small_encap_mpls_he_asbr_table_key_t element);
std::string to_short_string(struct npl_small_encap_mpls_he_asbr_table_key_t element);

struct npl_small_encap_mpls_he_asbr_table_value_t
{
    npl_small_encap_mpls_he_asbr_table_action_e action;
    union npl_small_encap_mpls_he_asbr_table_payloads_t {
        npl_lsp_encap_mapping_data_payload_t lsp_encap_mapping_data_payload_asbr;
    } payloads;
    std::string npl_action_enum_to_string(const npl_small_encap_mpls_he_asbr_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_SMALL_ENCAP_MPLS_HE_ASBR_TABLE_ACTION_WRITE:
            {
                return "NPL_SMALL_ENCAP_MPLS_HE_ASBR_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_small_encap_mpls_he_asbr_table_action_e");
        }
        return "";
    }
    npl_small_encap_mpls_he_asbr_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_small_encap_mpls_he_asbr_table_value_t element);
std::string to_short_string(struct npl_small_encap_mpls_he_asbr_table_value_t element);

/// API-s for table: small_encap_mpls_he_te_table

typedef enum
{
    NPL_SMALL_ENCAP_MPLS_HE_TE_TABLE_ACTION_WRITE = 0x0
} npl_small_encap_mpls_he_te_table_action_e;

struct npl_small_encap_mpls_he_te_table_key_t
{
    uint64_t te_tunnel : 16;
    uint64_t nh_ptr : 12;
    
    npl_small_encap_mpls_he_te_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_small_encap_mpls_he_te_table_key_t element);
std::string to_short_string(struct npl_small_encap_mpls_he_te_table_key_t element);

struct npl_small_encap_mpls_he_te_table_value_t
{
    npl_small_encap_mpls_he_te_table_action_e action;
    union npl_small_encap_mpls_he_te_table_payloads_t {
        npl_lsp_encap_mapping_data_payload_t lsp_encap_mapping_data_payload_asbr;
    } payloads;
    std::string npl_action_enum_to_string(const npl_small_encap_mpls_he_te_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_SMALL_ENCAP_MPLS_HE_TE_TABLE_ACTION_WRITE:
            {
                return "NPL_SMALL_ENCAP_MPLS_HE_TE_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_small_encap_mpls_he_te_table_action_e");
        }
        return "";
    }
    npl_small_encap_mpls_he_te_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_small_encap_mpls_he_te_table_value_t element);
std::string to_short_string(struct npl_small_encap_mpls_he_te_table_value_t element);

/// API-s for table: snoop_code_hw_table

typedef enum
{
    NPL_SNOOP_CODE_HW_TABLE_ACTION_WRITE = 0x0
} npl_snoop_code_hw_table_action_e;

struct npl_snoop_code_hw_table_key_t
{
    uint64_t pd_common_leaba_fields_snoop_code : 8;
    
    npl_snoop_code_hw_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_snoop_code_hw_table_key_t element);
std::string to_short_string(struct npl_snoop_code_hw_table_key_t element);

struct npl_snoop_code_hw_table_value_t
{
    npl_snoop_code_hw_table_action_e action;
    union npl_snoop_code_hw_table_payloads_t {
        uint64_t rxpp_pd_in_mirror_cmd0 : 5;
    } payloads;
    std::string npl_action_enum_to_string(const npl_snoop_code_hw_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_SNOOP_CODE_HW_TABLE_ACTION_WRITE:
            {
                return "NPL_SNOOP_CODE_HW_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_snoop_code_hw_table_action_e");
        }
        return "";
    }
    npl_snoop_code_hw_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_snoop_code_hw_table_value_t element);
std::string to_short_string(struct npl_snoop_code_hw_table_value_t element);

/// API-s for table: snoop_table

typedef enum
{
    NPL_SNOOP_TABLE_ACTION_WRITE = 0x0
} npl_snoop_table_action_e;

struct npl_snoop_table_key_t
{
    npl_traps_t traps;
    npl_trap_conditions_t trap_conditions;
    
    npl_snoop_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector384_t pack(void) const;
    void unpack(bit_vector384_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_snoop_table_key_t element);
std::string to_short_string(struct npl_snoop_table_key_t element);

struct npl_snoop_table_value_t
{
    npl_snoop_table_action_e action;
    union npl_snoop_table_payloads_t {
        npl_snoop_code_t snoop_code;
    } payloads;
    std::string npl_action_enum_to_string(const npl_snoop_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_SNOOP_TABLE_ACTION_WRITE:
            {
                return "NPL_SNOOP_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_snoop_table_action_e");
        }
        return "";
    }
    npl_snoop_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_snoop_table_value_t element);
std::string to_short_string(struct npl_snoop_table_value_t element);

/// API-s for table: snoop_to_dsp_in_npu_soft_header_table

typedef enum
{
    NPL_SNOOP_TO_DSP_IN_NPU_SOFT_HEADER_TABLE_ACTION_WRITE = 0x0
} npl_snoop_to_dsp_in_npu_soft_header_table_action_e;

struct npl_snoop_to_dsp_in_npu_soft_header_table_key_t
{
    uint64_t device_snoop_code : 8;
    
    npl_snoop_to_dsp_in_npu_soft_header_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_snoop_to_dsp_in_npu_soft_header_table_key_t element);
std::string to_short_string(struct npl_snoop_to_dsp_in_npu_soft_header_table_key_t element);

struct npl_snoop_to_dsp_in_npu_soft_header_table_value_t
{
    npl_snoop_to_dsp_in_npu_soft_header_table_action_e action;
    union npl_snoop_to_dsp_in_npu_soft_header_table_payloads_t {
        uint64_t update_dsp_in_npu_soft_header : 1;
    } payloads;
    std::string npl_action_enum_to_string(const npl_snoop_to_dsp_in_npu_soft_header_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_SNOOP_TO_DSP_IN_NPU_SOFT_HEADER_TABLE_ACTION_WRITE:
            {
                return "NPL_SNOOP_TO_DSP_IN_NPU_SOFT_HEADER_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_snoop_to_dsp_in_npu_soft_header_table_action_e");
        }
        return "";
    }
    npl_snoop_to_dsp_in_npu_soft_header_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_snoop_to_dsp_in_npu_soft_header_table_value_t element);
std::string to_short_string(struct npl_snoop_to_dsp_in_npu_soft_header_table_value_t element);

/// API-s for table: source_pif_hw_table

typedef enum
{
    NPL_SOURCE_PIF_HW_TABLE_ACTION_INIT_RX_DATA = 0x0
} npl_source_pif_hw_table_action_e;

struct npl_source_pif_hw_table_init_rx_data_payload_t
{
    uint64_t initial_layer_index : 4;
    npl_pd_rx_nw_app_t_anonymous_union_init_fields_union_t initial_rx_data;
    npl_tag_swap_cmd_e tag_swap_cmd;
    uint64_t np_macro_id : 6;
    uint64_t fi_macro_id : 6;
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_source_pif_hw_table_init_rx_data_payload_t element);
std::string to_short_string(npl_source_pif_hw_table_init_rx_data_payload_t element);

struct npl_source_pif_hw_table_key_t
{
    uint64_t rxpp_npu_input_ifg_rx_fd_source_pif : 5;
    uint64_t rxpp_npu_input_ifg : 1;
    
    npl_source_pif_hw_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_source_pif_hw_table_key_t element);
std::string to_short_string(struct npl_source_pif_hw_table_key_t element);

struct npl_source_pif_hw_table_value_t
{
    npl_source_pif_hw_table_action_e action;
    union npl_source_pif_hw_table_payloads_t {
        npl_source_pif_hw_table_init_rx_data_payload_t init_rx_data;
    } payloads;
    std::string npl_action_enum_to_string(const npl_source_pif_hw_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_SOURCE_PIF_HW_TABLE_ACTION_INIT_RX_DATA:
            {
                return "NPL_SOURCE_PIF_HW_TABLE_ACTION_INIT_RX_DATA(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_source_pif_hw_table_action_e");
        }
        return "";
    }
    npl_source_pif_hw_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_source_pif_hw_table_value_t element);
std::string to_short_string(struct npl_source_pif_hw_table_value_t element);

/// API-s for table: stage2_lb_group_size_table

typedef enum
{
    NPL_STAGE2_LB_GROUP_SIZE_TABLE_ACTION_WRITE = 0x0
} npl_stage2_lb_group_size_table_action_e;

struct npl_stage2_lb_group_size_table_key_t
{
    uint64_t ecmp_id : 13;
    
    npl_stage2_lb_group_size_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_stage2_lb_group_size_table_key_t element);
std::string to_short_string(struct npl_stage2_lb_group_size_table_key_t element);

struct npl_stage2_lb_group_size_table_value_t
{
    npl_stage2_lb_group_size_table_action_e action;
    union npl_stage2_lb_group_size_table_payloads_t {
        npl_lb_group_size_table_result_t stage2_lb_group_size_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_stage2_lb_group_size_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_STAGE2_LB_GROUP_SIZE_TABLE_ACTION_WRITE:
            {
                return "NPL_STAGE2_LB_GROUP_SIZE_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_stage2_lb_group_size_table_action_e");
        }
        return "";
    }
    npl_stage2_lb_group_size_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_stage2_lb_group_size_table_value_t element);
std::string to_short_string(struct npl_stage2_lb_group_size_table_value_t element);

/// API-s for table: stage2_lb_table

typedef enum
{
    NPL_STAGE2_LB_TABLE_ACTION_WRITE = 0x0
} npl_stage2_lb_table_action_e;

struct npl_stage2_lb_table_key_t
{
    uint64_t member_id : 16;
    uint64_t group_id : 14;
    
    npl_stage2_lb_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_stage2_lb_table_key_t element);
std::string to_short_string(struct npl_stage2_lb_table_key_t element);

struct npl_stage2_lb_table_value_t
{
    npl_stage2_lb_table_action_e action;
    union npl_stage2_lb_table_payloads_t {
        npl_stage2_lb_table_result_t stage2_lb_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_stage2_lb_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_STAGE2_LB_TABLE_ACTION_WRITE:
            {
                return "NPL_STAGE2_LB_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_stage2_lb_table_action_e");
        }
        return "";
    }
    npl_stage2_lb_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_stage2_lb_table_value_t element);
std::string to_short_string(struct npl_stage2_lb_table_value_t element);

/// API-s for table: stage3_lb_group_size_table

typedef enum
{
    NPL_STAGE3_LB_GROUP_SIZE_TABLE_ACTION_WRITE = 0x0
} npl_stage3_lb_group_size_table_action_e;

struct npl_stage3_lb_group_size_table_key_t
{
    uint64_t stage3_lb_id : 13;
    
    npl_stage3_lb_group_size_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_stage3_lb_group_size_table_key_t element);
std::string to_short_string(struct npl_stage3_lb_group_size_table_key_t element);

struct npl_stage3_lb_group_size_table_value_t
{
    npl_stage3_lb_group_size_table_action_e action;
    union npl_stage3_lb_group_size_table_payloads_t {
        npl_lb_group_size_table_result_t stage3_lb_group_size_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_stage3_lb_group_size_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_STAGE3_LB_GROUP_SIZE_TABLE_ACTION_WRITE:
            {
                return "NPL_STAGE3_LB_GROUP_SIZE_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_stage3_lb_group_size_table_action_e");
        }
        return "";
    }
    npl_stage3_lb_group_size_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_stage3_lb_group_size_table_value_t element);
std::string to_short_string(struct npl_stage3_lb_group_size_table_value_t element);

/// API-s for table: stage3_lb_table

typedef enum
{
    NPL_STAGE3_LB_TABLE_ACTION_WRITE = 0x0
} npl_stage3_lb_table_action_e;

struct npl_stage3_lb_table_key_t
{
    uint64_t member_id : 16;
    uint64_t group_id : 14;
    
    npl_stage3_lb_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_stage3_lb_table_key_t element);
std::string to_short_string(struct npl_stage3_lb_table_key_t element);

struct npl_stage3_lb_table_value_t
{
    npl_stage3_lb_table_action_e action;
    union npl_stage3_lb_table_payloads_t {
        npl_stage3_lb_table_result_t stage3_lb_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_stage3_lb_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_STAGE3_LB_TABLE_ACTION_WRITE:
            {
                return "NPL_STAGE3_LB_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_stage3_lb_table_action_e");
        }
        return "";
    }
    npl_stage3_lb_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_stage3_lb_table_value_t element);
std::string to_short_string(struct npl_stage3_lb_table_value_t element);

/// API-s for table: stage3_lb_type_decoding_table

typedef enum
{
    NPL_STAGE3_LB_TYPE_DECODING_TABLE_ACTION_WRITE = 0x0
} npl_stage3_lb_type_decoding_table_action_e;

struct npl_stage3_lb_type_decoding_table_key_t
{
    npl_stage3_lb_entry_type_e type;
    
    npl_stage3_lb_type_decoding_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_stage3_lb_type_decoding_table_key_t element);
std::string to_short_string(struct npl_stage3_lb_type_decoding_table_key_t element);

struct npl_stage3_lb_type_decoding_table_value_t
{
    npl_stage3_lb_type_decoding_table_action_e action;
    union npl_stage3_lb_type_decoding_table_payloads_t {
        npl_resolution_type_decoding_table_result_t stage3_lb_type_decoding_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_stage3_lb_type_decoding_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_STAGE3_LB_TYPE_DECODING_TABLE_ACTION_WRITE:
            {
                return "NPL_STAGE3_LB_TYPE_DECODING_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_stage3_lb_type_decoding_table_action_e");
        }
        return "";
    }
    npl_stage3_lb_type_decoding_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_stage3_lb_type_decoding_table_value_t element);
std::string to_short_string(struct npl_stage3_lb_type_decoding_table_value_t element);

/// API-s for table: svl_next_macro_static_table

typedef enum
{
    NPL_SVL_NEXT_MACRO_STATIC_TABLE_ACTION_SVL_NEXT_MACRO_ACTION = 0x0
} npl_svl_next_macro_static_table_action_e;

struct npl_svl_next_macro_static_table_svl_next_macro_action_payload_t
{
    uint64_t ipc_trap : 1;
    uint64_t protocol_trap : 1;
    uint64_t pl_inc : 2;
    uint64_t macro_id : 8;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_svl_next_macro_static_table_svl_next_macro_action_payload_t element);
std::string to_short_string(npl_svl_next_macro_static_table_svl_next_macro_action_payload_t element);

struct npl_svl_next_macro_static_table_key_t
{
    npl_protocol_type_e type;
    uint64_t mac_da_prefix : 8;
    
    npl_svl_next_macro_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_svl_next_macro_static_table_key_t element);
std::string to_short_string(struct npl_svl_next_macro_static_table_key_t element);

struct npl_svl_next_macro_static_table_value_t
{
    npl_svl_next_macro_static_table_action_e action;
    union npl_svl_next_macro_static_table_payloads_t {
        npl_svl_next_macro_static_table_svl_next_macro_action_payload_t svl_next_macro_action;
    } payloads;
    std::string npl_action_enum_to_string(const npl_svl_next_macro_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_SVL_NEXT_MACRO_STATIC_TABLE_ACTION_SVL_NEXT_MACRO_ACTION:
            {
                return "NPL_SVL_NEXT_MACRO_STATIC_TABLE_ACTION_SVL_NEXT_MACRO_ACTION(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_svl_next_macro_static_table_action_e");
        }
        return "";
    }
    npl_svl_next_macro_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_svl_next_macro_static_table_value_t element);
std::string to_short_string(struct npl_svl_next_macro_static_table_value_t element);

/// API-s for table: te_headend_lsp_counter_offset_table

typedef enum
{
    NPL_TE_HEADEND_LSP_COUNTER_OFFSET_TABLE_ACTION_OFFSETS = 0x0
} npl_te_headend_lsp_counter_offset_table_action_e;

struct npl_te_headend_lsp_counter_offset_table_offsets_payload_t
{
    npl_common_cntr_offset_and_padding_t lsp_counter_offset;
    npl_common_cntr_offset_and_padding_t php_counter_offset;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_te_headend_lsp_counter_offset_table_offsets_payload_t element);
std::string to_short_string(npl_te_headend_lsp_counter_offset_table_offsets_payload_t element);

struct npl_te_headend_lsp_counter_offset_table_key_t
{
    uint64_t is_mc : 1;
    npl_fwd_header_type_e fwd_header_type;
    npl_npu_encap_l3_header_type_e l3_encap_type;
    
    npl_te_headend_lsp_counter_offset_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_te_headend_lsp_counter_offset_table_key_t element);
std::string to_short_string(struct npl_te_headend_lsp_counter_offset_table_key_t element);

struct npl_te_headend_lsp_counter_offset_table_value_t
{
    npl_te_headend_lsp_counter_offset_table_action_e action;
    union npl_te_headend_lsp_counter_offset_table_payloads_t {
        npl_te_headend_lsp_counter_offset_table_offsets_payload_t offsets;
    } payloads;
    std::string npl_action_enum_to_string(const npl_te_headend_lsp_counter_offset_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_TE_HEADEND_LSP_COUNTER_OFFSET_TABLE_ACTION_OFFSETS:
            {
                return "NPL_TE_HEADEND_LSP_COUNTER_OFFSET_TABLE_ACTION_OFFSETS(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_te_headend_lsp_counter_offset_table_action_e");
        }
        return "";
    }
    npl_te_headend_lsp_counter_offset_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_te_headend_lsp_counter_offset_table_value_t element);
std::string to_short_string(struct npl_te_headend_lsp_counter_offset_table_value_t element);

/// API-s for table: termination_to_forwarding_fi_hardwired_table

typedef enum
{
    NPL_TERMINATION_TO_FORWARDING_FI_HARDWIRED_TABLE_ACTION_WRITE = 0x0
} npl_termination_to_forwarding_fi_hardwired_table_action_e;

struct npl_termination_to_forwarding_fi_hardwired_table_key_t
{
    npl_protocol_type_e packet_protocol_layer_current__header_0__header_info_type;
    
    npl_termination_to_forwarding_fi_hardwired_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_termination_to_forwarding_fi_hardwired_table_key_t element);
std::string to_short_string(struct npl_termination_to_forwarding_fi_hardwired_table_key_t element);

struct npl_termination_to_forwarding_fi_hardwired_table_value_t
{
    npl_termination_to_forwarding_fi_hardwired_table_action_e action;
    union npl_termination_to_forwarding_fi_hardwired_table_payloads_t {
        npl_fi_hardwired_type_e termination_to_forwarding_fields_fi_hardwired_type;
    } payloads;
    std::string npl_action_enum_to_string(const npl_termination_to_forwarding_fi_hardwired_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_TERMINATION_TO_FORWARDING_FI_HARDWIRED_TABLE_ACTION_WRITE:
            {
                return "NPL_TERMINATION_TO_FORWARDING_FI_HARDWIRED_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_termination_to_forwarding_fi_hardwired_table_action_e");
        }
        return "";
    }
    npl_termination_to_forwarding_fi_hardwired_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_termination_to_forwarding_fi_hardwired_table_value_t element);
std::string to_short_string(struct npl_termination_to_forwarding_fi_hardwired_table_value_t element);

/// API-s for table: tm_ibm_cmd_to_destination

typedef enum
{
    NPL_TM_IBM_CMD_TO_DESTINATION_ACTION_FOUND = 0x0
} npl_tm_ibm_cmd_to_destination_action_e;

struct npl_tm_ibm_cmd_to_destination_found_payload_t
{
    uint64_t dest_slice_id : 3;
    uint64_t dest_pif : 5;
    uint64_t dest_ifg : 1;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_tm_ibm_cmd_to_destination_found_payload_t element);
std::string to_short_string(npl_tm_ibm_cmd_to_destination_found_payload_t element);

struct npl_tm_ibm_cmd_to_destination_key_t
{
    uint64_t rxpp_to_txpp_local_vars_mirror_command : 5;
    
    npl_tm_ibm_cmd_to_destination_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_tm_ibm_cmd_to_destination_key_t element);
std::string to_short_string(struct npl_tm_ibm_cmd_to_destination_key_t element);

struct npl_tm_ibm_cmd_to_destination_value_t
{
    npl_tm_ibm_cmd_to_destination_action_e action;
    union npl_tm_ibm_cmd_to_destination_payloads_t {
        npl_tm_ibm_cmd_to_destination_found_payload_t found;
    } payloads;
    std::string npl_action_enum_to_string(const npl_tm_ibm_cmd_to_destination_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_TM_IBM_CMD_TO_DESTINATION_ACTION_FOUND:
            {
                return "NPL_TM_IBM_CMD_TO_DESTINATION_ACTION_FOUND(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_tm_ibm_cmd_to_destination_action_e");
        }
        return "";
    }
    npl_tm_ibm_cmd_to_destination_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_tm_ibm_cmd_to_destination_value_t element);
std::string to_short_string(struct npl_tm_ibm_cmd_to_destination_value_t element);

/// API-s for table: ts_cmd_hw_static_table

typedef enum
{
    NPL_TS_CMD_HW_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_ts_cmd_hw_static_table_action_e;

struct npl_ts_cmd_hw_static_table_key_t
{
    uint64_t pd_tx_common_tx_leaba_fields_ts_command_op : 4;
    
    npl_ts_cmd_hw_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_ts_cmd_hw_static_table_key_t element);
std::string to_short_string(struct npl_ts_cmd_hw_static_table_key_t element);

struct npl_ts_cmd_hw_static_table_value_t
{
    npl_ts_cmd_hw_static_table_action_e action;
    union npl_ts_cmd_hw_static_table_payloads_t {
        npl_ts_cmd_trans_t ts_cmd_trans;
    } payloads;
    std::string npl_action_enum_to_string(const npl_ts_cmd_hw_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_TS_CMD_HW_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_TS_CMD_HW_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_ts_cmd_hw_static_table_action_e");
        }
        return "";
    }
    npl_ts_cmd_hw_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_ts_cmd_hw_static_table_value_t element);
std::string to_short_string(struct npl_ts_cmd_hw_static_table_value_t element);

/// API-s for table: tunnel_dlp_p_counter_offset_table

typedef enum
{
    NPL_TUNNEL_DLP_P_COUNTER_OFFSET_TABLE_ACTION_WRITE = 0x0
} npl_tunnel_dlp_p_counter_offset_table_action_e;

struct npl_tunnel_dlp_p_counter_offset_table_key_t
{
    uint64_t is_mc : 1;
    uint64_t is_mpls : 1;
    npl_npu_encap_l3_header_type_e l3_encap_type;
    npl_fwd_header_type_e fwd_header_type;
    
    npl_tunnel_dlp_p_counter_offset_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_tunnel_dlp_p_counter_offset_table_key_t element);
std::string to_short_string(struct npl_tunnel_dlp_p_counter_offset_table_key_t element);

struct npl_tunnel_dlp_p_counter_offset_table_value_t
{
    npl_tunnel_dlp_p_counter_offset_table_action_e action;
    union npl_tunnel_dlp_p_counter_offset_table_payloads_t {
        npl_counter_offset_t cntr_offset;
    } payloads;
    std::string npl_action_enum_to_string(const npl_tunnel_dlp_p_counter_offset_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_TUNNEL_DLP_P_COUNTER_OFFSET_TABLE_ACTION_WRITE:
            {
                return "NPL_TUNNEL_DLP_P_COUNTER_OFFSET_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_tunnel_dlp_p_counter_offset_table_action_e");
        }
        return "";
    }
    npl_tunnel_dlp_p_counter_offset_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_tunnel_dlp_p_counter_offset_table_value_t element);
std::string to_short_string(struct npl_tunnel_dlp_p_counter_offset_table_value_t element);

/// API-s for table: tunnel_qos_static_table

typedef enum
{
    NPL_TUNNEL_QOS_STATIC_TABLE_ACTION_UPDATE_DSCP_FROM_L3_DLP_WITH_FWD_QOS_TAG = 0x0,
    NPL_TUNNEL_QOS_STATIC_TABLE_ACTION_UPDATE_DSCP_FROM_L3_DLP_WITH_QOS_GROUP = 0x1,
    NPL_TUNNEL_QOS_STATIC_TABLE_ACTION_UPDATE_DSCP_FROM_TUNNEL = 0x2
} npl_tunnel_qos_static_table_action_e;

struct npl_tunnel_qos_static_table_key_t
{
    uint64_t lp_set : 1;
    uint64_t l3_dlp_is_group_qos : 1;
    
    npl_tunnel_qos_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_tunnel_qos_static_table_key_t element);
std::string to_short_string(struct npl_tunnel_qos_static_table_key_t element);

struct npl_tunnel_qos_static_table_value_t
{
    npl_tunnel_qos_static_table_action_e action;
    std::string npl_action_enum_to_string(const npl_tunnel_qos_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_TUNNEL_QOS_STATIC_TABLE_ACTION_UPDATE_DSCP_FROM_L3_DLP_WITH_FWD_QOS_TAG:
            {
                return "NPL_TUNNEL_QOS_STATIC_TABLE_ACTION_UPDATE_DSCP_FROM_L3_DLP_WITH_FWD_QOS_TAG(0x0)";
                break;
            }
            case NPL_TUNNEL_QOS_STATIC_TABLE_ACTION_UPDATE_DSCP_FROM_L3_DLP_WITH_QOS_GROUP:
            {
                return "NPL_TUNNEL_QOS_STATIC_TABLE_ACTION_UPDATE_DSCP_FROM_L3_DLP_WITH_QOS_GROUP(0x1)";
                break;
            }
            case NPL_TUNNEL_QOS_STATIC_TABLE_ACTION_UPDATE_DSCP_FROM_TUNNEL:
            {
                return "NPL_TUNNEL_QOS_STATIC_TABLE_ACTION_UPDATE_DSCP_FROM_TUNNEL(0x2)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_tunnel_qos_static_table_action_e");
        }
        return "";
    }
    npl_tunnel_qos_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_tunnel_qos_static_table_value_t element);
std::string to_short_string(struct npl_tunnel_qos_static_table_value_t element);

/// API-s for table: tx_counters_block_config_table

typedef enum
{
    NPL_TX_COUNTERS_BLOCK_CONFIG_TABLE_ACTION_CONFIG = 0x0
} npl_tx_counters_block_config_table_action_e;

struct npl_tx_counters_block_config_table_config_payload_t
{
    uint64_t inc_bank_for_ifg_b : 1;
    uint64_t inc_addr_for_set : 1;
    npl_tx_counters_set_type_e bank_set_type;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_tx_counters_block_config_table_config_payload_t element);
std::string to_short_string(npl_tx_counters_block_config_table_config_payload_t element);

struct npl_tx_counters_block_config_table_key_t
{
    uint64_t counter_block_id : 7;
    
    npl_tx_counters_block_config_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_tx_counters_block_config_table_key_t element);
std::string to_short_string(struct npl_tx_counters_block_config_table_key_t element);

struct npl_tx_counters_block_config_table_value_t
{
    npl_tx_counters_block_config_table_action_e action;
    union npl_tx_counters_block_config_table_payloads_t {
        npl_tx_counters_block_config_table_config_payload_t config;
    } payloads;
    std::string npl_action_enum_to_string(const npl_tx_counters_block_config_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_TX_COUNTERS_BLOCK_CONFIG_TABLE_ACTION_CONFIG:
            {
                return "NPL_TX_COUNTERS_BLOCK_CONFIG_TABLE_ACTION_CONFIG(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_tx_counters_block_config_table_action_e");
        }
        return "";
    }
    npl_tx_counters_block_config_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_tx_counters_block_config_table_value_t element);
std::string to_short_string(struct npl_tx_counters_block_config_table_value_t element);

/// API-s for table: tx_error_handling_counter_table

typedef enum
{
    NPL_TX_ERROR_HANDLING_COUNTER_TABLE_ACTION_UPDATE_RESULT = 0x0
} npl_tx_error_handling_counter_table_action_e;

struct npl_tx_error_handling_counter_table_update_result_payload_t
{
    npl_counter_ptr_t counter;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_tx_error_handling_counter_table_update_result_payload_t element);
std::string to_short_string(npl_tx_error_handling_counter_table_update_result_payload_t element);

struct npl_tx_error_handling_counter_table_key_t
{
    uint64_t ser : 1;
    uint64_t dest_pif : 5;
    
    npl_tx_error_handling_counter_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_tx_error_handling_counter_table_key_t element);
std::string to_short_string(struct npl_tx_error_handling_counter_table_key_t element);

struct npl_tx_error_handling_counter_table_value_t
{
    npl_tx_error_handling_counter_table_action_e action;
    union npl_tx_error_handling_counter_table_payloads_t {
        npl_tx_error_handling_counter_table_update_result_payload_t update_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_tx_error_handling_counter_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_TX_ERROR_HANDLING_COUNTER_TABLE_ACTION_UPDATE_RESULT:
            {
                return "NPL_TX_ERROR_HANDLING_COUNTER_TABLE_ACTION_UPDATE_RESULT(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_tx_error_handling_counter_table_action_e");
        }
        return "";
    }
    npl_tx_error_handling_counter_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_tx_error_handling_counter_table_value_t element);
std::string to_short_string(struct npl_tx_error_handling_counter_table_value_t element);

/// API-s for table: tx_punt_eth_encap_table

typedef enum
{
    NPL_TX_PUNT_ETH_ENCAP_TABLE_ACTION_FOUND = 0x0
} npl_tx_punt_eth_encap_table_action_e;

struct npl_tx_punt_eth_encap_table_found_payload_t
{
    uint64_t wide_bit : 1;
    npl_pcp_dei_t eth_pcp_dei;
    npl_tx_punt_local_var_t_anonymous_union_ene_eth_or_npu_host_data_t punt_eth_or_npu_host_encap;
    
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_tx_punt_eth_encap_table_found_payload_t element);
std::string to_short_string(npl_tx_punt_eth_encap_table_found_payload_t element);

struct npl_tx_punt_eth_encap_table_key_t
{
    uint64_t punt_encap : 9;
    
    npl_tx_punt_eth_encap_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_tx_punt_eth_encap_table_key_t element);
std::string to_short_string(struct npl_tx_punt_eth_encap_table_key_t element);

struct npl_tx_punt_eth_encap_table_value_t
{
    npl_tx_punt_eth_encap_table_action_e action;
    union npl_tx_punt_eth_encap_table_payloads_t {
        npl_tx_punt_eth_encap_table_found_payload_t found;
    } payloads;
    std::string npl_action_enum_to_string(const npl_tx_punt_eth_encap_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_TX_PUNT_ETH_ENCAP_TABLE_ACTION_FOUND:
            {
                return "NPL_TX_PUNT_ETH_ENCAP_TABLE_ACTION_FOUND(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_tx_punt_eth_encap_table_action_e");
        }
        return "";
    }
    npl_tx_punt_eth_encap_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_tx_punt_eth_encap_table_value_t element);
std::string to_short_string(struct npl_tx_punt_eth_encap_table_value_t element);

/// API-s for table: tx_redirect_code_table

typedef enum
{
    NPL_TX_REDIRECT_CODE_TABLE_ACTION_TX_REDIRECT_ACTION = 0x0
} npl_tx_redirect_code_table_action_e;

struct npl_tx_redirect_code_table_tx_redirect_action_payload_t
{
    npl_redirect_is_drop_action_e is_drop_action;
    npl_stamp_on_headers_e stamp_into_packet_header;
    npl_lm_command_t cntr_stamp_cmd;
    npl_ts_command_t ts_cmd;
    npl_tx_punt_nw_encap_ptr_t tx_punt_nw_encap_ptr;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_tx_redirect_code_table_tx_redirect_action_payload_t element);
std::string to_short_string(npl_tx_redirect_code_table_tx_redirect_action_payload_t element);

struct npl_tx_redirect_code_table_key_t
{
    uint64_t tx_redirect_code : 8;
    
    npl_tx_redirect_code_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_tx_redirect_code_table_key_t element);
std::string to_short_string(struct npl_tx_redirect_code_table_key_t element);

struct npl_tx_redirect_code_table_value_t
{
    npl_tx_redirect_code_table_action_e action;
    union npl_tx_redirect_code_table_payloads_t {
        npl_tx_redirect_code_table_tx_redirect_action_payload_t tx_redirect_action;
    } payloads;
    std::string npl_action_enum_to_string(const npl_tx_redirect_code_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_TX_REDIRECT_CODE_TABLE_ACTION_TX_REDIRECT_ACTION:
            {
                return "NPL_TX_REDIRECT_CODE_TABLE_ACTION_TX_REDIRECT_ACTION(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_tx_redirect_code_table_action_e");
        }
        return "";
    }
    npl_tx_redirect_code_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_tx_redirect_code_table_value_t element);
std::string to_short_string(struct npl_tx_redirect_code_table_value_t element);

/// API-s for table: txpdr_mc_list_size_table

typedef enum
{
    NPL_TXPDR_MC_LIST_SIZE_TABLE_ACTION_WRITE = 0x0
} npl_txpdr_mc_list_size_table_action_e;

struct npl_txpdr_mc_list_size_table_key_t
{
    uint64_t rxpdr_output_rxrq_cud_rxrq_cud_encoding_mcid_mcid : 16;
    
    npl_txpdr_mc_list_size_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_txpdr_mc_list_size_table_key_t element);
std::string to_short_string(struct npl_txpdr_mc_list_size_table_key_t element);

struct npl_txpdr_mc_list_size_table_value_t
{
    npl_txpdr_mc_list_size_table_action_e action;
    union npl_txpdr_mc_list_size_table_payloads_t {
        uint64_t txpdr_local_vars_mc_group_size : 11;
    } payloads;
    std::string npl_action_enum_to_string(const npl_txpdr_mc_list_size_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_TXPDR_MC_LIST_SIZE_TABLE_ACTION_WRITE:
            {
                return "NPL_TXPDR_MC_LIST_SIZE_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_txpdr_mc_list_size_table_action_e");
        }
        return "";
    }
    npl_txpdr_mc_list_size_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_txpdr_mc_list_size_table_value_t element);
std::string to_short_string(struct npl_txpdr_mc_list_size_table_value_t element);

/// API-s for table: txpdr_tc_map_table

typedef enum
{
    NPL_TXPDR_TC_MAP_TABLE_ACTION_WRITE = 0x0
} npl_txpdr_tc_map_table_action_e;

struct npl_txpdr_tc_map_table_key_t
{
    uint64_t txpdr_local_vars_tc_map_profile : 3;
    uint64_t rxpp_pd_tc : 3;
    
    npl_txpdr_tc_map_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_txpdr_tc_map_table_key_t element);
std::string to_short_string(struct npl_txpdr_tc_map_table_key_t element);

struct npl_txpdr_tc_map_table_value_t
{
    npl_txpdr_tc_map_table_action_e action;
    union npl_txpdr_tc_map_table_payloads_t {
        uint64_t txpdr_local_vars_tc_offset : 3;
    } payloads;
    std::string npl_action_enum_to_string(const npl_txpdr_tc_map_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_TXPDR_TC_MAP_TABLE_ACTION_WRITE:
            {
                return "NPL_TXPDR_TC_MAP_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_txpdr_tc_map_table_action_e");
        }
        return "";
    }
    npl_txpdr_tc_map_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_txpdr_tc_map_table_value_t element);
std::string to_short_string(struct npl_txpdr_tc_map_table_value_t element);

/// API-s for table: txpp_dlp_profile_table

typedef enum
{
    NPL_TXPP_DLP_PROFILE_TABLE_ACTION_WRITE = 0x0
} npl_txpp_dlp_profile_table_action_e;

struct npl_txpp_dlp_profile_table_key_t
{
    uint64_t txpp_dlp_profile_info_dlp_msbs_13_12 : 2;
    uint64_t txpp_dlp_profile_info_dlp_msbs_11_0 : 12;
    
    npl_txpp_dlp_profile_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_txpp_dlp_profile_table_key_t element);
std::string to_short_string(struct npl_txpp_dlp_profile_table_key_t element);

struct npl_txpp_dlp_profile_table_value_t
{
    npl_txpp_dlp_profile_table_action_e action;
    union npl_txpp_dlp_profile_table_payloads_t {
        npl_dlp_profile_union_t pd_tx_dlp_profile;
    } payloads;
    std::string npl_action_enum_to_string(const npl_txpp_dlp_profile_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_TXPP_DLP_PROFILE_TABLE_ACTION_WRITE:
            {
                return "NPL_TXPP_DLP_PROFILE_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_txpp_dlp_profile_table_action_e");
        }
        return "";
    }
    npl_txpp_dlp_profile_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_txpp_dlp_profile_table_value_t element);
std::string to_short_string(struct npl_txpp_dlp_profile_table_value_t element);

/// API-s for table: txpp_encap_qos_mapping_table

typedef enum
{
    NPL_TXPP_ENCAP_QOS_MAPPING_TABLE_ACTION_WRITE = 0x0
} npl_txpp_encap_qos_mapping_table_action_e;

struct npl_txpp_encap_qos_mapping_table_key_t
{
    uint64_t packet_protocol_layer_none__tx_npu_header_slp_qos_id : 4;
    uint64_t pd_tx_out_color : 2;
    uint64_t packet_protocol_layer_none__tx_npu_header_encap_qos_tag : 7;
    
    npl_txpp_encap_qos_mapping_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_txpp_encap_qos_mapping_table_key_t element);
std::string to_short_string(struct npl_txpp_encap_qos_mapping_table_key_t element);

struct npl_txpp_encap_qos_mapping_table_value_t
{
    npl_txpp_encap_qos_mapping_table_action_e action;
    union npl_txpp_encap_qos_mapping_table_payloads_t {
        uint64_t txpp_npu_header_encap_qos_tag : 7;
    } payloads;
    std::string npl_action_enum_to_string(const npl_txpp_encap_qos_mapping_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_TXPP_ENCAP_QOS_MAPPING_TABLE_ACTION_WRITE:
            {
                return "NPL_TXPP_ENCAP_QOS_MAPPING_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_txpp_encap_qos_mapping_table_action_e");
        }
        return "";
    }
    npl_txpp_encap_qos_mapping_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_txpp_encap_qos_mapping_table_value_t element);
std::string to_short_string(struct npl_txpp_encap_qos_mapping_table_value_t element);

/// API-s for table: txpp_first_enc_type_to_second_enc_type_offset

typedef enum
{
    NPL_TXPP_FIRST_ENC_TYPE_TO_SECOND_ENC_TYPE_OFFSET_ACTION_WRITE = 0x0
} npl_txpp_first_enc_type_to_second_enc_type_offset_action_e;

struct npl_txpp_first_enc_type_to_second_enc_type_offset_key_t
{
    uint64_t packet_protocol_layer_0__tx_npu_header_encap_or_term_107_104_ : 4;
    
    npl_txpp_first_enc_type_to_second_enc_type_offset_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_txpp_first_enc_type_to_second_enc_type_offset_key_t element);
std::string to_short_string(struct npl_txpp_first_enc_type_to_second_enc_type_offset_key_t element);

struct npl_txpp_first_enc_type_to_second_enc_type_offset_value_t
{
    npl_txpp_first_enc_type_to_second_enc_type_offset_action_e action;
    union npl_txpp_first_enc_type_to_second_enc_type_offset_payloads_t {
        npl_bool_t txpp_first_encap_is_wide;
    } payloads;
    std::string npl_action_enum_to_string(const npl_txpp_first_enc_type_to_second_enc_type_offset_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_TXPP_FIRST_ENC_TYPE_TO_SECOND_ENC_TYPE_OFFSET_ACTION_WRITE:
            {
                return "NPL_TXPP_FIRST_ENC_TYPE_TO_SECOND_ENC_TYPE_OFFSET_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_txpp_first_enc_type_to_second_enc_type_offset_action_e");
        }
        return "";
    }
    npl_txpp_first_enc_type_to_second_enc_type_offset_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_txpp_first_enc_type_to_second_enc_type_offset_value_t element);
std::string to_short_string(struct npl_txpp_first_enc_type_to_second_enc_type_offset_value_t element);

/// API-s for table: txpp_fwd_header_type_is_l2_table

typedef enum
{
    NPL_TXPP_FWD_HEADER_TYPE_IS_L2_TABLE_ACTION_WRITE = 0x0
} npl_txpp_fwd_header_type_is_l2_table_action_e;

struct npl_txpp_fwd_header_type_is_l2_table_key_t
{
    npl_fwd_header_type_e packet_protocol_layer_0__tx_npu_header_fwd_header_type;
    uint64_t packet_protocol_layer_0__tx_npu_header_encap_or_term_107_104_ : 4;
    
    npl_txpp_fwd_header_type_is_l2_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_txpp_fwd_header_type_is_l2_table_key_t element);
std::string to_short_string(struct npl_txpp_fwd_header_type_is_l2_table_key_t element);

struct npl_txpp_fwd_header_type_is_l2_table_value_t
{
    npl_txpp_fwd_header_type_is_l2_table_action_e action;
    union npl_txpp_fwd_header_type_is_l2_table_payloads_t {
        uint64_t txpp_dlp_profile_info_fwd_header_type_is_l2 : 1;
    } payloads;
    std::string npl_action_enum_to_string(const npl_txpp_fwd_header_type_is_l2_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_TXPP_FWD_HEADER_TYPE_IS_L2_TABLE_ACTION_WRITE:
            {
                return "NPL_TXPP_FWD_HEADER_TYPE_IS_L2_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_txpp_fwd_header_type_is_l2_table_action_e");
        }
        return "";
    }
    npl_txpp_fwd_header_type_is_l2_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_txpp_fwd_header_type_is_l2_table_value_t element);
std::string to_short_string(struct npl_txpp_fwd_header_type_is_l2_table_value_t element);

/// API-s for table: txpp_fwd_qos_mapping_table

typedef enum
{
    NPL_TXPP_FWD_QOS_MAPPING_TABLE_ACTION_WRITE = 0x0
} npl_txpp_fwd_qos_mapping_table_action_e;

struct npl_txpp_fwd_qos_mapping_table_key_t
{
    uint64_t packet_protocol_layer_none__tx_npu_header_slp_qos_id : 4;
    uint64_t pd_tx_out_color : 2;
    uint64_t packet_protocol_layer_none__tx_npu_header_fwd_qos_tag : 7;
    
    npl_txpp_fwd_qos_mapping_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_txpp_fwd_qos_mapping_table_key_t element);
std::string to_short_string(struct npl_txpp_fwd_qos_mapping_table_key_t element);

struct npl_txpp_fwd_qos_mapping_table_value_t
{
    npl_txpp_fwd_qos_mapping_table_action_e action;
    union npl_txpp_fwd_qos_mapping_table_payloads_t {
        uint64_t txpp_npu_header_fwd_qos_tag : 7;
    } payloads;
    std::string npl_action_enum_to_string(const npl_txpp_fwd_qos_mapping_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_TXPP_FWD_QOS_MAPPING_TABLE_ACTION_WRITE:
            {
                return "NPL_TXPP_FWD_QOS_MAPPING_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_txpp_fwd_qos_mapping_table_action_e");
        }
        return "";
    }
    npl_txpp_fwd_qos_mapping_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_txpp_fwd_qos_mapping_table_value_t element);
std::string to_short_string(struct npl_txpp_fwd_qos_mapping_table_value_t element);

/// API-s for table: txpp_ibm_enables_table

typedef enum
{
    NPL_TXPP_IBM_ENABLES_TABLE_ACTION_WRITE = 0x0
} npl_txpp_ibm_enables_table_action_e;

struct npl_txpp_ibm_enables_table_key_t
{
    
    
    npl_txpp_ibm_enables_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_txpp_ibm_enables_table_key_t element);
std::string to_short_string(struct npl_txpp_ibm_enables_table_key_t element);

struct npl_txpp_ibm_enables_table_value_t
{
    npl_txpp_ibm_enables_table_action_e action;
    union npl_txpp_ibm_enables_table_payloads_t {
        npl_ibm_enables_table_result_t ibm_enables_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_txpp_ibm_enables_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_TXPP_IBM_ENABLES_TABLE_ACTION_WRITE:
            {
                return "NPL_TXPP_IBM_ENABLES_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_txpp_ibm_enables_table_action_e");
        }
        return "";
    }
    npl_txpp_ibm_enables_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_txpp_ibm_enables_table_value_t element);
std::string to_short_string(struct npl_txpp_ibm_enables_table_value_t element);

/// API-s for table: txpp_initial_npe_macro_table

typedef enum
{
    NPL_TXPP_INITIAL_NPE_MACRO_TABLE_ACTION_INIT_TX_DATA = 0x0
} npl_txpp_initial_npe_macro_table_action_e;

struct npl_txpp_initial_npe_macro_table_init_tx_data_payload_t
{
    uint64_t np_macro_id : 6;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_txpp_initial_npe_macro_table_init_tx_data_payload_t element);
std::string to_short_string(npl_txpp_initial_npe_macro_table_init_tx_data_payload_t element);

struct npl_txpp_initial_npe_macro_table_key_t
{
    npl_txpp_first_macro_table_key_t txpp_first_macro_table_key;
    
    npl_txpp_initial_npe_macro_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_txpp_initial_npe_macro_table_key_t element);
std::string to_short_string(struct npl_txpp_initial_npe_macro_table_key_t element);

struct npl_txpp_initial_npe_macro_table_value_t
{
    npl_txpp_initial_npe_macro_table_action_e action;
    union npl_txpp_initial_npe_macro_table_payloads_t {
        npl_txpp_initial_npe_macro_table_init_tx_data_payload_t init_tx_data;
    } payloads;
    std::string npl_action_enum_to_string(const npl_txpp_initial_npe_macro_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_TXPP_INITIAL_NPE_MACRO_TABLE_ACTION_INIT_TX_DATA:
            {
                return "NPL_TXPP_INITIAL_NPE_MACRO_TABLE_ACTION_INIT_TX_DATA(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_txpp_initial_npe_macro_table_action_e");
        }
        return "";
    }
    npl_txpp_initial_npe_macro_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_txpp_initial_npe_macro_table_value_t element);
std::string to_short_string(struct npl_txpp_initial_npe_macro_table_value_t element);

/// API-s for table: txpp_mapping_qos_tag_table

typedef enum
{
    NPL_TXPP_MAPPING_QOS_TAG_TABLE_ACTION_WRITE = 0x0
} npl_txpp_mapping_qos_tag_table_action_e;

struct npl_txpp_mapping_qos_tag_table_key_t
{
    uint64_t qos_tag : 7;
    uint64_t qos_id : 4;
    
    npl_txpp_mapping_qos_tag_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_txpp_mapping_qos_tag_table_key_t element);
std::string to_short_string(struct npl_txpp_mapping_qos_tag_table_key_t element);

struct npl_txpp_mapping_qos_tag_table_value_t
{
    npl_txpp_mapping_qos_tag_table_action_e action;
    union npl_txpp_mapping_qos_tag_table_payloads_t {
        npl_egress_qos_result_t egress_qos_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_txpp_mapping_qos_tag_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_TXPP_MAPPING_QOS_TAG_TABLE_ACTION_WRITE:
            {
                return "NPL_TXPP_MAPPING_QOS_TAG_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_txpp_mapping_qos_tag_table_action_e");
        }
        return "";
    }
    npl_txpp_mapping_qos_tag_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_txpp_mapping_qos_tag_table_value_t element);
std::string to_short_string(struct npl_txpp_mapping_qos_tag_table_value_t element);

/// API-s for table: uc_ibm_tc_map_table

typedef enum
{
    NPL_UC_IBM_TC_MAP_TABLE_ACTION_WRITE = 0x0
} npl_uc_ibm_tc_map_table_action_e;

struct npl_uc_ibm_tc_map_table_key_t
{
    uint64_t ibm_cmd_table_result_tc_map_profile : 3;
    uint64_t rxpp_pd_tc : 3;
    
    npl_uc_ibm_tc_map_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_uc_ibm_tc_map_table_key_t element);
std::string to_short_string(struct npl_uc_ibm_tc_map_table_key_t element);

struct npl_uc_ibm_tc_map_table_value_t
{
    npl_uc_ibm_tc_map_table_action_e action;
    union npl_uc_ibm_tc_map_table_payloads_t {
        npl_rxpdr_ibm_tc_map_result_t rxpdr_ibm_tc_map_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_uc_ibm_tc_map_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_UC_IBM_TC_MAP_TABLE_ACTION_WRITE:
            {
                return "NPL_UC_IBM_TC_MAP_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_uc_ibm_tc_map_table_action_e");
        }
        return "";
    }
    npl_uc_ibm_tc_map_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_uc_ibm_tc_map_table_value_t element);
std::string to_short_string(struct npl_uc_ibm_tc_map_table_value_t element);

/// API-s for table: urpf_ipsa_dest_is_lpts_static_table

typedef enum
{
    NPL_URPF_IPSA_DEST_IS_LPTS_STATIC_TABLE_ACTION_WRITE = 0x0
} npl_urpf_ipsa_dest_is_lpts_static_table_action_e;

struct npl_urpf_ipsa_dest_is_lpts_static_table_key_t
{
    uint64_t ipsa_dest_prefix : 5;
    
    npl_urpf_ipsa_dest_is_lpts_static_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_urpf_ipsa_dest_is_lpts_static_table_key_t element);
std::string to_short_string(struct npl_urpf_ipsa_dest_is_lpts_static_table_key_t element);

struct npl_urpf_ipsa_dest_is_lpts_static_table_value_t
{
    npl_urpf_ipsa_dest_is_lpts_static_table_action_e action;
    union npl_urpf_ipsa_dest_is_lpts_static_table_payloads_t {
        uint64_t is_lpts_prefix : 1;
    } payloads;
    std::string npl_action_enum_to_string(const npl_urpf_ipsa_dest_is_lpts_static_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_URPF_IPSA_DEST_IS_LPTS_STATIC_TABLE_ACTION_WRITE:
            {
                return "NPL_URPF_IPSA_DEST_IS_LPTS_STATIC_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_urpf_ipsa_dest_is_lpts_static_table_action_e");
        }
        return "";
    }
    npl_urpf_ipsa_dest_is_lpts_static_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_urpf_ipsa_dest_is_lpts_static_table_value_t element);
std::string to_short_string(struct npl_urpf_ipsa_dest_is_lpts_static_table_value_t element);

/// API-s for table: vlan_edit_tpid1_profile_hw_table

typedef enum
{
    NPL_VLAN_EDIT_TPID1_PROFILE_HW_TABLE_ACTION_WRITE = 0x0
} npl_vlan_edit_tpid1_profile_hw_table_action_e;

struct npl_vlan_edit_tpid1_profile_hw_table_key_t
{
    uint64_t vlan_edit_info_tpid_profile : 2;
    
    npl_vlan_edit_tpid1_profile_hw_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_vlan_edit_tpid1_profile_hw_table_key_t element);
std::string to_short_string(struct npl_vlan_edit_tpid1_profile_hw_table_key_t element);

struct npl_vlan_edit_tpid1_profile_hw_table_value_t
{
    npl_vlan_edit_tpid1_profile_hw_table_action_e action;
    union npl_vlan_edit_tpid1_profile_hw_table_payloads_t {
        uint64_t vlan_edit_info_tpid1 : 16;
    } payloads;
    std::string npl_action_enum_to_string(const npl_vlan_edit_tpid1_profile_hw_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_VLAN_EDIT_TPID1_PROFILE_HW_TABLE_ACTION_WRITE:
            {
                return "NPL_VLAN_EDIT_TPID1_PROFILE_HW_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_vlan_edit_tpid1_profile_hw_table_action_e");
        }
        return "";
    }
    npl_vlan_edit_tpid1_profile_hw_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_vlan_edit_tpid1_profile_hw_table_value_t element);
std::string to_short_string(struct npl_vlan_edit_tpid1_profile_hw_table_value_t element);

/// API-s for table: vlan_edit_tpid2_profile_hw_table

typedef enum
{
    NPL_VLAN_EDIT_TPID2_PROFILE_HW_TABLE_ACTION_WRITE = 0x0
} npl_vlan_edit_tpid2_profile_hw_table_action_e;

struct npl_vlan_edit_tpid2_profile_hw_table_key_t
{
    uint64_t vlan_edit_info_tpid_profile : 2;
    
    npl_vlan_edit_tpid2_profile_hw_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_vlan_edit_tpid2_profile_hw_table_key_t element);
std::string to_short_string(struct npl_vlan_edit_tpid2_profile_hw_table_key_t element);

struct npl_vlan_edit_tpid2_profile_hw_table_value_t
{
    npl_vlan_edit_tpid2_profile_hw_table_action_e action;
    union npl_vlan_edit_tpid2_profile_hw_table_payloads_t {
        uint64_t vlan_edit_info_tpid2 : 16;
    } payloads;
    std::string npl_action_enum_to_string(const npl_vlan_edit_tpid2_profile_hw_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_VLAN_EDIT_TPID2_PROFILE_HW_TABLE_ACTION_WRITE:
            {
                return "NPL_VLAN_EDIT_TPID2_PROFILE_HW_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_vlan_edit_tpid2_profile_hw_table_action_e");
        }
        return "";
    }
    npl_vlan_edit_tpid2_profile_hw_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_vlan_edit_tpid2_profile_hw_table_value_t element);
std::string to_short_string(struct npl_vlan_edit_tpid2_profile_hw_table_value_t element);

/// API-s for table: vlan_format_table

typedef enum
{
    NPL_VLAN_FORMAT_TABLE_ACTION_UPDATE = 0x0
} npl_vlan_format_table_action_e;

struct npl_vlan_format_table_update_payload_t
{
    uint64_t vid_from_port : 1;
    npl_mac_termination_type_e mac_termination_type;
    npl_service_mapping_selector_e sm_selector;
    npl_service_mapping_logical_db_e sm_logical_db;
    uint64_t pcp_dei_from_port : 1;
    uint64_t dummy_bit : 1;
    uint64_t enable_l3_qos : 1;
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(npl_vlan_format_table_update_payload_t element);
std::string to_short_string(npl_vlan_format_table_update_payload_t element);

struct npl_vlan_format_table_key_t
{
    uint64_t vlan_profile : 4;
    npl_protocol_type_e header_1_type;
    npl_protocol_type_e header_2_type;
    uint64_t is_priority : 1;
    
    npl_vlan_format_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_vlan_format_table_key_t element);
std::string to_short_string(struct npl_vlan_format_table_key_t element);

struct npl_vlan_format_table_value_t
{
    npl_vlan_format_table_action_e action;
    union npl_vlan_format_table_payloads_t {
        npl_vlan_format_table_update_payload_t update;
    } payloads;
    std::string npl_action_enum_to_string(const npl_vlan_format_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_VLAN_FORMAT_TABLE_ACTION_UPDATE:
            {
                return "NPL_VLAN_FORMAT_TABLE_ACTION_UPDATE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_vlan_format_table_action_e");
        }
        return "";
    }
    npl_vlan_format_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_vlan_format_table_value_t element);
std::string to_short_string(struct npl_vlan_format_table_value_t element);

/// API-s for table: vni_table

typedef enum
{
    NPL_VNI_TABLE_ACTION_WRITE = 0x0
} npl_vni_table_action_e;

struct npl_vni_table_key_t
{
    uint64_t vni : 24;
    
    npl_vni_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_vni_table_key_t element);
std::string to_short_string(struct npl_vni_table_key_t element);

struct npl_vni_table_value_t
{
    npl_vni_table_action_e action;
    union npl_vni_table_payloads_t {
        npl_vni_table_result_t vni_table_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_vni_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_VNI_TABLE_ACTION_WRITE:
            {
                return "NPL_VNI_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_vni_table_action_e");
        }
        return "";
    }
    npl_vni_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_vni_table_value_t element);
std::string to_short_string(struct npl_vni_table_value_t element);

/// API-s for table: voq_cgm_slice_buffers_consumption_lut_for_enq_table

typedef enum
{
    NPL_VOQ_CGM_SLICE_BUFFERS_CONSUMPTION_LUT_FOR_ENQ_TABLE_ACTION_WRITE = 0x0
} npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_action_e;

struct npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_key_t
{
    npl_voq_profile_len profile_id;
    uint64_t free_dram_cntx : 1;
    uint64_t buffer_pool_available_level : 2;
    uint64_t buffer_voq_size_level : 3;
    
    npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_key_t element);
std::string to_short_string(struct npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_key_t element);

struct npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_value_t
{
    npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_action_e action;
    union npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_payloads_t {
        npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t voq_cgm_slice_buffers_consumption_lut_for_enq_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_VOQ_CGM_SLICE_BUFFERS_CONSUMPTION_LUT_FOR_ENQ_TABLE_ACTION_WRITE:
            {
                return "NPL_VOQ_CGM_SLICE_BUFFERS_CONSUMPTION_LUT_FOR_ENQ_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_action_e");
        }
        return "";
    }
    npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_value_t element);
std::string to_short_string(struct npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_value_t element);

/// API-s for table: voq_cgm_slice_dram_cgm_profile_table

typedef enum
{
    NPL_VOQ_CGM_SLICE_DRAM_CGM_PROFILE_TABLE_ACTION_WRITE = 0x0
} npl_voq_cgm_slice_dram_cgm_profile_table_action_e;

struct npl_voq_cgm_slice_dram_cgm_profile_table_key_t
{
    npl_voq_profile_len profile_id;
    
    npl_voq_cgm_slice_dram_cgm_profile_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_voq_cgm_slice_dram_cgm_profile_table_key_t element);
std::string to_short_string(struct npl_voq_cgm_slice_dram_cgm_profile_table_key_t element);

struct npl_voq_cgm_slice_dram_cgm_profile_table_value_t
{
    npl_voq_cgm_slice_dram_cgm_profile_table_action_e action;
    union npl_voq_cgm_slice_dram_cgm_profile_table_payloads_t {
        npl_voq_cgm_slice_dram_cgm_profile_results_t voq_cgm_slice_dram_cgm_profile_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_voq_cgm_slice_dram_cgm_profile_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_VOQ_CGM_SLICE_DRAM_CGM_PROFILE_TABLE_ACTION_WRITE:
            {
                return "NPL_VOQ_CGM_SLICE_DRAM_CGM_PROFILE_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_voq_cgm_slice_dram_cgm_profile_table_action_e");
        }
        return "";
    }
    npl_voq_cgm_slice_dram_cgm_profile_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_voq_cgm_slice_dram_cgm_profile_table_value_t element);
std::string to_short_string(struct npl_voq_cgm_slice_dram_cgm_profile_table_value_t element);

/// API-s for table: voq_cgm_slice_pd_consumption_lut_for_enq_table

typedef enum
{
    NPL_VOQ_CGM_SLICE_PD_CONSUMPTION_LUT_FOR_ENQ_TABLE_ACTION_WRITE = 0x0
} npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_action_e;

struct npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_key_t
{
    npl_voq_profile_len profile_id;
    uint64_t pd_pool_available_level : 2;
    uint64_t pd_voq_fill_level : 3;
    
    npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_key_t element);
std::string to_short_string(struct npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_key_t element);

struct npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_value_t
{
    npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_action_e action;
    union npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_payloads_t {
        npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t voq_cgm_slice_pd_consumption_lut_for_enq_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_VOQ_CGM_SLICE_PD_CONSUMPTION_LUT_FOR_ENQ_TABLE_ACTION_WRITE:
            {
                return "NPL_VOQ_CGM_SLICE_PD_CONSUMPTION_LUT_FOR_ENQ_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_action_e");
        }
        return "";
    }
    npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_value_t element);
std::string to_short_string(struct npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_value_t element);

/// API-s for table: voq_cgm_slice_profile_buff_region_thresholds_table

typedef enum
{
    NPL_VOQ_CGM_SLICE_PROFILE_BUFF_REGION_THRESHOLDS_TABLE_ACTION_WRITE = 0x0
} npl_voq_cgm_slice_profile_buff_region_thresholds_table_action_e;

struct npl_voq_cgm_slice_profile_buff_region_thresholds_table_key_t
{
    npl_voq_profile_len profile_id;
    
    npl_voq_cgm_slice_profile_buff_region_thresholds_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_voq_cgm_slice_profile_buff_region_thresholds_table_key_t element);
std::string to_short_string(struct npl_voq_cgm_slice_profile_buff_region_thresholds_table_key_t element);

struct npl_voq_cgm_slice_profile_buff_region_thresholds_table_value_t
{
    npl_voq_cgm_slice_profile_buff_region_thresholds_table_action_e action;
    union npl_voq_cgm_slice_profile_buff_region_thresholds_table_payloads_t {
        npl_voq_cgm_slice_profile_buff_region_thresholds_results_t voq_cgm_slice_profile_buff_region_thresholds_results;
    } payloads;
    std::string npl_action_enum_to_string(const npl_voq_cgm_slice_profile_buff_region_thresholds_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_VOQ_CGM_SLICE_PROFILE_BUFF_REGION_THRESHOLDS_TABLE_ACTION_WRITE:
            {
                return "NPL_VOQ_CGM_SLICE_PROFILE_BUFF_REGION_THRESHOLDS_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_voq_cgm_slice_profile_buff_region_thresholds_table_action_e");
        }
        return "";
    }
    npl_voq_cgm_slice_profile_buff_region_thresholds_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_voq_cgm_slice_profile_buff_region_thresholds_table_value_t element);
std::string to_short_string(struct npl_voq_cgm_slice_profile_buff_region_thresholds_table_value_t element);

/// API-s for table: voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table

typedef enum
{
    NPL_VOQ_CGM_SLICE_PROFILE_PKT_ENQ_TIME_REGION_THRESHOLDS_TABLE_ACTION_WRITE = 0x0
} npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_action_e;

struct npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_key_t
{
    npl_voq_profile_len profile_id;
    
    npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_key_t element);
std::string to_short_string(struct npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_key_t element);

struct npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_value_t
{
    npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_action_e action;
    union npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_payloads_t {
        npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_results_t voq_cgm_slice_profile_pkt_enq_time_region_thresholds_results;
    } payloads;
    std::string npl_action_enum_to_string(const npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_VOQ_CGM_SLICE_PROFILE_PKT_ENQ_TIME_REGION_THRESHOLDS_TABLE_ACTION_WRITE:
            {
                return "NPL_VOQ_CGM_SLICE_PROFILE_PKT_ENQ_TIME_REGION_THRESHOLDS_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_action_e");
        }
        return "";
    }
    npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_value_t element);
std::string to_short_string(struct npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_value_t element);

/// API-s for table: voq_cgm_slice_profile_pkt_region_thresholds_table

typedef enum
{
    NPL_VOQ_CGM_SLICE_PROFILE_PKT_REGION_THRESHOLDS_TABLE_ACTION_WRITE = 0x0
} npl_voq_cgm_slice_profile_pkt_region_thresholds_table_action_e;

struct npl_voq_cgm_slice_profile_pkt_region_thresholds_table_key_t
{
    npl_voq_profile_len profile_id;
    
    npl_voq_cgm_slice_profile_pkt_region_thresholds_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_voq_cgm_slice_profile_pkt_region_thresholds_table_key_t element);
std::string to_short_string(struct npl_voq_cgm_slice_profile_pkt_region_thresholds_table_key_t element);

struct npl_voq_cgm_slice_profile_pkt_region_thresholds_table_value_t
{
    npl_voq_cgm_slice_profile_pkt_region_thresholds_table_action_e action;
    union npl_voq_cgm_slice_profile_pkt_region_thresholds_table_payloads_t {
        npl_voq_cgm_slice_profile_pkt_region_thresholds_results_t voq_cgm_slice_profile_pkt_region_thresholds_results;
    } payloads;
    std::string npl_action_enum_to_string(const npl_voq_cgm_slice_profile_pkt_region_thresholds_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_VOQ_CGM_SLICE_PROFILE_PKT_REGION_THRESHOLDS_TABLE_ACTION_WRITE:
            {
                return "NPL_VOQ_CGM_SLICE_PROFILE_PKT_REGION_THRESHOLDS_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_voq_cgm_slice_profile_pkt_region_thresholds_table_action_e");
        }
        return "";
    }
    npl_voq_cgm_slice_profile_pkt_region_thresholds_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_voq_cgm_slice_profile_pkt_region_thresholds_table_value_t element);
std::string to_short_string(struct npl_voq_cgm_slice_profile_pkt_region_thresholds_table_value_t element);

/// API-s for table: voq_cgm_slice_slice_cgm_profile_table

typedef enum
{
    NPL_VOQ_CGM_SLICE_SLICE_CGM_PROFILE_TABLE_ACTION_WRITE = 0x0
} npl_voq_cgm_slice_slice_cgm_profile_table_action_e;

struct npl_voq_cgm_slice_slice_cgm_profile_table_key_t
{
    npl_voq_profile_len profile_id;
    
    npl_voq_cgm_slice_slice_cgm_profile_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_voq_cgm_slice_slice_cgm_profile_table_key_t element);
std::string to_short_string(struct npl_voq_cgm_slice_slice_cgm_profile_table_key_t element);

struct npl_voq_cgm_slice_slice_cgm_profile_table_value_t
{
    npl_voq_cgm_slice_slice_cgm_profile_table_action_e action;
    union npl_voq_cgm_slice_slice_cgm_profile_table_payloads_t {
        npl_voq_cgm_slice_slice_cgm_profile_result_t voq_cgm_slice_slice_cgm_profile_result;
    } payloads;
    std::string npl_action_enum_to_string(const npl_voq_cgm_slice_slice_cgm_profile_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_VOQ_CGM_SLICE_SLICE_CGM_PROFILE_TABLE_ACTION_WRITE:
            {
                return "NPL_VOQ_CGM_SLICE_SLICE_CGM_PROFILE_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_voq_cgm_slice_slice_cgm_profile_table_action_e");
        }
        return "";
    }
    npl_voq_cgm_slice_slice_cgm_profile_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_voq_cgm_slice_slice_cgm_profile_table_value_t element);
std::string to_short_string(struct npl_voq_cgm_slice_slice_cgm_profile_table_value_t element);

/// API-s for table: vsid_table

typedef enum
{
    NPL_VSID_TABLE_ACTION_WRITE = 0x0
} npl_vsid_table_action_e;

struct npl_vsid_table_key_t
{
    uint64_t vsid : 24;
    
    npl_vsid_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_vsid_table_key_t element);
std::string to_short_string(struct npl_vsid_table_key_t element);

struct npl_vsid_table_value_t
{
    npl_vsid_table_action_e action;
    union npl_vsid_table_payloads_t {
        uint64_t l2_relay_attributes_id : 14;
    } payloads;
    std::string npl_action_enum_to_string(const npl_vsid_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_VSID_TABLE_ACTION_WRITE:
            {
                return "NPL_VSID_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_vsid_table_action_e");
        }
        return "";
    }
    npl_vsid_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_vsid_table_value_t element);
std::string to_short_string(struct npl_vsid_table_value_t element);

/// API-s for table: vxlan_l2_dlp_table

typedef enum
{
    NPL_VXLAN_L2_DLP_TABLE_ACTION_WRITE = 0x0
} npl_vxlan_l2_dlp_table_action_e;

struct npl_vxlan_l2_dlp_table_key_t
{
    uint64_t l2_dlp_id_key_id : 18;
    
    npl_vxlan_l2_dlp_table_key_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t bv);
    field_structure to_field_structure() const;
};
std::string to_string(struct npl_vxlan_l2_dlp_table_key_t element);
std::string to_short_string(struct npl_vxlan_l2_dlp_table_key_t element);

struct npl_vxlan_l2_dlp_table_value_t
{
    npl_vxlan_l2_dlp_table_action_e action;
    union npl_vxlan_l2_dlp_table_payloads_t {
        npl_vxlan_dlp_specific_t vxlan_tunnel_attributes;
    } payloads;
    std::string npl_action_enum_to_string(const npl_vxlan_l2_dlp_table_action_e enum_instance) const
    {
        switch(enum_instance) {
            case NPL_VXLAN_L2_DLP_TABLE_ACTION_WRITE:
            {
                return "NPL_VXLAN_L2_DLP_TABLE_ACTION_WRITE(0x0)";
                break;
            }
            
            default:
            return std::string("UNKNOWN") + std::string("_npl_vxlan_l2_dlp_table_action_e");
        }
        return "";
    }
    npl_vxlan_l2_dlp_table_value_t()
    {
        memset(this, 0, sizeof(*this));
    }
    
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t bv);
    field_structure to_field_structure(void) const;
};
std::string to_string(struct npl_vxlan_l2_dlp_table_value_t element);
std::string to_short_string(struct npl_vxlan_l2_dlp_table_value_t element);

#pragma pack(pop)

#endif
