// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "sai_hostif.h"

#include <fcntl.h>
#include <linux/if_vlan.h>
#include <linux/if_tun.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "api/system/la_pci_port.h"
#include "api/system/la_punt_inject_port.h"
#include "sai_device.h"
#include "sai_logger.h"
#include "sai_utils.h"

namespace silicon_one
{
namespace sai
{

using namespace std;

sai_status_t hostif_trap_attr_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

sai_status_t hostif_trap_attr_get(_In_ const sai_object_key_t* key,
                                  _Inout_ sai_attribute_value_t* value,
                                  _In_ uint32_t attr_index,
                                  _Inout_ vendor_cache_t* cache,
                                  void* arg);

sai_status_t hostif_trap_group_attr_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

sai_status_t hostif_trap_group_attr_get(_In_ const sai_object_key_t* key,
                                        _Inout_ sai_attribute_value_t* value,
                                        _In_ uint32_t attr_index,
                                        _Inout_ vendor_cache_t* cache,
                                        void* arg);

sai_status_t hostif_attr_get(_In_ const sai_object_key_t* key,
                             _Inout_ sai_attribute_value_t* value,
                             _In_ uint32_t attr_index,
                             _Inout_ vendor_cache_t* cache,
                             void* arg);
sai_status_t hostif_attr_oper_status_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);
sai_status_t hostif_attr_queue_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);
sai_status_t hostif_attr_vlan_tag_mode_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

sai_status_t hostif_table_entry_attr_get(_In_ const sai_object_key_t* key,
                                         _Inout_ sai_attribute_value_t* value,
                                         _In_ uint32_t attr_index,
                                         _Inout_ vendor_cache_t* cache,
                                         void* arg);

// clang-format off
extern const sai_attribute_entry_t hostif_trap_attribs[] = {
    // id, mandatory_on_create, valid_for_create, valid_for_set, valid_for_get, name
    {SAI_HOSTIF_TRAP_ATTR_TRAP_TYPE, true, true, false, true, "Trap type", SAI_ATTR_VAL_TYPE_U32},
    {SAI_HOSTIF_TRAP_ATTR_PACKET_ACTION, true, true, true, true, "Trap Packet Action", SAI_ATTR_VAL_TYPE_U32},
    {SAI_HOSTIF_TRAP_ATTR_TRAP_PRIORITY, false, true, true, true, "Trap Priority", SAI_ATTR_VAL_TYPE_U32},
    {SAI_HOSTIF_TRAP_ATTR_TRAP_GROUP, false, true, true, true, "Trap Group", SAI_ATTR_VAL_TYPE_OID},
    {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}};

static const sai_vendor_attribute_entry_t hostif_trap_vendor_attribs[] = {
    /*
     id,
     {create, remove, set, get}, // implemented
     {create, remove, set, get}, // supported
     getter, getter_arg,
     setter, setter_arg
     */
    {SAI_HOSTIF_TRAP_ATTR_TRAP_TYPE,
     {true, false, false, true},
     {true, false, false, true},
     hostif_trap_attr_get, (void*)SAI_HOSTIF_TRAP_ATTR_TRAP_TYPE, hostif_trap_attr_set, (void*)SAI_HOSTIF_TRAP_ATTR_TRAP_TYPE},

    {SAI_HOSTIF_TRAP_ATTR_PACKET_ACTION,
     {true, false, true, true},
     {true, false, true, true},
     hostif_trap_attr_get, (void*)SAI_HOSTIF_TRAP_ATTR_PACKET_ACTION, hostif_trap_attr_set, (void*)SAI_HOSTIF_TRAP_ATTR_PACKET_ACTION},

    {SAI_HOSTIF_TRAP_ATTR_TRAP_PRIORITY,
     {true, false, true, true},
     {true, false, true, true},
     hostif_trap_attr_get, (void*)SAI_HOSTIF_TRAP_ATTR_TRAP_PRIORITY, hostif_trap_attr_set, (void*)SAI_HOSTIF_TRAP_ATTR_TRAP_PRIORITY},

    {SAI_HOSTIF_TRAP_ATTR_TRAP_GROUP,
     {true, false, true, true},
     {true, false, true, true},
     hostif_trap_attr_get, (void*)SAI_HOSTIF_TRAP_ATTR_TRAP_GROUP, hostif_trap_attr_set, (void*)SAI_HOSTIF_TRAP_ATTR_TRAP_GROUP}
};

extern const sai_attribute_entry_t hostif_trap_group_attribs[] = {
    // id, mandatory_on_create, valid_for_create, valid_for_set, valid_for_get, name
    {SAI_HOSTIF_TRAP_GROUP_ATTR_ADMIN_STATE, false, true, true, true, "Trap Group Admin State", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_HOSTIF_TRAP_GROUP_ATTR_QUEUE, false, true, true, true, "Trap Group Queue", SAI_ATTR_VAL_TYPE_U32},
    {SAI_HOSTIF_TRAP_GROUP_ATTR_POLICER, false, true, true, true, "Trap Group Policer", SAI_ATTR_VAL_TYPE_OID},
    {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}};

static const sai_vendor_attribute_entry_t hostif_trap_group_vendor_attribs[] = {
    /*
       id,
       {create, remove, set, get}, // implemented
       {create, remove, set, get}, // supported
       getter, getter_arg,
       setter, setter_arg
    */
    {SAI_HOSTIF_TRAP_GROUP_ATTR_ADMIN_STATE,
     {true, true, true, true},
     {true, true, true, true},
     hostif_trap_group_attr_get, (void*)SAI_HOSTIF_TRAP_GROUP_ATTR_ADMIN_STATE, hostif_trap_group_attr_set, (void*)SAI_HOSTIF_TRAP_GROUP_ATTR_ADMIN_STATE},

    {SAI_HOSTIF_TRAP_GROUP_ATTR_QUEUE,
     {true, true, true, true},
     {true, true, true, true},
     hostif_trap_group_attr_get, (void*)SAI_HOSTIF_TRAP_GROUP_ATTR_QUEUE, hostif_trap_group_attr_set, (void*)SAI_HOSTIF_TRAP_GROUP_ATTR_QUEUE},

    {SAI_HOSTIF_TRAP_GROUP_ATTR_POLICER,
     {true, true, true, true},
     {true, true, true, true},
     hostif_trap_group_attr_get, (void*)SAI_HOSTIF_TRAP_GROUP_ATTR_POLICER, hostif_trap_group_attr_set, (void*)SAI_HOSTIF_TRAP_GROUP_ATTR_POLICER}
};

extern const sai_attribute_entry_t hostif_attribs[] = {
    // id, mandatory_on_create, valid_for_create, valid_for_set, valid_for_get, name
    {SAI_HOSTIF_ATTR_OPER_STATUS, false, false, true, true, "HOSTIF Oper status", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_HOSTIF_ATTR_TYPE, true, true, false, true, "Host interface type", SAI_ATTR_VAL_TYPE_S32 },
    {SAI_HOSTIF_ATTR_OBJ_ID, false, true, false, true, "Host interface port/lag/vlan Object ID", SAI_ATTR_VAL_TYPE_OID },
    {SAI_HOSTIF_ATTR_NAME, true, true, false, true, "Host interface name", SAI_ATTR_VAL_TYPE_CHARDATA },
    {SAI_HOSTIF_ATTR_QUEUE, false, false, true, true, "HOSTIF Oper status", SAI_ATTR_VAL_TYPE_U32},
    {SAI_HOSTIF_ATTR_VLAN_TAG, false, false, true, true, "HOSTIF Oper status", SAI_ATTR_VAL_TYPE_S32},
    {SAI_HOSTIF_ATTR_GENETLINK_MCGRP_NAME, false, true, false, true, "GETNETLINK multicast group name", SAI_ATTR_VAL_TYPE_CHARDATA },
    {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}};

static const sai_vendor_attribute_entry_t hostif_vendor_attribs[] = {
    /*
     id,
     {create, remove, set, get}, // implemented
     {create, remove, set, get}, // supported
     getter, getter_arg,
     setter, setter_arg
     */
    {SAI_HOSTIF_ATTR_OPER_STATUS,
     {false, false, true, true},
     {false, false, true, true},
     hostif_attr_get, (void*)SAI_HOSTIF_ATTR_OPER_STATUS, hostif_attr_oper_status_set, nullptr},

    {SAI_HOSTIF_ATTR_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      hostif_attr_get, (void*)SAI_HOSTIF_ATTR_TYPE,
      nullptr, nullptr },

    {SAI_HOSTIF_ATTR_OBJ_ID,
      { true, false, false, true },
      { true, false, false, true },
      hostif_attr_get, (void*)SAI_HOSTIF_ATTR_OBJ_ID,
      nullptr, nullptr },

    {SAI_HOSTIF_ATTR_NAME,
      { true, false, true, true },
      { true, false, true, true },
      hostif_attr_get, (void*)SAI_HOSTIF_ATTR_NAME,
      nullptr, nullptr },

    {SAI_HOSTIF_ATTR_QUEUE,
     {false, false, true, true},
     {false, false, true, true},
     hostif_attr_get, (void*)SAI_HOSTIF_ATTR_QUEUE, hostif_attr_queue_set, nullptr},

    {SAI_HOSTIF_ATTR_VLAN_TAG,
     {false, false, true, true},
     {false, false, true, true},
     hostif_attr_get, (void*)SAI_HOSTIF_ATTR_VLAN_TAG, hostif_attr_vlan_tag_mode_set, nullptr},

    {SAI_HOSTIF_ATTR_GENETLINK_MCGRP_NAME,
      { true, false, false, true },
      { true, false, false, true },
      hostif_attr_get, (void*)SAI_HOSTIF_ATTR_GENETLINK_MCGRP_NAME,
      nullptr, nullptr },

    {END_FUNCTIONALITY_ATTRIBS_ID, {false, false, false, false}, {"", SAI_ATTR_VAL_TYPE_UNDETERMINED}}};

extern const sai_attribute_entry_t hostif_table_entry_attribs[] = {
   // id, mandatory_on_create, valid_for_create, valid_for_set, valid_for_get, name
   {SAI_HOSTIF_TABLE_ENTRY_ATTR_TYPE , true, true, false, true, "Host interface table entry type", SAI_ATTR_VAL_TYPE_S32 },
   {SAI_HOSTIF_TABLE_ENTRY_ATTR_OBJ_ID, true, true, false, true, "Host interface table entry port/lag/vlan Object ID", SAI_ATTR_VAL_TYPE_OID },
   {SAI_HOSTIF_TABLE_ENTRY_ATTR_TRAP_ID, true, true, false, true, "Host interface table entry trap ID", SAI_ATTR_VAL_TYPE_OID },
   {SAI_HOSTIF_TABLE_ENTRY_ATTR_CHANNEL_TYPE, true, true, false, true, "Host interface table entry action channel type", SAI_ATTR_VAL_TYPE_S32 },
   {SAI_HOSTIF_TABLE_ENTRY_ATTR_HOST_IF, false, true, false, true, "Host interface oid", SAI_ATTR_VAL_TYPE_OID },
   {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}};

static const sai_vendor_attribute_entry_t hostif_table_entry_vendor_attribs[] = {
   /*
    id,
    {create, remove, set, get}, // implemented
    {create, remove, set, get}, // supported
    getter, getter_arg,
    setter, setter_arg
    */
   {SAI_HOSTIF_TABLE_ENTRY_ATTR_TYPE,
    {true, true, false, true},
    {true, true, false, true},
    hostif_table_entry_attr_get, (void*)SAI_HOSTIF_TABLE_ENTRY_ATTR_TYPE, nullptr, nullptr},

   {SAI_HOSTIF_TABLE_ENTRY_ATTR_OBJ_ID,
     { true, true, false, true },
     { true, true, false, true },
     hostif_table_entry_attr_get, (void*)SAI_HOSTIF_TABLE_ENTRY_ATTR_OBJ_ID,
     nullptr, nullptr },

   {SAI_HOSTIF_TABLE_ENTRY_ATTR_TRAP_ID,
     { true, false, false, true },
     { true, false, false, true },
     hostif_table_entry_attr_get, (void*)SAI_HOSTIF_TABLE_ENTRY_ATTR_TRAP_ID,
     nullptr, nullptr },

   {SAI_HOSTIF_TABLE_ENTRY_ATTR_CHANNEL_TYPE,
     { true, false, true, true },
     { true, false, true, true },
     hostif_table_entry_attr_get, (void*)SAI_HOSTIF_TABLE_ENTRY_ATTR_CHANNEL_TYPE,
     nullptr, nullptr },
   {SAI_HOSTIF_TABLE_ENTRY_ATTR_HOST_IF,
     { true, false, false, true },
     { true, false, false, true },
     hostif_table_entry_attr_get, (void*)SAI_HOSTIF_TABLE_ENTRY_ATTR_HOST_IF,
     nullptr, nullptr },
};

// clang-format on

sai_status_t
hostif_trap_attr_get(_In_ const sai_object_key_t* key,
                     _Inout_ sai_attribute_value_t* value,
                     _In_ uint32_t attr_index,
                     _Inout_ vendor_cache_t* cache,
                     void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_trap(key->key.object_id);
    auto sdev = la_trap.get_device();
    if (sdev == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    la_status status = LA_STATUS_SUCCESS;
    auto trap_type = (sai_hostif_trap_type_t)la_trap.index;

    int32_t attr_id = (uintptr_t)arg;
    if (attr_id == SAI_HOSTIF_TRAP_ATTR_TRAP_TYPE) {
        set_attr_value(SAI_HOSTIF_TRAP_ATTR_TRAP_TYPE, *value, trap_type);
        return SAI_STATUS_SUCCESS;
    }

    switch (attr_id) {
    case SAI_HOSTIF_TRAP_ATTR_PACKET_ACTION: {
        sai_packet_action_t pkt_action{};
        status = sdev->m_trap_manager->get_trap_action(trap_type, pkt_action);
        set_attr_value(SAI_HOSTIF_TRAP_ATTR_PACKET_ACTION, *value, pkt_action);
        break;
    }
    case SAI_HOSTIF_TRAP_ATTR_TRAP_PRIORITY: {
        la_uint_t priority = 0;
        status = sdev->m_trap_manager->get_trap_priority(trap_type, priority);
        set_attr_value(SAI_HOSTIF_TRAP_ATTR_TRAP_PRIORITY, *value, priority);
        break;
    }
    case SAI_HOSTIF_TRAP_ATTR_TRAP_GROUP: {
        sai_object_id_t group = SAI_NULL_OBJECT_ID;
        status = sdev->m_trap_manager->get_trap_group(trap_type, group);
        set_attr_value(SAI_HOSTIF_TRAP_ATTR_TRAP_GROUP, *value, group);
        break;
    }
    default:
        break;
    }

    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
hostif_trap_attr_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    int32_t attr_id = (uintptr_t)arg;

    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    la_status status = LA_STATUS_SUCCESS;
    lsai_object la_trap(key->key.object_id);
    auto sdev = la_trap.get_device();
    auto trap_type = (sai_hostif_trap_type_t)la_trap.index;

    switch (attr_id) {
    case SAI_HOSTIF_TRAP_ATTR_PACKET_ACTION: {
        auto action = get_attr_value(SAI_HOSTIF_TRAP_ATTR_PACKET_ACTION, *value);
        status = sdev->m_trap_manager->update_trap_action(trap_type, action);
        break;
    }
    case SAI_HOSTIF_TRAP_ATTR_TRAP_PRIORITY: {
        auto priority = get_attr_value(SAI_HOSTIF_TRAP_ATTR_TRAP_PRIORITY, *value);
        status = sdev->m_trap_manager->update_trap_priority(trap_type, priority);
        break;
    }
    case SAI_HOSTIF_TRAP_ATTR_TRAP_GROUP: {
        auto group = get_attr_value(SAI_HOSTIF_TRAP_ATTR_TRAP_GROUP, *value);
        status = sdev->m_trap_manager->update_trap_group(trap_type, group);
        break;
    }
    default:
        break;
    }

    sai_return_on_la_error(status);
    return (SAI_STATUS_SUCCESS);
}

sai_status_t
hostif_trap_group_attr_get(_In_ const sai_object_key_t* key,
                           _Inout_ sai_attribute_value_t* value,
                           _In_ uint32_t attr_index,
                           _Inout_ vendor_cache_t* cache,
                           void* arg)
{
    int32_t attr_id = (uintptr_t)arg;

    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    la_status status = LA_STATUS_SUCCESS;
    lsai_object la_trap_group(key->key.object_id);
    auto sdev = la_trap_group.get_device();
    if (sdev == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch (attr_id) {
    case SAI_HOSTIF_TRAP_GROUP_ATTR_ADMIN_STATE: {
        bool admin_state = false;
        status = sdev->m_trap_manager->get_trap_group_admin_state(la_trap_group.index, admin_state);
        set_attr_value(SAI_HOSTIF_TRAP_GROUP_ATTR_ADMIN_STATE, *value, admin_state);
        break;
    }
    case SAI_HOSTIF_TRAP_GROUP_ATTR_QUEUE: {
        la_uint_t queue_index = 0;
        status = sdev->m_trap_manager->get_trap_group_queue(la_trap_group.index, queue_index);
        set_attr_value(SAI_HOSTIF_TRAP_GROUP_ATTR_QUEUE, *value, queue_index);
        break;
    }
    case SAI_HOSTIF_TRAP_GROUP_ATTR_POLICER: {
        sai_object_id_t policer_id;
        status = sdev->m_trap_manager->get_trap_group_policer(la_trap_group.index, policer_id);
        set_attr_value(SAI_HOSTIF_TRAP_GROUP_ATTR_POLICER, *value, policer_id);
        break;
    }
    default:
        break;
    }

    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
hostif_trap_group_attr_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    int32_t attr_id = (uintptr_t)arg;

    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    la_status status = LA_STATUS_SUCCESS;
    lsai_object la_trap_group(key->key.object_id);
    auto sdev = la_trap_group.get_device();
    if (sdev == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch (attr_id) {
    case SAI_HOSTIF_TRAP_GROUP_ATTR_ADMIN_STATE: {
        auto admin_state = get_attr_value(SAI_HOSTIF_TRAP_GROUP_ATTR_ADMIN_STATE, *value);
        status = sdev->m_trap_manager->set_trap_group_admin_state(la_trap_group.index, admin_state);
        break;
    }
    case SAI_HOSTIF_TRAP_GROUP_ATTR_QUEUE: {
        auto queue_index = get_attr_value(SAI_HOSTIF_TRAP_GROUP_ATTR_QUEUE, *value);
        status = sdev->m_trap_manager->set_trap_group_queue(la_trap_group.index, queue_index);
        break;
    }
    case SAI_HOSTIF_TRAP_GROUP_ATTR_POLICER: {
        auto policer = get_attr_value(SAI_HOSTIF_TRAP_GROUP_ATTR_POLICER, *value);
        status = sdev->m_trap_manager->set_trap_group_policer(la_trap_group.index, policer);
        break;
    }
    default:
        break;
    }

    sai_return_on_la_error(status);
    return (SAI_STATUS_SUCCESS);
}

int
sai_hostif::create_tap_device(const std::string& ifname)
{
    ifreq ifr{};

    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    const int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        sai_log_error(SAI_API_HOSTIF, "Failed to open /dev/net/tun");
        return -1;
    }

    int rc = ioctl(fd, TUNSETIFF, &ifr);
    if (rc < 0) {
        sai_log_error(SAI_API_HOSTIF, "Failed TUNSETIFF for tap ifname %s, rc %d", ifname.c_str(), rc);
        close(fd);
        return -1;
    }

    return fd;
}

sai_status_t
sai_hostif::set_dev_mac_address(const std::string& ifname, const sai_mac_t& mac)
{
    ifreq ifr{};
    strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    memcpy(ifr.ifr_hwaddr.sa_data, mac, sizeof(sai_mac_t));

    const int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        sai_log_error(SAI_API_HOSTIF, "Failed to create socket, rc %d", fd);
        return SAI_STATUS_FAILURE;
    }

    int rc = ioctl(fd, SIOCSIFHWADDR, &ifr);
    if (rc < 0) {
        sai_log_error(SAI_API_HOSTIF, "Failed to configure mac addr for hostif %s, rc %d", ifname.c_str(), rc);
        close(fd);
        return SAI_STATUS_FAILURE;
    }

    close(fd);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_hostif::create_netdev(lsai_hostif& hostif)
{
    // Certain NOS state machines moves to all port init done state only after netdev
    // create RTM_NEWLINK is delievered to it. Delete and re-create netdev if previously
    // they were created as persistant netdev. Since we are not creating persistant
    // netdevs, there is no need to delete and re-create.

    const int fd = create_tap_device(hostif.ifname);
    if (fd < 0) {
        return SAI_STATUS_FAILURE;
    }

    sai_status_t status = set_dev_mac_address(hostif.ifname, m_sdev->m_default_switch_mac);
    if (status != SAI_STATUS_SUCCESS) {
        close(fd);
        return status;
    }

    // netdev_fd is used to hand over packet to netdev-intf
    // in inject rx path.
    hostif.netdev_fd = fd;
    status = m_sdev->switchport_hostif_socket_fd_set(hostif, fd);
    sai_return_on_error(status);

    // resolve host interface index
    auto ifindex = if_nametoindex(hostif.ifname.c_str());
    m_sdev->m_port_hostif_index_map.emplace(hostif.port_lag_id, ifindex);

    // start thread to listen pkts from hostif and inject up into pipeline
    status = m_sdev->switchport_hostif_tx_listener_start();
    sai_return_on_error(status);

    return SAI_STATUS_SUCCESS;
}

static std::string
hostif_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_hostif_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";

    return log_message.str();
}

static sai_status_t
create_hostif(sai_object_id_t* hostif_id, sai_object_id_t switch_id, uint32_t attr_count, const sai_attribute_t* attr_list)
{
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_HOSTIF, SAI_OBJECT_TYPE_SWITCH, switch_id, &hostif_to_string, "attrs", attrs);

    sai_hostif_type_t hostif_type;
    get_attrs_value(SAI_HOSTIF_ATTR_TYPE, attrs, hostif_type, true);
    if (hostif_type == SAI_HOSTIF_TYPE_NETDEV) {
        /* Create netdev interfaces as well */
        const sai_attribute_value_t* name;
        uint32_t name_index;
        sai_status_t status = find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_ATTR_NAME, &name, &name_index);
        if (status != SAI_STATUS_SUCCESS) {
            return status;
        }

        auto sai_hostif_db_map = sdev->m_hostifs.map();
        auto it = std::find_if(
            sai_hostif_db_map.begin(), sai_hostif_db_map.end(), [&name](const std::pair<uint32_t, lsai_hostif>& hostif) {
                return (hostif.second.ifname.compare(name->chardata)) ? false : true;
            });
        if (it != sai_hostif_db_map.end()) {
            // Check for already created hostif is being created again
            // duplicate creation.
            *hostif_id = it->second.oid;
            sai_log_info(SAI_API_HOSTIF, "hostif netdev 0x%lx already created", *hostif_id);
            return SAI_STATUS_SUCCESS;
        }

        uint32_t hostif_index;
        sdev->m_hostifs.allocate_id(hostif_index);
        lsai_object la_hostif(SAI_OBJECT_TYPE_HOSTIF, la_obj.index, hostif_index);

        *hostif_id = la_hostif.object_id();
        sai_object_id_t obj_id;
        get_attrs_value(SAI_HOSTIF_ATTR_OBJ_ID, attrs, obj_id, true);
        lsai_object la_hostif_port(obj_id);

        lsai_hostif hostif;
        hostif.oid = *hostif_id;
        hostif.ifname = name->chardata;
        hostif.port_type = la_hostif_port.type;
        hostif.hostif_attr_type = SAI_HOSTIF_TYPE_NETDEV;
        if (la_hostif_port.type == SAI_OBJECT_TYPE_VLAN) {
            hostif.vid = la_hostif_port.index;
        } else {
            hostif.port_lag_id = la_hostif_port.object_id();
        }

        if (!std::getenv("SAI_SKIP_HOSTIF_NETDEV_CREATION")) {
            status = sdev->m_hostif_handler->create_netdev(hostif);
            sai_return_on_error(status);
        }

        sdev->m_hostifs.set(hostif_index, hostif);
        sai_log_info(SAI_API_HOSTIF, "hostif netdev 0x%lx created", *hostif_id);
    } else if (hostif_type == SAI_HOSTIF_TYPE_GENETLINK) {
        uint32_t hostif_index;
        sdev->m_hostifs.allocate_id(hostif_index);
        lsai_object la_hostif(SAI_OBJECT_TYPE_HOSTIF, la_obj.index, hostif_index);
        *hostif_id = la_hostif.object_id();

        const sai_attribute_value_t* name;
        uint32_t name_index;
        sai_status_t status = find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_ATTR_NAME, &name, &name_index);
        sai_return_on_error(status);

        const sai_attribute_value_t* multicast_group;
        status = find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_ATTR_GENETLINK_MCGRP_NAME, &multicast_group, &name_index);
        sai_return_on_error(status);

        lsai_hostif hostif;
        hostif.oid = *hostif_id;
        hostif.ifname = name->chardata;
        hostif.hostif_attr_type = SAI_HOSTIF_TYPE_GENETLINK;
        hostif.multicast_group = multicast_group->chardata;
        hostif.nl_sock = std::make_shared<sai_netlink_socket>();
        status = hostif.nl_sock->open(hostif.ifname, hostif.multicast_group);
        sai_return_on_error(status);

        sdev->m_hostifs.set(hostif_index, hostif);

    } else if (hostif_type == SAI_HOSTIF_TYPE_FD) {
        // TODO: TYPE_FD not supported yet.
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
remove_hostif(sai_object_id_t hostif_id)
{
    sai_start_api(SAI_API_HOSTIF, SAI_OBJECT_TYPE_HOSTIF, hostif_id, &hostif_to_string, hostif_id);

    lsai_hostif hostif;
    auto status = sdev->m_hostifs.get(la_obj.index, hostif);
    if (status != LA_STATUS_SUCCESS) {
        sai_log_error(SAI_API_HOSTIF, "remove hostif 0x%lx failed", hostif_id);
        return SAI_STATUS_FAILURE;
    }

    {
        std::lock_guard<std::mutex> lock(sdev->m_hostif_lock);
        // remove netdev fd to hostif mapping
        auto netdev_fd_it = std::find_if(sdev->m_frontport_netdev_sock_fds.begin(),
                                         sdev->m_frontport_netdev_sock_fds.end(),
                                         [&hostif](const int fd) { return fd == hostif.netdev_fd; });
        if (netdev_fd_it != sdev->m_frontport_netdev_sock_fds.end()) {
            sdev->m_frontport_netdev_sock_fds.erase(netdev_fd_it);
        }
        sdev->m_netdev_sock_fd_to_hostif.erase(hostif.netdev_fd);
        sdev->m_port_hostif_map.erase(hostif.port_lag_id);
        sdev->m_port_hostif_index_map.erase(hostif.port_lag_id);
    }

    if (hostif.hostif_attr_type == SAI_HOSTIF_TYPE_NETDEV) {
        // remove netdev
        std::string delLinkCmd("ip link del ");
        if ((hostif.port_type == SAI_OBJECT_TYPE_PORT) || (hostif.port_type == SAI_OBJECT_TYPE_LAG)) {
            delLinkCmd += hostif.ifname;
            system(delLinkCmd.c_str());
        }
    }

    status = sdev->m_hostifs.remove(hostif_id);
    sai_return_on_la_error(status);
    return SAI_STATUS_SUCCESS;
}

sai_status_t
hostif_attr_get(_In_ const sai_object_key_t* key,
                _Inout_ sai_attribute_value_t* value,
                _In_ uint32_t attr_index,
                _Inout_ vendor_cache_t* cache,
                void* arg)
{
    // For sonic, get return success. It doesn't use oper status as of now

    lsai_object la_hostif(key->key.object_id);
    auto sdev = la_hostif.get_device();

    lsai_hostif hostif;
    auto status = sdev->m_hostifs.get(la_hostif.index, hostif);
    if (status != LA_STATUS_SUCCESS) {
        // Unknown hostif objectid or oper status set on hostif that is removed/deleted
        return SAI_STATUS_FAILURE;
    }
    int32_t attr_id = (uintptr_t)arg;
    switch (attr_id) {
    case SAI_HOSTIF_ATTR_OPER_STATUS: {
        set_attr_value(SAI_HOSTIF_ATTR_OPER_STATUS, *value, hostif.oper_status);
        break;
    }
    case SAI_HOSTIF_ATTR_TYPE: {
        set_attr_value(SAI_HOSTIF_ATTR_TYPE, *value, hostif.hostif_attr_type);
        break;
    }
    case SAI_HOSTIF_ATTR_OBJ_ID: {
        set_attr_value(SAI_HOSTIF_ATTR_OBJ_ID, *value, hostif.port_lag_id);
        break;
    }
    case SAI_HOSTIF_ATTR_NAME: {
        strncpy(value->chardata, hostif.ifname.c_str(), sizeof(value->chardata));
        break;
    }
    case SAI_HOSTIF_ATTR_QUEUE: {
        set_attr_value(SAI_HOSTIF_ATTR_QUEUE, *value, hostif.q_index);
        break;
    }
    case SAI_HOSTIF_ATTR_VLAN_TAG: {
        set_attr_value(SAI_HOSTIF_ATTR_VLAN_TAG, *value, hostif.tag_mode);
        break;
    }
    case SAI_HOSTIF_ATTR_GENETLINK_MCGRP_NAME: {
        strncpy(value->chardata, hostif.multicast_group.c_str(), sizeof(value->chardata));
        break;
    }
    default:
        return SAI_STATUS_NOT_IMPLEMENTED;
        break;
    }
    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_hostif::set_netdev_oper_status(lsai_hostif& hostif, bool oper_state)
{
    int fd;
    // create basic socket to interact with kernel
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        return SAI_STATUS_SUCCESS;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, hostif.ifname.c_str(), IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    int rc = ioctl(fd, SIOCGIFFLAGS, &ifr);
    if (rc >= 0) {
        if (oper_state) {
            ifr.ifr_flags |= IFF_UP;
        } else {
            ifr.ifr_flags &= ~IFF_UP;
        }

        rc = ioctl(fd, SIOCSIFFLAGS, &ifr);
    }

    // during ioctl operation if failed due to privilege handle it.
    if (rc < 0 && (errno != EPERM && errno != ENODEV)) {
        sai_log_error(SAI_API_HOSTIF, "oper status set failed errno = %d", errno);
        return SAI_STATUS_FAILURE;
    }

    // Incase of failed ioctl and caused either due to limited privilege or no netdev
    // to change its oper-status, return success even though oper-status cannot
    // be changed. This will allow to run tests that do not use netdev and are run with
    // regular privilege level.
    close(fd);
    return SAI_STATUS_SUCCESS;
}

sai_status_t
hostif_attr_oper_status_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    lsai_object la_hostif(key->key.object_id);
    auto sdev = la_hostif.get_device();

    lsai_hostif hostif;
    auto status = sdev->m_hostifs.get(la_hostif.index, hostif);
    if (status != LA_STATUS_SUCCESS) {
        // Unknown hostif objectid or oper status set on hostif that is removed/deleted
        return SAI_STATUS_FAILURE;
    }
    auto oper_state = get_attr_value(SAI_HOSTIF_ATTR_OPER_STATUS, (*value));

    sdev->m_hostif_handler->set_netdev_oper_status(hostif, oper_state);

    hostif.oper_status = oper_state;
    sdev->m_hostifs.set(la_hostif.index, hostif);
    return SAI_STATUS_SUCCESS;
}

sai_status_t
hostif_attr_queue_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    lsai_object la_hostif(key->key.object_id);
    auto sdev = la_hostif.get_device();

    lsai_hostif hostif;
    auto status = sdev->m_hostifs.get(la_hostif.index, hostif);
    if (status != LA_STATUS_SUCCESS) {
        // Unknown hostif objectid or oper status set on hostif that is removed/deleted
        return SAI_STATUS_FAILURE;
    }
    hostif.q_index = get_attr_value(SAI_HOSTIF_ATTR_QUEUE, (*value));
    sdev->m_hostifs.set(la_hostif.index, hostif);
    // TODO Adjust TC of the injected packet based on Tc -> Q mapping.
    return SAI_STATUS_SUCCESS;
}

sai_status_t
hostif_attr_vlan_tag_mode_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    lsai_object la_hostif(key->key.object_id);
    auto sdev = la_hostif.get_device();

    lsai_hostif hostif;
    auto status = sdev->m_hostifs.get(la_hostif.index, hostif);
    if (status != LA_STATUS_SUCCESS) {
        // Unknown hostif objectid or oper status set on hostif that is removed/deleted
        return SAI_STATUS_FAILURE;
    }
    hostif.tag_mode = get_attr_value(SAI_HOSTIF_ATTR_VLAN_TAG, (*value));
    sdev->m_hostifs.set(la_hostif.index, hostif);
    // TODO Program asic using SDK api
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
set_hostif_attribute(sai_object_id_t hostif_id, const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = hostif_id;

    sai_start_api(SAI_API_HOSTIF, SAI_OBJECT_TYPE_HOSTIF, hostif_id, &hostif_to_string, "attr", *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "hostif 0x%lx", hostif_id);
    return sai_set_attribute(&key, key_str, hostif_attribs, hostif_vendor_attribs, attr);
}

static sai_status_t
get_hostif_attribute(sai_object_id_t hostif_id, uint32_t attr_count, sai_attribute_t* attr_list)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = hostif_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_HOSTIF, SAI_OBJECT_TYPE_HOSTIF, hostif_id, &hostif_to_string, "attrs", attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "hostif 0x%lx", hostif_id);
    return sai_get_attributes(&key, key_str, hostif_attribs, hostif_vendor_attribs, attr_count, attr_list);
}

static std::string
hostif_table_entry_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_hostif_table_entry_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";

    return log_message.str();
}

static sai_status_t
create_hostif_table_entry(sai_object_id_t* hostif_table_entry_id,
                          sai_object_id_t switch_id,
                          uint32_t attr_count,
                          const sai_attribute_t* attr_list)
{
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_HOSTIF, SAI_OBJECT_TYPE_SWITCH, switch_id, &hostif_to_string, "attrs", attrs);

    lsai_hostif_table_entry hostif_entry;

    get_attrs_value(SAI_HOSTIF_TABLE_ENTRY_ATTR_TYPE, attrs, hostif_entry.type, true);

    if (hostif_entry.type == SAI_HOSTIF_TABLE_ENTRY_TYPE_PORT || hostif_entry.type == SAI_HOSTIF_TABLE_ENTRY_TYPE_LAG
        || hostif_entry.type == SAI_HOSTIF_TABLE_ENTRY_TYPE_VLAN) {
        get_attrs_value(SAI_HOSTIF_TABLE_ENTRY_ATTR_OBJ_ID, attrs, hostif_entry.port_id, true);
    }

    if (hostif_entry.type == SAI_HOSTIF_TABLE_ENTRY_TYPE_PORT || hostif_entry.type == SAI_HOSTIF_TABLE_ENTRY_TYPE_LAG
        || hostif_entry.type == SAI_HOSTIF_TABLE_ENTRY_TYPE_VLAN
        || hostif_entry.type == SAI_HOSTIF_TABLE_ENTRY_TYPE_TRAP_ID) {
        get_attrs_value(SAI_HOSTIF_TABLE_ENTRY_ATTR_TRAP_ID, attrs, hostif_entry.trap_id, true);
    }

    get_attrs_value(SAI_HOSTIF_TABLE_ENTRY_ATTR_CHANNEL_TYPE, attrs, hostif_entry.channel_type, true);

    if (hostif_entry.channel_type == SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_FD
        || hostif_entry.channel_type == SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_GENETLINK) {
        get_attrs_value(SAI_HOSTIF_TABLE_ENTRY_ATTR_HOST_IF, attrs, hostif_entry.host_if, true);
    }

    // save mapping for port-trap id to hostif_table_entry
    if (hostif_entry.channel_type == SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_NETDEV_PHYSICAL_PORT
        || hostif_entry.channel_type == SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_NETDEV_LOGICAL_PORT
        || hostif_entry.channel_type == SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_NETDEV_L3) {
        lsai_hostif_table_entry_key_t entry_key(hostif_entry.port_id, hostif_entry.trap_id);
        sdev->m_hostif_table_entry_map.emplace(entry_key, hostif_entry);
    } else if (hostif_entry.channel_type == SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_GENETLINK) {
        lsai_hostif_table_entry_key_t entry_key = lsai_hostif_table_entry_key_t(0, hostif_entry.trap_id);
        sdev->m_hostif_table_entry_map.emplace(entry_key, hostif_entry);
    } else {
        auto it = sdev->m_port_hostif_map.find(hostif_entry.port_id);
        if (it != sdev->m_port_hostif_map.end()) {
            hostif_entry.host_if = it->second;
        }
    }
    // allocate hostif_entry oid
    uint32_t table_entry_index;
    sdev->m_hostif_table.allocate_id(table_entry_index);
    lsai_object la_hostif_entry(SAI_OBJECT_TYPE_HOSTIF_TABLE_ENTRY, la_obj.switch_id, table_entry_index);

    *hostif_table_entry_id = la_hostif_entry.object_id();
    hostif_entry.oid = la_hostif_entry.object_id();

    sdev->m_hostif_table.set(table_entry_index, hostif_entry);
    sai_log_info(SAI_API_HOSTIF, "hostif table entry 0x%lx created", *hostif_table_entry_id);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
remove_hostif_table_entry(sai_object_id_t hostif_table_entry_id)
{
    sai_start_api(SAI_API_HOSTIF,
                  SAI_OBJECT_TYPE_HOSTIF_TABLE_ENTRY,
                  hostif_table_entry_id,
                  &hostif_table_entry_to_string,
                  hostif_table_entry_id);

    lsai_hostif_table_entry hostif_entry;
    auto status = sdev->m_hostif_table.get(la_obj.index, hostif_entry);
    if (status != LA_STATUS_SUCCESS) {
        return SAI_STATUS_ITEM_NOT_FOUND;
    }
    // remove port id trap id to hostif mapping
    {
        std::lock_guard<std::mutex> lock(sdev->m_hostif_lock);
        lsai_hostif_table_entry_key_t entry_key(hostif_entry.port_id, hostif_entry.trap_id);
        sdev->m_hostif_table_entry_map.erase(entry_key);
    }

    status = sdev->m_hostif_table.remove(hostif_table_entry_id);
    sai_return_on_la_error(status);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
set_hostif_table_entry_attribute(sai_object_id_t hostif_table_entry_id, const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = hostif_table_entry_id;

    sai_start_api(
        SAI_API_HOSTIF, SAI_OBJECT_TYPE_HOSTIF_TABLE_ENTRY, hostif_table_entry_id, &hostif_table_entry_to_string, "attr", *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "hostif 0x%lx", hostif_table_entry_id);
    return sai_set_attribute(&key, key_str, hostif_table_entry_attribs, hostif_table_entry_vendor_attribs, attr);
}

static sai_status_t
get_hostif_table_entry_attribute(sai_object_id_t hostif_table_entry_id, uint32_t attr_count, sai_attribute_t* attr_list)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = hostif_table_entry_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(
        SAI_API_HOSTIF, SAI_OBJECT_TYPE_HOSTIF_TABLE_ENTRY, hostif_table_entry_id, &hostif_table_entry_to_string, "attrs", attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "hostif table entry 0x%lx", hostif_table_entry_id);
    return sai_get_attributes(&key, key_str, hostif_table_entry_attribs, hostif_table_entry_vendor_attribs, attr_count, attr_list);
}

sai_status_t
hostif_table_entry_attr_get(_In_ const sai_object_key_t* key,
                            _Inout_ sai_attribute_value_t* value,
                            _In_ uint32_t attr_index,
                            _Inout_ vendor_cache_t* cache,
                            void* arg)
{
    lsai_object la_hostif_entry(key->key.object_id);
    auto sdev = la_hostif_entry.get_device();
    if (sdev == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_hostif_table_entry hostif_table_entry;
    auto status = sdev->m_hostif_table.get(la_hostif_entry.index, hostif_table_entry);
    if (status != LA_STATUS_SUCCESS) {
        return SAI_STATUS_FAILURE;
    }
    int32_t attr_id = (uintptr_t)arg;
    switch (attr_id) {
    case SAI_HOSTIF_TABLE_ENTRY_ATTR_OBJ_ID: {
        set_attr_value(SAI_HOSTIF_TABLE_ENTRY_ATTR_OBJ_ID, *value, hostif_table_entry.port_id);
        break;
    }
    case SAI_HOSTIF_TABLE_ENTRY_ATTR_TRAP_ID: {
        set_attr_value(SAI_HOSTIF_TABLE_ENTRY_ATTR_TRAP_ID, *value, hostif_table_entry.trap_id);
        break;
    }
    case SAI_HOSTIF_TABLE_ENTRY_ATTR_TYPE: {
        set_attr_value(SAI_HOSTIF_TABLE_ENTRY_ATTR_TYPE, *value, hostif_table_entry.type);
        break;
    }
    case SAI_HOSTIF_TABLE_ENTRY_ATTR_CHANNEL_TYPE: {
        set_attr_value(SAI_HOSTIF_TABLE_ENTRY_ATTR_CHANNEL_TYPE, *value, hostif_table_entry.channel_type);
        break;
    }
    case SAI_HOSTIF_TABLE_ENTRY_ATTR_HOST_IF: {
        set_attr_value(SAI_HOSTIF_TABLE_ENTRY_ATTR_HOST_IF, *value, hostif_table_entry.host_if);
        break;
    }
    default:
        return SAI_STATUS_NOT_IMPLEMENTED;
        break;
    }
    return SAI_STATUS_SUCCESS;
}

static std::string
hostif_trap_group_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_hostif_trap_group_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";

    return log_message.str();
}

static sai_status_t
create_hostif_trap_group(sai_object_id_t* hostif_trap_group_id,
                         sai_object_id_t switch_id,
                         uint32_t attr_count,
                         const sai_attribute_t* attr_list)
{
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_HOSTIF, SAI_OBJECT_TYPE_SWITCH, switch_id, &hostif_trap_group_to_string, "attrs", attrs);

    bool admin_state = true;
    {
        get_attrs_value(SAI_HOSTIF_TRAP_GROUP_ATTR_ADMIN_STATE, attrs, admin_state, false);
    }

    uint32_t queue_index = 0;
    {
        get_attrs_value(SAI_HOSTIF_TRAP_GROUP_ATTR_QUEUE, attrs, queue_index, false);
    }

    sai_object_id_t policer_id = SAI_NULL_OBJECT_ID;
    ;
    {
        get_attrs_value(SAI_HOSTIF_TRAP_GROUP_ATTR_POLICER, attrs, policer_id, false);
    }

    sai_object_id_t trap_group_id = SAI_NULL_OBJECT_ID;
    la_status status = sdev->m_trap_manager->create_trap_group(trap_group_id, admin_state, queue_index, policer_id);
    sai_return_on_la_error(status);

    *hostif_trap_group_id = trap_group_id;
    sai_log_info(SAI_API_HOSTIF, "hostif trap group id 0x%lx created", *hostif_trap_group_id);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
remove_hostif_trap_group(sai_object_id_t hostif_trap_group_id)
{

    sai_start_api(SAI_API_HOSTIF,
                  SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP,
                  hostif_trap_group_id,
                  &hostif_trap_group_to_string,
                  hostif_trap_group_id);

    la_status status = sdev->m_trap_manager->remove_trap_group(la_obj.index);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
set_hostif_trap_group_attribute(sai_object_id_t hostif_trap_group_id, const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = hostif_trap_group_id;

    sai_start_api(SAI_API_HOSTIF,
                  SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP,
                  hostif_trap_group_id,
                  &hostif_trap_group_to_string,
                  "hostif_trap_group",
                  hostif_trap_group_id,
                  "attr",
                  *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "hostif trap group 0x%lx", hostif_trap_group_id);
    return sai_set_attribute(&key, key_str, hostif_trap_group_attribs, hostif_trap_group_vendor_attribs, attr);
}

static sai_status_t
get_hostif_trap_group_attribute(sai_object_id_t hostif_trap_group_id, uint32_t attr_count, sai_attribute_t* attr_list)
{
    char key_str[MAX_KEY_STR_LEN];

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_HOSTIF,
                  SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP,
                  hostif_trap_group_id,
                  &hostif_trap_group_to_string,
                  "hostif_trap_group",
                  hostif_trap_group_id,
                  "attrs",
                  attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "hostif trap group 0x%lx", hostif_trap_group_id);

    sai_object_key_t key{};
    key.key.object_id = hostif_trap_group_id;
    return sai_get_attributes(&key, key_str, hostif_trap_group_attribs, hostif_trap_group_vendor_attribs, attr_count, attr_list);
}

static std::string
hostif_trap_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_hostif_trap_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";

    return log_message.str();
}

static sai_status_t
create_hostif_trap(sai_object_id_t* hostif_trap_id,
                   sai_object_id_t switch_id,
                   uint32_t attr_count,
                   const sai_attribute_t* attr_list)
{
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_HOSTIF, SAI_OBJECT_TYPE_SWITCH, switch_id, &hostif_trap_to_string, "attrs", attrs);

    sai_hostif_trap_type_t trap_type = SAI_HOSTIF_TRAP_TYPE_END;
    {
        get_attrs_value(SAI_HOSTIF_TRAP_ATTR_TRAP_TYPE, attrs, trap_type, true);
    }

    lsai_object la_trap(SAI_OBJECT_TYPE_HOSTIF_TRAP, la_obj.switch_id, trap_type);
    *hostif_trap_id = la_trap.object_id();

    sai_packet_action_t pkt_action = SAI_PACKET_ACTION_DROP;
    {
        get_attrs_value(SAI_HOSTIF_TRAP_ATTR_PACKET_ACTION, attrs, pkt_action, true);
    }

    la_uint_t priority = 0; // default minimun priority
    {
        get_attrs_value(SAI_HOSTIF_TRAP_ATTR_TRAP_PRIORITY, attrs, priority, false);
    }

    sai_object_id_t group_id = SAI_NULL_OBJECT_ID;
    {
        get_attrs_value(SAI_HOSTIF_TRAP_ATTR_TRAP_GROUP, attrs, group_id, false);
    }

    lsai_object la_sw(switch_id);
    lsai_object la_oid(SAI_OBJECT_TYPE_HOSTIF_TRAP, la_sw.switch_id, trap_type);
    la_status status = sdev->m_trap_manager->create_trap(la_oid.object_id(), pkt_action, priority, group_id);
    sai_return_on_la_error(status);
    sai_log_info(SAI_API_HOSTIF, "hostif trap id 0x%lx created", *hostif_trap_id);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
remove_hostif_trap(sai_object_id_t hostif_trap_id)
{
    sai_start_api(SAI_API_HOSTIF, SAI_OBJECT_TYPE_HOSTIF_TRAP, hostif_trap_id, &hostif_trap_to_string, hostif_trap_id);

    auto trap_type = (sai_hostif_trap_type_t)la_obj.index;
    la_status status = sdev->m_trap_manager->remove_trap(trap_type);
    sai_return_on_la_error(status);
    sai_log_debug(SAI_API_HOSTIF, "hostif trap id 0x%lx removed", hostif_trap_id);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
set_hostif_trap_attribute(sai_object_id_t hostif_trap_id, const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = hostif_trap_id;

    sai_start_api(SAI_API_HOSTIF, SAI_OBJECT_TYPE_HOSTIF_TRAP, hostif_trap_id, &hostif_trap_to_string, hostif_trap_id, *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "hostif trap 0x%lx", hostif_trap_id);
    return sai_set_attribute(&key, key_str, hostif_trap_attribs, hostif_trap_vendor_attribs, attr);
}

static sai_status_t
get_hostif_trap_attribute(sai_object_id_t hostif_trap_id, uint32_t attr_count, sai_attribute_t* attr_list)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = hostif_trap_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_HOSTIF, SAI_OBJECT_TYPE_HOSTIF_TRAP, hostif_trap_id, &hostif_trap_to_string, hostif_trap_id, attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "hostif trap 0x%lx", hostif_trap_id);
    return sai_get_attributes(&key, key_str, hostif_trap_attribs, hostif_trap_vendor_attribs, attr_count, attr_list);
}

static sai_status_t
create_hostif_user_defined_trap(sai_object_id_t* hostif_user_defined_trap_id,
                                sai_object_id_t switch_id,
                                uint32_t attr_count,
                                const sai_attribute_t* attr_list)
{

    lsai_object la_trap(SAI_OBJECT_TYPE_HOSTIF_TRAP, switch_id, SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP);
    *hostif_user_defined_trap_id = la_trap.object_id();
    // TODO program datapath
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
remove_hostif_user_defined_trap(sai_object_id_t hostif_user_defined_trap_id)
{
    // TODO program datapath
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
set_hostif_user_defined_trap_attribute(sai_object_id_t hostif_user_defined_trap_id, const sai_attribute_t* attr)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
get_hostif_user_defined_trap_attribute(sai_object_id_t hostif_user_defined_trap_id, uint32_t attr_count, sai_attribute_t* attr_list)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
recv_hostif_packet(sai_object_id_t hostif_id,
                   sai_size_t* buffer_size,
                   void* buffer,
                   uint32_t* attr_count,
                   sai_attribute_t* attr_list)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
send_hostif_packet(sai_object_id_t hostif_id,
                   sai_size_t buffer_size,
                   const void* buffer,
                   uint32_t attr_count,
                   const sai_attribute_t* attr_list)
{
    lsai_object la_hostif(hostif_id);
    auto sdev = la_hostif.get_device();
    if (sdev == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    int sent_size = buffer_size;

    sai_status_t status = sdev->sai2la_inject_packet((uint8_t*)buffer, &sent_size, attr_count, attr_list);
    sai_return_on_error(status);

    sai_log_debug(SAI_API_HOSTIF, "sent %d bytes", sent_size);

    return SAI_STATUS_SUCCESS;
}

const sai_hostif_api_t host_interface_api = {
    create_hostif,
    remove_hostif,
    set_hostif_attribute,
    get_hostif_attribute,
    create_hostif_table_entry,
    remove_hostif_table_entry,
    set_hostif_table_entry_attribute,
    get_hostif_table_entry_attribute,
    create_hostif_trap_group,
    remove_hostif_trap_group,
    set_hostif_trap_group_attribute,
    get_hostif_trap_group_attribute,
    create_hostif_trap,
    remove_hostif_trap,
    set_hostif_trap_attribute,
    get_hostif_trap_attribute,
    create_hostif_user_defined_trap,
    remove_hostif_user_defined_trap,
    set_hostif_user_defined_trap_attribute,
    get_hostif_user_defined_trap_attribute,
    recv_hostif_packet,
    send_hostif_packet,
};
}
}
