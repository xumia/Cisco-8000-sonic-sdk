// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __SAI_HOSTIF_H__
#define __SAI_HOSTIF_H__

#include <string>
#include "la_sai_object.h"
#include "sai_netlink_socket.h"

namespace silicon_one
{
namespace sai
{

// sai hostif interface related  information.
struct lsai_hostif {
    sai_object_id_t oid;
    sai_hostif_type_t hostif_attr_type; // netdev or fd etc
    sai_object_type_t port_type;
    std::string ifname;
    std::string multicast_group;
    bool oper_status = false;
    sai_object_id_t port_lag_id;
    uint16_t vid;
    int netdev_fd; // fd obtained when netdev intf is created.
    sai_hostif_vlan_tag_t tag_mode;
    uint32_t q_index; // queue index for packets egress out through the hostif intf
    std::shared_ptr<sai_netlink_socket> nl_sock;
};

struct lsai_hostif_table_entry {
    sai_object_id_t oid;
    sai_hostif_table_entry_type_t type;
    sai_object_id_t port_id;
    sai_object_id_t trap_id;
    sai_hostif_table_entry_channel_type_t channel_type;
    sai_object_id_t host_if;
};

class sai_hostif
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS;

public:
    sai_hostif() = default;
    sai_hostif(std::shared_ptr<lsai_device> sdev) : m_sdev(sdev){};
    ~sai_hostif() = default;
    sai_status_t create_netdev(lsai_hostif& hostif);
    sai_status_t set_netdev_oper_status(lsai_hostif& hostif, bool oper_state);

private:
    sai_status_t set_dev_mac_address(const std::string& ifname, const sai_mac_t& mac);
    int create_tap_device(const std::string& ifname);

    std::shared_ptr<lsai_device> m_sdev;
};

class lsai_hostif_table_entry_key_t
{
public:
    lsai_hostif_table_entry_key_t() : lsai_hostif_table_entry_key_t(0, 0)
    {
    }
    lsai_hostif_table_entry_key_t(sai_object_id_t p, sai_object_id_t t) : port_id(p), trap_id(t)
    {
    }
    bool operator<(const lsai_hostif_table_entry_key_t& other) const
    {
        return std::tie(port_id, trap_id) < std::tie(other.port_id, other.trap_id);
    }

    sai_object_id_t port_id;
    sai_object_id_t trap_id;
};
}
}
#endif
