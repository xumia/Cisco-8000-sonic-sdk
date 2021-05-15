#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
#
# This file and all technical concepts, proprietary knowledge, algorithms and
# intellectual property rights it contains (collectively the "Confidential Information"),
# are the sole propriety information of Cisco and shall remain at Cisco's ownership.
# You shall not disclose the Confidential Information to any third party and you
# shall use it solely in connection with operating and/or maintaining of Cisco's
# products and pursuant to the terms and conditions of the license agreement you
# entered into with Cisco.
#
# THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
# IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
# AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
# THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# END_LEGAL

###
# Configuration functions of various snake apps
###

from snake_base_standalone import snake_base_topology
from snake_base_standalone import NUM_PIF_PER_PORT
from snake_p2p_standalone import snake_p2p_topology
from snake_board_p2p_standalone import snake_board_p2p_topology
from snake_bridging_standalone import snake_bridging_topology
from snake_routing_standalone import snake_routing_topology

# Base topology
base_topology = None

# @brief Configure the base topology - MAC thru Eth ports that are common to all topologies.
#
# @param first_slice           First slice of the snake. Relevant only for on-chip snake configurations.
# @param first_ifg             First IFG of the snake. Relevant only for on-chip snake configurations.
# @param first_pif             First PIF of the snake. Relevant only for on-chip snake configurations.
# @param is_on_chip_loopbacks  Create the MAC ports with loopback enabled, needed for on-chip snake tests.
#                               Such topology is not suitable for board snake test (where the snake is implemented
#                               by connecting physical ports with cables).
# @param loopback_num          Limit the number of loops in the test. Relevant only for on-chip snake configurations. For debug only.
# @param is_simulator          True iff the application runs on NSIM.


def configure_base_topology(
        la_dev,
        first_slice,
        first_ifg,
        first_pif,
        is_on_chip_loopbacks=True,
        loopback_num=-1,
        is_simulator=False):
    global base_topology
    base_topology = snake_base_topology(la_dev, is_simulator)
    base_topology.initialize(first_slice, first_ifg, first_pif, is_on_chip_loopbacks, loopback_num)


def teardown_base_topolgy():
    global base_topology
    base_topology.teardown()
    base_topology = None


# P2P
p2p_topology = None

# @brief Configure the topology for L2 P2P on-chip snake test.


def configure_p2p(la_dev):
    global p2p_topology
    p2p_topology = snake_p2p_topology(la_dev)
    p2p_topology.initialize(base_topology)


def teardown_p2p():
    global p2p_topology
    p2p_topology.teardown()
    p2p_topology = None


# L2 bridging
bridging_topology = None

# @brief Configure the topology for L2 bridging on-chip snake test.
#
# @param  la_dev  la_device object.
# @param  dst     MAC destination address of the input packet.


def configure_bridging(la_dev, dst):
    global bridging_topology
    bridging_topology = snake_bridging_topology(la_dev)
    bridging_topology.initialize(base_topology, dst)


def teardown_bridging():
    global bridging_topology
    bridging_topology.teardown()
    bridging_topology = None


# L3 routing
routing_topology = None

# @brief Configure the topology for L3 routing on-chip snake test.
#
# @param  la_dev  la_device object.
# @param  dst     MAC destination address of the input packet.
# @param  src     MAC source address of the input packet.
# @param  dip     IP destination address of the input packet.


def configure_routing(la_dev, dst, src, dip):
    global routing_topology
    routing_topology = snake_routing_topology(la_dev)
    routing_topology.initialize(base_topology, dst, src, dip)


def teardown_routing():
    global routing_topology
    routing_topology.teardown()
    routing_topology = None


# Board L2 P2P
board_p2p_topology = None

# @brief Configure the topology for L2 P2P board snake test.


def configure_board_p2p(la_dev):
    global board_p2p_topology
    board_p2p_topology = snake_board_p2p_topology(la_dev)
    board_p2p_topology.initialize(base_topology)


def teardown_board_p2p():
    global board_p2p_topology
    board_p2p_topology.teardown()
    board_p2p_topology = None
