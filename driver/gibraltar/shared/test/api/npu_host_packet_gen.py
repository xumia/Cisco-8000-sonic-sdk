# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

import argparse
import sys
import os
import imp
import re
import math
from random import shuffle
from enum import Enum
import packet_test_utils as U  # SW simulator
from leaba import debug
from leaba import sdk
from bit_utils import *
import logging
getframe_expr = 'sys._getframe({}).f_code.co_name'

######################################
############### HELPERS ##############
######################################

logging.basicConfig(stream=sys.stdout,
                    level=logging.DEBUG,
                    format='%(levelname)-8s %(message)s',
                    datefmt='%d/%m/%Y %H:%M:%S',
                    filemode='w')
formatter = logging.Formatter("%(asctime)s %(name)-12s %(levelname)-8s %(message)s")
logger = logging.getLogger('')
logger1 = logging.getLogger('validation')

global debug_mode
debug_mode = False  # initial global var


def get_caller(depth=0):  # 0: who-am-i, 1: who-is-caller, 2: who-is-caller's-caller..
    return eval(getframe_expr.format(depth + 2))
    # return inspect.stack()[depth][3]


def get_caller_module():  # get the module of the caller
    stk = inspect.stack()[-1]
    caller = inspect.getmodule(stk[0])
    lb_debug('caller = %s' % (caller))
    return caller


def lb_note(str, add_source=1, note_type="INFO", source=""):
    if source == "":
        source = get_caller(1)
    if (add_source == 1):
        msg = ("from '%s': %s" % (source, str))
    else:
        msg = ("%s" % (str))
    # Print according to note_type
    if (note_type == "INFO"):
        logger1.info(msg)
    elif (note_type == "DEBUG"):
        logger1.debug(msg)
    elif (note_type == "WARNING"):
        logger1.warning(msg)
    elif (note_type == "ERROR"):
        logger1.error(msg)
    elif (note_type == "FATAL"):
        logger1.critical(msg)
        print("\nTEST FATAL FAIL!\n")
        print("Fatal is: ", msg)
        sys.exit(1)


def lb_debug(str, add_source=1):
    if (debug_mode):
        lb_note(str, add_source, note_type="DEBUG", source=get_caller(1))


def lb_warning(str, add_source=1):
    lb_note(str, add_source, note_type="WARNING", source=get_caller(1))


def lb_error(str, add_source=1, source=""):
    if source == "":
        source = get_caller(1)
    note_type = "ERROR"
    lb_note(str, add_source, note_type, source)


def lb_fatal(str, add_source=1):
    lb_note(str, add_source, note_type="FATAL", source=get_caller(1))


def module_exists(module):
    try:
        imp.find_module(module)
        return True
    except ImportError:
        return False


def load_module(filename_or_module):
    lb_note("Attempting to load module: '%s' ..." % filename_or_module)

    if not filename_or_module:
        lb_note("Module name is empty -> return")
        return None

    if module_exists(filename_or_module):
        lb_note("Found module: '%s'" % (filename_or_module))
        if (filename_or_module in sys.modules):
            lb_warning("Previous module with the same name found -> removing old one from 'sys.modules'")
            del sys.modules[filename_or_module]
        return filename_or_module

    if not os.path.exists(filename_or_module):
        lb_error("module does not exist: '%s'" % filename_or_module)
        assert False

    tc_dir = os.path.dirname(filename_or_module)
    if (tc_dir not in sys.path):
        sys.path.append(tc_dir)

    (module, ext) = os.path.splitext(os.path.basename(filename_or_module))
    if (module):
        lb_note("Found module after split path: '%s'" % (module))
        if (module in sys.modules):
            lb_warning("Previous module with the same name found -> removing old one from 'sys.modules'")
            del sys.modules[module]
    else:
        lb_note("Did not find module -> return")
    return module

############### ARGS ##############


class PacketRateType(Enum):
    MAX = 0
    SPECIFIC = 1
    CALCULATED = 2


class NpuHostPacketGenAttribute:
    def __init__(self,
                 configure_packets=1,  # Set if configuring the packets in the npu-host tables is required
                 configure_scanners=1,
                 # Set if configuring the npu-host scanner is required (e.g. for controlling the rate, num_of_replications..)
                 packet_inject_module="packet_inject.py",  # Module contains the inject packets
                 randomize_inject_order=0,
                 num_of_replications=1,  # Number of replications for each packet. valid values are: 1-255 for specific number, 0 for endless
                 packet_rate_type=PacketRateType.CALCULATED,
                 # May be CALCULATED/SPECIFIC/MAX (default: CALCULATED (i.e. calculate
                 # packet rate according to port-rate, percentage, clk-rate and
                 # total-packet-sizes)
                 npuh_port_rate=50,
                 # Npuh Port rate in Gbps (default: 50 (i.e. 50Ghz)). Relevant only if packet_rate_type is SPECIFIC
                 inject_percentage=99,  # Inject percentage out of the max port rate in accordance to npuh_port_rate (default: 99%)
                 clk_rate=1.2,  # Clk rate is Ghz (default: 1.2Ghz)
                 specific_packet_rate=16,
                 # default: 16 (i.e. stimulus new packet each 16 clks). Relevant only if packet_rate_type is SPECIFIC.
                 force_first_packet_index=0,  # default: 0 -> no force. if != 0 -> this will be the first packet which will be injected
                 force_total_num_of_packets=0,
                 # default: 0 -> no force. if != 0 -> this will be the number which will be
                 # taken into account when configuring the scanner. relevant only if
                 # configure_packets = 0
                 force_total_number_of_bytes_from_different_packets=0):  # default: 0 -> no force. if != 0 -> this will be the number which will be taken into account when configuring the scanner. relevant only if configure_packets = 0
        self.configure_packets = configure_packets
        self.configure_scanners = configure_scanners
        self.packet_inject_module = packet_inject_module
        self.randomize_inject_order = randomize_inject_order
        self.num_of_replications = num_of_replications
        self.packet_rate_type = packet_rate_type
        self.npuh_port_rate = npuh_port_rate
        self.inject_percentage = inject_percentage
        self.clk_rate = clk_rate
        self.specific_packet_rate = specific_packet_rate
        self.force_first_packet_index = force_first_packet_index
        self.force_total_num_of_packets = force_total_num_of_packets
        self.force_total_number_of_bytes_from_different_packets = force_total_number_of_bytes_from_different_packets


############### INJECT MODUOLE ##############


class npuh_traffic_gen_send_module:

    def __init__(self, dev_handlers):
        self.la_dev = dev_handlers.la_dev
        self.ll_device = dev_handlers.ll_device
        self.tree = dev_handlers.tree
        self.debug_device = dev_handlers.debug_device

    def start_npu_host_inject(self):
        self.enable_or_disable_scanner(1)
        lb_note('Enabling Npu-host scanner (Start inject from npu-host)')

    def stop_npu_host_inject(self):
        self.enable_or_disable_scanner(0)
        lb_note('Disabling Npu-host scanner (Stop inject from npu-host)')

    def enable_or_disable_scanner(self, enable=1):
        # read
        status = 0
        mp_ccm_timer_reg_data = self.ll_device.read_register(self.tree.npuh.host.mp_ccm_timer)
        lb_debug("Before %s npu-host-scanner: mp_ccm_timer_reg_data = 0x%x" %
                 ("enabling" if enable else "disabling", mp_ccm_timer_reg_data))
        # modify
        mp_ccm_timer_reg_data = set_bits(mp_ccm_timer_reg_data, 90, 90, enable)
        lb_debug("After %s npu-host-scanner: mp_ccm_timer_reg_data = 0x%x" %
                 ("enabling" if enable else "disabling", mp_ccm_timer_reg_data))
        # write
        self.ll_device.write_register(self.tree.npuh.host.mp_ccm_timer, mp_ccm_timer_reg_data)

    def set_num_or_replications(self, num_of_replications=1):
        # read
        status = 0
        mp_ccm_timer_reg_data = self.ll_device.read_register(self.tree.npuh.host.mp_ccm_timer)
        lb_debug(
            "Before setting num_of_replications = %0d in npu-host-scanner: mp_ccm_timer_reg_data = 0x%x" %
            (num_of_replications, mp_ccm_timer_reg_data))
        # modify
        mp_ccm_timer_reg_data = set_bits(mp_ccm_timer_reg_data, 98, 91, num_of_replications)  # mp_ccm_count
        lb_debug(
            "After setting num_of_replications = %0d in npu-host-scanner: mp_ccm_timer_reg_data = 0x%x" %
            (num_of_replications, mp_ccm_timer_reg_data))
        # write
        self.ll_device.write_register(self.tree.npuh.host.mp_ccm_timer, mp_ccm_timer_reg_data)

############### CONFIG MODUOLE ##############


class npuh_traffic_gen_config_module:
    injected_packets = []
    pkt_ids_injected = {}
    first_packet_index = 0
    total_number_of_different_packets = 0
    total_number_of_bytes_from_different_packets = 0

    def __init__(self, dev_handlers):
        self.la_dev = dev_handlers.la_dev
        self.ll_device = dev_handlers.ll_device
        self.tree = dev_handlers.tree
        self.debug_device = dev_handlers.debug_device

    def init_packets_databases(self):
        lb_note("init_packets_databases")
        self.injected_packets = []
        self.pkt_ids_injected = {}
        self.first_packet_index = 0
        self.total_number_of_different_packets = 0
        self.total_number_of_bytes_from_different_packets = 0

    def inject_packet(self, flow_id, per_flow_pkt_id, packet, slice_id, ifg, pif, values={}):
        if flow_id in self.pkt_ids_injected and per_flow_pkt_id in self.pkt_ids_injected[flow_id]:
            lb_error("packet id override! flow id %d, packet id %d was injected twice!" % (flow_id, per_flow_pkt_id))
            return
        if flow_id not in self.pkt_ids_injected:
            self.pkt_ids_injected[flow_id] = []
        self.pkt_ids_injected[flow_id].append(per_flow_pkt_id)

        packet_to_inject = {'flow_id': flow_id,
                            'per_flow_pkt_id': per_flow_pkt_id,
                            'packet': packet,
                            'packet_size_in_bytes': self.get_packet_size_in_bytes(packet),
                            'slice_id': slice_id,
                            'ifg': ifg,
                            'pif': pif,
                            'values': values}
        packet_to_inject['packet_size_in_bytes'] = self.get_packet_size_in_bytes(packet_to_inject['packet'])
        self.injected_packets.append(packet_to_inject)
        self.total_number_of_different_packets += 1
        self.total_number_of_bytes_from_different_packets += packet_to_inject['packet_size_in_bytes']

    # def print_output_pkts(self, pkt_info, out_pkts, output_file):
    #    pkt_index = 0
    #    for out_pkt in out_pkts:
    #        print("output pkt: flow_id %d, per_flow_pkt_id: %d, copy index: %d (total of %d pkt(s) for this flow,packet):" %
    #              (pkt_info['flow_id'], pkt_info['per_flow_pkt_id'], pkt_index, len(out_pkts)), file=output_file)
    #        print(
    #            "  packet data: %s" %
    #            out_pkt.m_packet_data.to_string()[
    #                2:],
    #            file=output_file)  # the "[2:] is for removing "0x" from the packet
    #        print("  packet length in bytes: %d" % (out_pkt.m_packet_data.get_width() / 8), file=output_file)
    #        print("  output slice_id: %d" % out_pkt.m_slice_id, file=output_file)
    #        print("  output ifg: %d" % out_pkt.m_ifg, file=output_file)
    #        print("  output pif: %d" % out_pkt.m_pif, file=output_file)
    #        print("", file=output_file)  # adding seperator between flows
    #        pkt_index += 1

    def configure_npu_host_scanners(self, args):
        lb_debug("------------------------------------------------------------------------------------------------------------------------------------------------------------")
        lb_debug("-----------------------------------------------Printing scanner info for NPU-HOST-PACKET-GEN ---------------------------------------------------------------")
        lb_debug("------------------------------------------------------------------------------------------------------------------------------------------------------------")

        if (self.total_number_of_different_packets == 0):
            lb_error("No configured packets found! cannot calculate the requested average rate!")
            return

        clks_gap_between_scanner_stimulus = self.calculate_average_packet_rate(args)

        # Configure scanner
        start_index = self.first_packet_index
        end_index = start_index + self.total_number_of_different_packets - 1
        interval_clock = clks_gap_between_scanner_stimulus - 1
        cycle_clocks = (end_index - start_index + 1) * (interval_clock + 1) - 1
        if (args.num_of_replications > 255):
            lb_warning(
                "num_of_replications = %0d > 255 which is the max-allowed for cfg. configuring 0 (for endless), and assuming timer will be enabled only for the requested time according to the packet rate (Duration might be not accurate in lab tests !)" %
                (args.num_of_replications))
            num_of_replications = 0  # endless

        lb_debug(
            "Scanner config: start_index = %0d, end_index = %0d, interval_clock = %0d, cycle_clocks = %0d, mp_ccm_count (i.e. num_of_replications) = %0d" %
            (start_index, end_index, interval_clock, cycle_clocks, args.num_of_replications))
        # ccm timer reg
        mp_ccm_timer_reg_data = self.debug_device.read_register(self.tree.npuh.host.mp_ccm_timer)
        mp_ccm_timer_reg_data.mp_ccm_interval_clocks = interval_clock
        mp_ccm_timer_reg_data.mp_ccm_cycle_clocks = cycle_clocks
        mp_ccm_timer_reg_data.mp_ccm_start_index = start_index
        mp_ccm_timer_reg_data.mp_ccm_end_index = end_index
        mp_ccm_timer_reg_data.mp_ccm_timer_enable = 0  # will be set and reset from other method when requested
        mp_ccm_timer_reg_data.mp_ccm_count = args.num_of_replications
        self.debug_device.write_register(self.tree.npuh.host.mp_ccm_timer, mp_ccm_timer_reg_data)
        lb_debug("mp_ccm_timer_reg_data = 0x%x" % (mp_ccm_timer_reg_data.flat))

        # max-ccm-counter
        for i in range(8):
            # configure each entry to 0 -> this way each packet will be sent symmetrically
            self.ll_device.write_memory(self.tree.npuh.host.max_ccm_counter, i, 0)

        lb_debug("--------------------------------------------------------Done----------------------------------------------")

        return 0

    def calculate_average_packet_rate(self, args):
        lb_debug("Calculating packet rate for packet_rate_type = %s" % (args.packet_rate_type))
        if (args.packet_rate_type == PacketRateType.MAX):
            calculated_average_packet_rate = 11  # 10 is the minimum possible B2B SAT/MPS Events (11 Cycles: 0..10)
        elif (args.packet_rate_type == PacketRateType.SPECIFIC):
            calculated_average_packet_rate = args.specific_packet_rate
        else:  # Calculated
            if (self.total_number_of_different_packets == 0):
                lb_error("No configured packets found! cannot calculate the requested average rate!")
                return
            if (args.num_of_replications == 0):
                lb_warning(
                    "Got num_of_replications == 0 (endless) with packet-rate-type = CALCULATED -> using num_of_replications == 1 for the rate calculation!")
                local_num_of_replications = 1
            else:
                local_num_of_replications = args.num_of_replications
            ifg_bytes_overhead = 24;  # additional per packet: preamble (8B), CRC (4B), IPG (12B)
            ifg_reduced_port_rate = args.npuh_port_rate * (args.inject_percentage / 100)
            total_num_of_packets = self.total_number_of_different_packets * local_num_of_replications
            total_number_of_bytes = self.total_number_of_bytes_from_different_packets * \
                local_num_of_replications + total_num_of_packets * ifg_bytes_overhead
            total_ifg_send_time = (total_number_of_bytes * 8) / ifg_reduced_port_rate
            total_ifg_send_clks = (total_ifg_send_time * args.clk_rate)
            calculated_average_packet_rate = math.ceil(total_ifg_send_clks / total_num_of_packets)  # round result to next integer
            lb_debug(
                "packet_rate_type is CALCULATED. ifg port rate is %2.2f Gbps (Got ifg_bit_rate_percentage = %0d -> reduce ifg rate from %0d Gbps), total_num_of_packets = %0d, "
                "total_number_of_bytes (including ifg_bytes_overhead of %0d[B] for each packet) = %0d[B], total_ifg_send_time = %2.2f[ns], total_ifg_send_clks = %2.2f[clks] -> average_packet_rate will be 1 packet stimulus each %0d clks "
                "(NOTE: in the npu-host output, there is a minimum 1-clk gap between each packet to another))" %
                (ifg_reduced_port_rate, args.inject_percentage, args.npuh_port_rate, total_num_of_packets, ifg_bytes_overhead, total_number_of_bytes, total_ifg_send_time, total_ifg_send_clks, calculated_average_packet_rate))
        if (calculated_average_packet_rate < 11):
            lb_warning(
                "calculated_average_packet_rate is %0d which is less than the allowed (which is 1 packet stimulus each 11 clks). overriding value --> calculated_average_packet_rate = 11" %
                (calculated_average_packet_rate))
            calculated_average_packet_rate = 11
        lb_debug("Summary: calculated_average_packet_rate is: 1 packet stimulus each %0d clks" % (calculated_average_packet_rate))

        return calculated_average_packet_rate

    def get_packet_size_in_bytes(self, packet_string):
        return int(len(packet_string) / 2)

    def configure_packets_in_npu_host_tables(self, args):
        MAX_PACKET_SIZE_IN_BYTES_FOR_FIRST_STAGE = (128 - 16)
        MAX_NUM_OF_ENTRIES_FOR_AUX = int(MAX_PACKET_SIZE_IN_BYTES_FOR_FIRST_STAGE / 16)  # should be 7
        # Local packet counter
        curr_packet_number = 0
        # MP Data Table
        next_mp_table_index = 0
        # AUX Data Table
        next_aux_table_index = 0
        # Packet Data Table
        next_packet_data_table_index = 0

        lb_note("------------------------------------------------------------------------------------------------------------------------------------------------------------")
        lb_note("-----------------------------------------------Printing packets to configure for NPU-HOST-PACKET-GEN--------------------------------------------------------")
        lb_note("------------------------------------------------------------------------------------------------------------------------------------------------------------")

        # NOTE: in python: res = c ? a : b <-> res = a if c else b
        if (args.randomize_inject_order):
            lb_debug("'randomize_inject_order' is set -> Randomizing the packets order before configre in databases")
            shuffle(self.injected_packets)

        for pkt_info in self.injected_packets:
            curr_packet_number += 1
            # inject port
            inject_pif = pkt_info['pif']
            inject_ifg = pkt_info['slice_id'] * 2 + pkt_info['ifg']
            # Calculate data required for configuration
            packet_data = self.construct_packet_from_string(pkt_info['packet'])
            packet_size = pkt_info['packet_size_in_bytes']
            packet_data_required = (packet_size > MAX_PACKET_SIZE_IN_BYTES_FOR_FIRST_STAGE)

            # packet-out can add only 16B multiple, so that if the packet-size is
            # greater than 112 (packet-out will use the packet-data-table), the
            # non-multiple should be used from the aux
            aux_size = (MAX_PACKET_SIZE_IN_BYTES_FOR_FIRST_STAGE - (0 if (packet_size % 16 == 0)
                                                                    else (16 - packet_size % 16))) if packet_data_required else packet_size
            extra_size = (packet_size - aux_size) if packet_data_required else 0
            num_of_extra_packet_data_entries = (int(extra_size / 16) + (extra_size % 16 != 0)) if packet_data_required else 0

            number_of_aux_entries_needed = (int(aux_size / 16) + (aux_size % 16 != 0))
            start_aux_index = next_aux_table_index
            end_aux_index = (next_aux_table_index + MAX_NUM_OF_ENTRIES_FOR_AUX -
                             1) if packet_data_required else (next_aux_table_index + (int(aux_size / 16) + (aux_size % 16 != 0)) - 1)

            # Check packet validity
            self.check_packet_info_validity(pkt_info, packet_size)

            #--------------------------------------------
            #----------MP-table configuration------------
            #--------------------------------------------
            #----MP-data----
            mp_data = 0
            # general info
            mp_data = set_bits(mp_data, 3, 0, inject_ifg)
            mp_data = set_bits(mp_data, 11, 4, aux_size)
            # packet-data usage
            mp_data = set_bits(mp_data, 12, 12, packet_data_required)
            mp_data = set_bits(mp_data, 20, 13, next_packet_data_table_index)
            mp_data = set_bits(mp_data, 25, 21, num_of_extra_packet_data_entries)
            # aux data usage
            # total number of aux entries to read (including first read from scanner)
            mp_data = set_bits(mp_data, 29, 26, number_of_aux_entries_needed)
            mp_data = set_bits(mp_data, 30, 30, 0)  # padding
            mp_data = set_bits(mp_data, 42, 31, next_aux_table_index)  # first aux-entry to be read from npe

            #----MP-table-entry----
            mp_table_entry = self.debug_device.read_memory(self.tree.npuh.host.mp_data_table, next_mp_table_index)
            mp_table_entry.mp_valid = 0x1
            mp_table_entry.aux_ptr = next_aux_table_index
            mp_table_entry.ccm_valid = 0x1
            mp_table_entry.ccm_period = 0x0
            mp_table_entry.ccm_count_phase = 0x0000
            mp_table_entry.data = mp_data
            # unused fields
            mp_table_entry.lm_valid = 0x0  # not used
            mp_table_entry.lm_period = 0x0  # not used
            mp_table_entry.lm_count_phase = 0x0000  # not used
            mp_table_entry.dm_valid = 0x0  # not used
            mp_table_entry.dm_period = 0x0  # not used
            mp_table_entry.dm_count_phase = 0x0000  # not used
            #---Write to MP-table---
            self.debug_device.write_memory(self.tree.npuh.host.mp_data_table, next_mp_table_index, mp_table_entry)

            lb_note(
                "Configuring packet %0d/%0d: flow_id %d, per_flow_pkt_id %d (inject port is: slice[%0d], ifg[%0d], pif[%0d])" %
                (curr_packet_number,
                 self.total_number_of_different_packets,
                 pkt_info['flow_id'],
                    pkt_info['per_flow_pkt_id'],
                    pkt_info['slice_id'],
                    pkt_info['ifg'],
                    pkt_info['pif']))
            lb_note("  packet data: %s" % (pkt_info['packet']))
            lb_note("  packet length in bytes: %d" % (packet_size))
            lb_debug("  packet_data_required = %0d, aux_size = %0d ,extra_size = %0d ,num_of_extra_packet_data_entries = %0d" %
                     (packet_data_required, aux_size, extra_size, num_of_extra_packet_data_entries))
            packed_packet_for_print = "  packed_packet[%0d-1:0]: " % (packet_size * 8)
            #lb_debug("  packed_packet[%0d-1:0]: " % (packet_size*8), new_line = 0)
            for i in range(packet_size):
                curr_msb = packet_size * 8 - 1 - 8 * i
                packed_packet_for_print += "%02x" % (get_bits(packet_data, curr_msb, curr_msb - 7))
                #lb_note("%02x" % (get_bits(packet_data, curr_msb, curr_msb-7)), new_line=0, add_source=0)
            packed_packet_for_print += "\n"
            lb_debug(packed_packet_for_print)
            lb_debug("", add_source=0)
            lb_debug("  Configuring MP table index %d (data is 0x%0x)" % (next_mp_table_index, mp_table_entry.flat))

            # Prepare data for next packet
            next_mp_table_index = next_mp_table_index + 1

            #---------------------------------------------
            #----------AUX-table configuration------------
            #---------------------------------------------
            for aux_table_index in range(start_aux_index, end_aux_index + 1):
                start_byte = (aux_table_index - start_aux_index) * 16
                curr_aux_data = 0
                for offset in range(0, 16):
                    if (start_byte + offset < packet_size):
                        curr_packet_msb = packet_size * 8 - 1 - 8 * (start_byte + offset)
                        curr_aux_data_msb = 128 - 1 - offset * 8
                        curr_aux_data = set_bits(curr_aux_data, curr_aux_data_msb, curr_aux_data_msb - 7,
                                                 get_bits(packet_data, curr_packet_msb, curr_packet_msb - 7))
                if (aux_table_index < 4096):
                    self.ll_device.write_memory(self.tree.npuh.host.aux_data_table, aux_table_index, curr_aux_data)
                    lb_debug(
                        "  Configuring aux-data-table: mem-entry-index is %0d -> data is 0x%032x" %
                        (aux_table_index, curr_aux_data))
                else:
                    lb_error("Reached last entry in aux-data memory (too many flows/packet or packets are too big). please check!")
                    return 1

            # Prepare data for next packet
            next_aux_table_index = next_aux_table_index + number_of_aux_entries_needed

            #-----------------------------------------------------
            #----------Packet-Data-table configuration------------
            #-----------------------------------------------------
            if (num_of_extra_packet_data_entries > 0):
                string_postfix = ("from byte %s of the last aux entry)" % (aux_size % 16)) if (aux_size % 16 != 0) else "new entry)"
                lb_debug("  Configuring Packet Data Table (Starting %s" % (string_postfix))
            else:
                lb_debug(
                    "  Do not configure Packet Data Table (Packet size < 112B). Last valid byte in last aux-entry is %0d" %
                    (aux_size %
                     16 if (
                         aux_size %
                         16 != 0) else 16))

            for packet_data_table_index in range(
                    next_packet_data_table_index,
                    next_packet_data_table_index +
                    num_of_extra_packet_data_entries):
                start_byte = aux_size + (packet_data_table_index - next_packet_data_table_index) * 16
                curr_packet_data = 0
                for offset in range(0, 16):
                    if (start_byte + offset < packet_size):
                        curr_packet_msb = packet_size * 8 - 1 - 8 * (start_byte + offset)
                        curr_packet_data_table_msb = 128 - 1 - offset * 8
                        curr_packet_data = set_bits(
                            curr_packet_data,
                            curr_packet_data_table_msb,
                            curr_packet_data_table_msb - 7,
                            get_bits(
                                packet_data,
                                curr_packet_msb,
                                curr_packet_msb - 7))
                if (packet_data_table_index < 256):
                    packet_data_mem_entry = self.debug_device.read_memory(
                        self.tree.npuh.host.packet_data_table, packet_data_table_index)
                    packet_data_mem_entry.next_recycle_valid = 0  # bit-0 may be used for 'recycle' data which is not used here!
                    packet_data_mem_entry.packet_data = curr_packet_data  # bit-0 may be used for 'recycle' data which is not used here!
                    self.debug_device.write_memory(
                        self.tree.npuh.host.packet_data_table,
                        packet_data_table_index,
                        packet_data_mem_entry)
                    lb_debug(
                        "  Configuring packet-data-table: mem-entry-index is %0d -> data is 0x%032x, (data[128:1] = 0x%x)" %
                        (packet_data_table_index, packet_data_mem_entry.packet_data, curr_packet_data))
                else:
                    lb_error("Reached last entry in packet-data memory (too many flows/packet or packets are too big). please check!")
                    return 1
            # Set next index
            next_packet_data_table_index = next_packet_data_table_index + num_of_extra_packet_data_entries

            lb_note("--------------------------------------------------------DONE------------------------------------------------------------------------------")

        return 0

    def construct_packet_from_string(self, packet_string):
        packet_data = 0
        curr_lsb = 0
        for nibble in reversed(packet_string):
            packet_data = set_bits(packet_data, curr_lsb + 3, curr_lsb, int(nibble, 16))
            curr_lsb += 4
        return packet_data

    def check_packet_info_validity(self, pkt_info, packet_size):
        # Check length is valid
        packet_string_length = len(pkt_info['packet'])
        if (packet_string_length % 2 != 0):
            lb_error(
                "For flow_id %x, per_flow_packet_id %d: number of nibbles in packet_string is not even (string length is %0d). please check input!" %
                (pkt_info['flow_id'], pkt_info['per_flow_pkt_id'], packet_string_length))
            return 1
        # Check packet size
        if (packet_size < 60):
            lb_warning(
                "For flow_id %x, per_flow_packet_id %d: packet_size = %0d < 60 Bytes which is the minumum packet size for valid ETHERNET packet!" %
                (pkt_info['flow_id'], pkt_info['per_flow_pkt_id'], packet_size))
        if (packet_size > 608):
            lb_error(
                "For flow_id %x, per_flow_packet_id %d: packet_size = %0d > 608 Bytes which is the maximum suppoted packet size when generating using the npu-host. Please decrease the packet size!" %
                (pkt_info['flow_id'], pkt_info['per_flow_pkt_id'], packet_size))
            return 1
        supported_inject_pif = self.get_supported_inject_pci_pif(pkt_info['slice_id'], pkt_info['ifg'])
        if (pkt_info['pif'] != supported_inject_pif):
            lb_error(
                "For flow_id %x, per_flow_packet_id %d: inject_pif == %0d != %0d which is the only pif supported when generating using the npu-host for slice %0d, ifg %0d. Please change!" %
                (pkt_info['flow_id'],
                 pkt_info['per_flow_pkt_id'],
                    pkt_info['pif'],
                    supported_inject_pif,
                    pkt_info['slice_id'],
                    pkt_info['ifg']))
            return 1
        return 0

    def config_packets_and_scanners(self, args):

        if (args.configure_packets):
            # Get packet inject module
            module = load_module(args.packet_inject_module)
            if module:
                packet_inject_module = __import__(module)
            # init packets databases
            self.init_packets_databases()
            # Construct inject packets database
            packet_inject_module.inject_packet(self)
            # Configre npu-host tables and regs
            self.configure_packets_in_npu_host_tables(args)

        # Set forced params
        if (args.force_total_num_of_packets != 0):
            lb_note(
                "Got force_total_num_of_packets != 0 -> Forcing total number of configured packets  = %0d" %
                (args.force_total_num_of_packets))
            self.total_number_of_different_packets = args.force_total_num_of_packets
        if (args.force_total_number_of_bytes_from_different_packets != 0):
            lb_note(
                "Got force_total_number_of_bytes_from_different_packets != 0 -> Forcing total number of bytes in configured packets = %0d" %
                (args.force_total_number_of_bytes_from_different_packets))
            self.total_number_of_bytes_from_different_packets = args.force_total_number_of_bytes_from_different_packets
        if (args.force_first_packet_index != 0):
            lb_note("Got force_first_packet_index != 0 -> Forcing first_packet_index = %0d" % (args.force_first_packet_index))
            self.first_packet_index = args.force_first_packet_index

        # Configure scannre
        if (args.configure_scanners):
            self.configure_npu_host_scanners(args)

    def get_supported_inject_pci_pif(self, slice_id, ifg):
        if self.ll_device.is_pacific():
            inject_pci_pif = 18
        elif self.ll_device.is_gibraltar():
            inject_pci_pif = 24
        elif self.ll_device.is_asic3():
            inject_pci_pif = 32
        else:
            inject_pci_pif = None
        return inject_pci_pif

############### USAGE EXAMPLE ##############


def main():
    LAB_PATH = (os.environ['LAB_PATH'])
    script_path = os.path.dirname(os.path.realpath(__file__))
    packet_injext_example_file = LAB_PATH + '/npu/data/packet_inject.py'
    #------------------------------------------------------
    #-------------------Get arguments----------------------
    #------------------------------------------------------
    NpuHostPacketGenArgs = NpuHostPacketGenAttribute()
    argparser = argparse.ArgumentParser(description='Npuh packet generator arguments')

    argparser.add_argument(
        '--packet-inject-file-name',
        dest='packet_inject_file_name',
        action='store',
        default=os.path.realpath(packet_injext_example_file),
        help='Source file for packet injection code. may contain also the path.')

    argparser.add_argument(
        '--configure-packets',
        dest='configure_packets',
        action='store',
        default=1,
        help='Set if configuring the packets in the npu-host tables is required (default: 1)')

    argparser.add_argument(
        '--configure-scanners',
        dest='configure_scanners',
        action='store',
        default=1,
        help='Set if configuring the npu-host scanner is required (e.g. for controlling the rate, num_of_replications..)')

    argparser.add_argument(
        '--num-of-replications',
        dest='num_of_replications',
        action='store',
        type=int,
        default=1,
        help='Number of replications for each packet. valid values are: 1-255 for specific number, 0 for endless (default: 1 (i.e. 1 replication))')

    argparser.add_argument(
        '--randomize-inject-order',
        dest='randomize_inject_order',
        action='store',
        type=int,
        default=0,
        help='If set, inject order will be random. otherwise, inject order will be in the same order as in the packet_inject file (default: 0 (i.e. not randomize)))')

    argparser.add_argument(
        '--packet-rate-type',
        dest='packet_rate_type',
        action='store',
        default="CALCULATED",
        help='May be CALCULATED/SPECIFIC/MAX (default: CALCULATED (i.e. calculate packet rate according to port-rate, percentage, clk-rate and total-packet-sizes)')

    argparser.add_argument(
        '--npuh-port-rate',
        dest='npuh_port_rate',
        action='store',
        type=int,
        default=50,
        help='Npuh Port rate in Gbps (default: 50 (i.e. 50Ghz)). Relevant only if packet_rate_type is SPECIFIC')

    argparser.add_argument(
        '--inject-percentage',
        dest='inject_percentage',
        action='store',
        type=int,
        default=99,
        help='Inject percentage out of the max port rate in accordance to npuh_port_rate (default: 99 (i.e. 99%%))')

    argparser.add_argument(
        '--clk-rate',
        dest='clk_rate',
        action='store',
        type=float,
        default=1.2,
        help='Clk rate is Ghz (default: 1.2Ghz)')

    argparser.add_argument(
        '--specific-packet-rate',
        dest='specific_packet_rate',
        action='store',
        type=int,
        default=16,
        help='default: 16 (i.e. stimulus new packet each 16 clks). Relevant only if packet_rate_type is SPECIFIC.')

    argparser.add_argument(
        '--debug',
        dest='debug_mode',
        # type=int,
        action='store_true',  # store_true/store_const/store_false: create an option that needs no value (store: get a value)
        default=0,
        help='Use for interractive mode and debug (device will not be destroyed automatically)')

    my_args = argparser.parse_args()
    my_args.packet_rate_type = PacketRateType[my_args.packet_rate_type]  # convert from string
    lb_global.debug_mode = my_args.debug_mode

    # Set npu-host packet-gen args
    NpuHostPacketGenArgs.configure_packets = my_args.configure_packets
    NpuHostPacketGenArgs.configure_scanners = my_args.configure_scanners
    NpuHostPacketGenArgs.packet_inject_file_name = my_args.packet_inject_file_name
    NpuHostPacketGenArgs.randomize_inject_order = my_args.randomize_inject_order
    NpuHostPacketGenArgs.num_of_replications = my_args.num_of_replications
    NpuHostPacketGenArgs.packet_rate_type = my_args.packet_rate_type
    NpuHostPacketGenArgs.npuh_port_rate = my_args.npuh_port_rate
    NpuHostPacketGenArgs.inject_percentage = my_args.inject_percentage
    NpuHostPacketGenArgs.clk_rate = my_args.clk_rate
    NpuHostPacketGenArgs.specific_packet_rate = my_args.specific_packet_rate

    #------------------------------------------------------
    #-------------------Create device----------------------
    #------------------------------------------------------
    # TODO: move to other place!
    device_name = '/dev/testdev'

    device, nsim = U.sim_utils.create_test_device(device_name, 1)

    lb_global.device = device
    lb_global.ll_device = device.get_ll_device()
    lb_global.tree = ll_device.get_device_tree(lb_global.ll_device)
    #------------------------------------------------------
    #------------------------------------------------------
    #------------------------------------------------------

    # Configure npu-host
    npuh_traffic_gen_config_m = npuh_traffic_gen_config_module()
    npuh_traffic_gen_config_m.config_packets_and_scanners(NpuHostPacketGenArgs)

    # Inject packets
    npuh_traffic_gen_send_m = npuh_traffic_gen_send_module()
    npuh_traffic_gen_send_m.start_npu_host_inject()
    lb_note('Injecting from npu-host. please wait...')
    time.sleep(2)
    npuh_traffic_gen_send_m.stop_npu_host_inject()
    lb_note('Done injecting from npu-host')

    # Reconfigure - only change some scanner arguments num-of-replications
    NpuHostPacketGenArgs.configure_packets = 0
    NpuHostPacketGenArgs.packet_rate_type = PacketRateType.MAX
    NpuHostPacketGenArgs.configure_scanners = 1
    NpuHostPacketGenArgs.num_of_replications = 50
    NpuHostPacketGenArgs.specific_packet_rate = 20
    npuh_traffic_gen_config_m.config_packets_and_scanners(NpuHostPacketGenArgs)

    check_log()

    U.sim_utils.destroy_device(device)

    sys.exit(0)


if __name__ == '__main__':
    main()
