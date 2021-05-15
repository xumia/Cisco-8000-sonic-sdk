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

# python imports
from collections import namedtuple
import filecmp
import functools
import importlib
import json
import os
from pathlib import Path
from prettytable import PrettyTable
import random
import tempfile
import time

# SDK imports
from leaba import sdk
import test_nsim_providercli as nsim

# SAI imports
import nsim_kernel
from saicli import *
import sai_obj_wrapper
import sai_packet_utils as U
from sai_stats_info import sai_stats_info
import sai_test_utils as st_utils


def get_test_options(request):
    st_utils.check_if_skipped(request)
    options = {}
    warmboot_option = request.config.getoption("--warmboot")
    warmboot_split = warmboot_option.split(",")
    options["wb_point"] = "point" in warmboot_split
    options["wb_topology"] = "topology" in warmboot_split
    options["wb_create"] = "create" in warmboot_split
    options["wb_init"] = request.config.getoption("--warmboot_init")
    options["wb_shutdown_count"] = int(request.config.getoption("--warmboot_shutdown_count"))
    return options


class sai_test_base():
    router_mac = "00:01:02:03:04:05";
    do_object_check = False
    do_object_print = False
    temp_config_file = None

    # debug flag for all test messages, single level (True/False)
    # We should use this flag to suppress all debugging message in test environment.
    debug_log = False
    sai_apis = {
        "ACL": SAI_API_ACL,
        "BRIDGE": SAI_API_BRIDGE,
        "BUFFER": SAI_API_BUFFER,
        "DEBUG_COUNTER": SAI_API_DEBUG_COUNTER,
        "FDB": SAI_API_FDB,
        "HASH": SAI_API_HASH,
        "HOSTIF": SAI_API_HOSTIF,
        "LAG": SAI_API_LAG,
        "MPLS": SAI_API_MPLS,
        "NEIGHBOR": SAI_API_NEIGHBOR,
        "NEXT_HOP": SAI_API_NEXT_HOP,
        "NEXT_HOP_GROUP": SAI_API_NEXT_HOP_GROUP,
        "POLICER": SAI_API_POLICER,
        "PORT": SAI_API_PORT,
        "QOS_MAP": SAI_API_QOS_MAP,
        "QUEUE": SAI_API_QUEUE,
        "ROUTER_INTERFACE": SAI_API_ROUTER_INTERFACE,
        "ROUTE": SAI_API_ROUTE,
        "SCHEDULER": SAI_API_SCHEDULER,
        "SWITCH": SAI_API_SWITCH,
        "TUNNEL": SAI_API_TUNNEL,
        "VIRTUAL_ROUTER": SAI_API_VIRTUAL_ROUTER,
        "VLAN": SAI_API_VLAN,
        "WRED": SAI_API_WRED,
        "MIRROR": SAI_API_MIRROR,
        "SAMPLEPACKET": SAI_API_SAMPLEPACKET,
        "TAM": SAI_API_TAM,
    }
    if (st_utils.is_sai_17x_or_higher()):
        sai_apis["SYSTEM_PORT"] = SAI_API_SYSTEM_PORT

    log_levels = {
        "DEBUG": SAI_LOG_LEVEL_DEBUG,
        "INFO": SAI_LOG_LEVEL_INFO,
        "NOTICE": SAI_LOG_LEVEL_NOTICE,
        "WARNING": SAI_LOG_LEVEL_WARN,
        "ERROR": SAI_LOG_LEVEL_ERROR,
        "CRITICAL": SAI_LOG_LEVEL_CRITICAL,
    }

    def object_check(type, obj_type):
        def decorator_object_check(func):
            @functools.wraps(func)
            def wrapper_object_check(*args, **kwargs):
                if not sai_test_base.do_object_check:
                    return func(*args, **kwargs)

                # compare number of objects from type, before and after create/remove, and in
                # case of create, verify the new object is in the object list
                num_objs_before, obj_list_before = sai_test_base.get_object_keys(obj_type)
                if type[0] == "c":
                    ret_obj_id = func(*args, **kwargs)
                else:
                    func(*args, **kwargs)

                num_objs_after, obj_list_after = sai_test_base.get_object_keys(obj_type)
                if type[0] == "c":
                    # sometimes, the create does not add object, just changes some attribute in it
                    if type != "create_no_count_change":
                        assert(num_objs_after == num_objs_before + 1)
                else:
                    assert(num_objs_after == num_objs_before - 1)
                    if sai_test_base.do_object_print:
                        print("Removed object: type {0} object_id {1} - {2} objects from this type exists"
                              .format(hex(obj_type), hex(args[1]), num_objs_after))
                    return

                # obj in obj_list_after does not work because obj_list_after is a swig defined object of type int_array
                obj_found = False
                for index in range(0, num_objs_after):
                    if obj_list_after[index] == ret_obj_id:
                        obj_found = True
                assert(obj_found)
                if sai_test_base.do_object_print:
                    print("Created object: type {0} object_id {1} - {2} objects from this type exists"
                          .format(hex(obj_type), hex(ret_obj_id), num_objs_after))
                return ret_obj_id
            return wrapper_object_check
        return decorator_object_check

    def __init__(self, config={}):
        self.nsim_provider = None

        self.config = {}
        self.config["wb_point"] = False
        self.config["wb_topology"] = False
        self.config["wb_create"] = False
        self.config["wb_init"] = False
        self.config["wb_shutdown_count"] = 0

        self.config.update(config)
        # SAI switch firmware path name
        self.fw_path_name = ""
        self.nsim_provider = None

        # members for all SAI objects
        self.ports = {}
        self.apis = {}
        self.bridge_ports = {}
        self.vlans = {}

        self.vlan_mem_table = PrettyTable(title="VLANs Table")
        self.vlan_mem_table.field_names = ["VLAN", "PIF", "TAG", "OUT_VLAN", "SAI_VLAN_ID", "SAI_BRIDGE_PORT_ID", "SAI_PORT_ID"]

    # To enable logging do setenv SAI_LOG_[module] level
    # for example:
    # setenv SAI_LOG_SWITCH DEBUG
    # for nsim log should do:
    # setenv ENABLE_NSIM_LOG true
    # or (for more detailed logs)
    # setenv ENABLE_NSIM_LOG full
    # for Debugging messages in Test case or environment
    # setenv SAI_LOG_TEST DEBUG
    # for SDK logs:
    # setenv SAI_LOG_SDK level
    # Currently this only affect SDK API and SDK HLD components
    # Other SDK components log level can't be configured from SAI
    # setenv SAI_LOG_ALL level will set log level for all components, including SDK
    def set_logging(self, nsim_provider):
        # For testing, we want to send logging info to screen and not to syslog
        sai_logging_param_set(False, True)
        for key in os.environ.keys():
            if key == "ENABLE_NSIM_LOG" and nsim_provider is not None:
                nsim_provider.set_logging(True)
                if os.environ["ENABLE_NSIM_LOG"].upper() == "FULL":
                    nsim_provider.set_log_level(nsim.NSIM_LOG_FULL)

                nsim_output_dir = os.getenv('SAI_NSIM_OUTPUT_DIR')
                if not nsim_output_dir:
                    nsim_output_dir = "."
                self.nsim.set_log_file(os.path.join(nsim_output_dir, "nsim_log.txt"), True)
                record_dir = os.getenv('SAI_NSIM_RECORD_DIR')
                if record_dir:
                    os.makedirs(record_dir, exist_ok=True)
                    self.nsim.set_rerun_info_folder(record_dir, True)
                continue

            if key[0:8] == "SAI_LOG_":
                module_name = key[8:]
                log_level = self.log_levels[os.environ[key].upper()]

                if module_name == "TEST":
                    self.debug_log = True if log_level is not SAI_LOG_LEVEL_INFO else False
                    continue
                elif module_name == "SDK" or module_name == "UNSPECIFIED":
                    api = SAI_API_UNSPECIFIED
                elif module_name == "ALL" or module_name == "MAX":
                    api = SAI_API_MAX
                else:
                    api = self.sai_apis[module_name]

                sai_log_set(api, log_level)

    def disable_logging(self):
        sai_logging_param_set(False, False)

    def enable_logging(self):
        sai_logging_param_set(False, True)

    def log(self, message):
        if self.debug_log:
            print(message)

    def get_apis(self):
        for key in self.sai_apis:
            self.apis[self.sai_apis[key]] = sai_api_query(self.sai_apis[key])

    def create_object(self, obj_type, args, verify=[False, False], warm_boot=False):
        if isinstance(args, dict):
            attrs = []

            for key in args:
                attrs.append([key, args[key]])
        elif isinstance(args, list):
            attrs = args
        else:
            assert False, "wrong type of args"

        return self.obj_wrapper.create_object(obj_type, self.switch_id, attrs, verify, warm_boot)

    def remove_object(self, obj_id):
        self.obj_wrapper.remove_object(obj_id)

    def set_object_attr(self, obj_id, attr, value, verify=False):
        return self.obj_wrapper.set_attr(obj_id, attr, value, verify)

    def get_object_attr(self, obj_id, attr):
        return self.obj_wrapper.get_attr(obj_id, attr)

    def do_warm_boot(self, type="wb_point"):
        # warm boot support only for gibraltar currently
        if not st_utils.is_asic_env_gibraltar():
            return

        if self.config[type] == False:
            return

        if self.config["wb_shutdown_count"] > 1:
            # in this mode, we ignore warm boot points, until the one we want to activate
            self.config["wb_shutdown_count"] -= 1
            return

        cvar.g_sai_warm_boot_type = 0  # FULL mode
        base_file_name = "./sai_warm_boot."
        before_file = base_file_name + "{0}".format("before.") + str(os.getpid())
        after_file = base_file_name + "{0}".format("after.") + str(os.getpid())
        warmboot_dump_file = "warmboot_dump." + str(os.getpid())
        st_utils.dump_obj_to_file(before_file, self)

        self.log("doing warm boot")
        # do warm boot
        self.set_object_attr(self.switch_id, SAI_SWITCH_ATTR_RESTART_WARM, True)
        time_before = time.monotonic()
        self.remove_object(self.switch_id)
        warm_boot_time = time.monotonic() - time_before
        if self.config["wb_shutdown_count"] == 1:
            self.switch_id = None
            self.obj_wrapper.set_mode("close")
            os.remove(before_file)
            # in this mode, we want to exit the process
            os._exit(0)  # bypassing pytest exit
        self.stop_kernel_thread()
        # fake warm boot for testing. Create the switch again
        cvar.g_sai_boot_type = 1
        attrs = []
        attr = sai_attribute_t(SAI_SWITCH_ATTR_SWITCH_HARDWARE_INFO, self.device_name)
        attrs.append(attr)
        self.switch_profile_id = 1
        attr = sai_attribute_t(SAI_SWITCH_ATTR_SWITCH_PROFILE_ID, self.switch_profile_id)
        attrs.append(attr)
        attrs += self.configure_notification()
        time_before = time.monotonic()
        self.apis[SAI_API_SWITCH].create_switch(attrs)
        warm_boot_time += time.monotonic() - time_before
        self.la_device = sdk.la_get_device(0)
        cvar.g_sai_boot_type = 0
        self.set_object_attr(self.switch_id, SAI_SWITCH_ATTR_RESTART_WARM, False)
        st_utils.dump_obj_to_file(after_file, self)
        if not filecmp.cmp(before_file, after_file):
            print("Error: SAI attributes before and after warm boot are different - test failed")
            os.system("diff {} {}".format(before_file, after_file))
            assert False, "SAI attributes before and after warm boot differ"
        os.remove(before_file)
        os.remove(after_file)
        if os.path.exists(warmboot_dump_file):
            os.remove(warmboot_dump_file)
        if os.path.exists(warmboot_dump_file + ".sdk"):
            os.remove(warmboot_dump_file + ".sdk")
        if os.path.exists(warmboot_dump_file + ".sai"):
            os.remove(warmboot_dump_file + ".sai")
        return warm_boot_time

    def set_queue_attr(self, queue_obj_id, attr, value):
        self.set_object_attr(queue_obj_id, attr, value)

    def get_queue_attr(self, queue_obj_id, attr_id):
        return self.get_object_attr(queue_obj_id, attr_id)

    def query_attribute_enum_values_capability(self, obj_type, attr_id):
        cap_list = int_array(1)
        count = int_array(1)
        count[0] = 0

        # first call to take the count
        try:
            swig_query_attribute_enum_values_capability(self.switch_id, obj_type, attr_id, count, cap_list)
        except BaseException:
            pass

        # now, count should be the size of the attribute list
        cap_list = int_array(count[0])
        swig_query_attribute_enum_values_capability(self.switch_id, obj_type, attr_id, count, cap_list)

        return count[0], cap_list

    def query_attribute_capability(self, obj_type, attr_id):
        res_list = []
        out = {"create": False, "set": False, "get": False}

        swig_sai_query_attribute_capability(self.switch_id, obj_type, attr_id, res_list)

        if res_list[0] == "true":
            out["create"] = True
        if res_list[1] == "true":
            out["set"] = True
        if res_list[2] == "true":
            out["get"] = True

        return out

    @object_check("create", SAI_OBJECT_TYPE_DEBUG_COUNTER)
    def create_debug_counter(self, counter_type, drop_list=[], verify=[True, False], warm_boot=False):
        attrs = []
        attrs.append([SAI_DEBUG_COUNTER_ATTR_TYPE, counter_type])

        if not isinstance(drop_list, list):
            drop_list = [drop_list]

        if len(drop_list) != 0:
            if counter_type == SAI_DEBUG_COUNTER_TYPE_SWITCH_IN_DROP_REASONS or counter_type == SAI_DEBUG_COUNTER_TYPE_PORT_IN_DROP_REASONS:
                drop_reason_type = SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST
            elif counter_type == SAI_DEBUG_COUNTER_TYPE_SWITCH_OUT_DROP_REASONS or counter_type == SAI_DEBUG_COUNTER_TYPE_PORT_IN_DROP_REASONS:
                drop_reason_type = SAI_DEBUG_COUNTER_ATTR_OUT_DROP_REASON_LIST
            attrs.append([drop_reason_type, drop_list])

        return self.obj_wrapper.create_object(SAI_OBJECT_TYPE_DEBUG_COUNTER, self.switch_id, attrs, verify, warm_boot)

    @object_check("create", SAI_OBJECT_TYPE_PORT)
    def create_port(self, port_cfg, verify=[True, False], warm_boot=False):
        '''
        port_cfg: port configuration which contains 'pif', 'pif_counts', 'speed', etc. See sai_test_utils.port_config()
        return port_obj_id, SAI port object ID.
        '''
        attrs = []
        lanes = range(port_cfg['pif'], port_cfg['pif'] + port_cfg['pif_counts'])
        attrs.append([SAI_PORT_ATTR_HW_LANE_LIST, lanes])
        attrs.append([SAI_PORT_ATTR_SPEED, port_cfg['speed']])
        attrs.append([SAI_PORT_ATTR_FEC_MODE, port_cfg['fec']])
        attrs.append([SAI_PORT_ATTR_INTERNAL_LOOPBACK_MODE, port_cfg['mac_lpbk']])
        attrs.append([SAI_PORT_ATTR_AUTO_NEG_MODE, port_cfg['an']])
        attrs.append([SAI_PORT_ATTR_ADMIN_STATE, port_cfg['admin_state']])  # Enable port
        attrs.append([SAI_PORT_ATTR_GLOBAL_FLOW_CONTROL_MODE, port_cfg['fc']])
        attrs.append([SAI_PORT_ATTR_MTU, port_cfg['mtu_size']])
        attrs.append([SAI_PORT_ATTR_MEDIA_TYPE, port_cfg['media_type']])
        if 'serdes_preemp' in port_cfg:
            attrs.append([SAI_PORT_ATTR_SERDES_PREEMPHASIS, port_cfg['serdes_preemp']])

        return self.obj_wrapper.create_object(SAI_OBJECT_TYPE_PORT, self.switch_id, attrs, verify, warm_boot)

    def set_port_admin_state(self, port_pif, enable):
        self.set_object_attr(self.ports[port_pif], SAI_PORT_ATTR_ADMIN_STATE, enable, verify=True)

    def set_all_ports_admin_state(self, enable):
        for port_pif in self.ports:
            self.set_port_admin_state(port_pif, enable)

    def is_port_up(self, port_pif):
        return is_sai_port_state_up(self.ports[port_pif])

    def link_state_check(self, port_pif, is_up=True, polls=10, msg=None):
        '''
        Blocking link state check function.
        if is_up == True, verifying that link is_up, else, verifying that link is down
        First check done immediately, then 1 sec between polls, so x polls will be done in x-1 seconds
        Assert error if link down after polls
        '''
        if msg is None:
            msg = "Failed link state check on pif {}, expected({})".format(port_pif, is_up)
        count = 1
        while count < polls:
            if self.is_port_up(port_pif) == is_up:
                return
            time.sleep(1)
            count += 1

        assert self.is_port_up(port_pif) == is_up, msg

    def get_port_state(self, port_pif):
        oper_status = self.get_object_attr(self.ports[port_pif], SAI_PORT_ATTR_OPER_STATUS)
        admin_state = self.get_object_attr(self.ports[port_pif], SAI_PORT_ATTR_ADMIN_STATE)

        return oper_status, admin_state

    def check_port_state_callback(self, port_pif):
        oper_status = self.get_object_attr(self.ports[port_pif], SAI_PORT_ATTR_OPER_STATUS)
        oper_status_up = oper_status == 1
        is_up = is_sai_port_state_up(self.ports[port_pif])
        assert is_up == oper_status_up, "is_up({}), oper_status_up({})".format(is_up, oper_status_up)

    def check_ports_state_callback(self, port_pif_list):
        for port_pif in port_pif_list:
            self.check_port_state_callback(port_pif)

    def port_state_up_msg_counts(self, port_pif):
        return get_sai_port_state_up_msg_counts(self.ports[port_pif])

    def port_state_down_msg_counts(self, port_pif):
        return get_sai_port_state_down_msg_counts(self.ports[port_pif])

    def clear_all_port_state_msg_counts(self):
        clear_all_sai_port_state_msg_counts()

    def configure_ports(self, port_cfg_list):
        for port_cfg in port_cfg_list:
            self.ports[port_cfg['pif']] = self.create_port(port_cfg)

    def remove_port(self, port_pif):
        self.set_port_admin_state(port_pif, False)
        self.remove_object(self.ports[port_pif])
        return self.ports.pop(port_pif)

    def remove_ports(self):
        '''
        Removes all ports and port's dictionary
        '''
        port_pif_list = list(self.ports.keys())
        for port_pif in port_pif_list:
            self.remove_port(port_pif)
        self.ports = {}

    def port_serdes_id(self, port_pif):
        '''
        Return SAI port_serdes object ID from ports[]
        '''
        return (self.ports[port_pif] & 0x00FF_FFFF_FFFF_FFFF) | (SAI_OBJECT_TYPE_PORT_SERDES << 56)

    @object_check("create", SAI_OBJECT_TYPE_PORT_SERDES)
    def create_port_serdes(self, args, verify=[True, False], warm_boot=False):
        '''
        args must have SAI_PORT_SERDES_ATTR_PORT_ID key and port_oid as its value.
        '''
        attrs = []

        for key in args:
            attrs.append([key, args[key]])

        return self.obj_wrapper.create_object(SAI_OBJECT_TYPE_PORT_SERDES, self.switch_id, attrs, verify, warm_boot)

    def remove_port_serdes(self, port_serdes_obj_id):
        self.remove_object(port_serdes_obj_id)

    def enable_decrement_ttl(self, port_pif):
        # this attr means disable decrement ttl, set to false means enable
        self.set_object_attr(self.ports[port_pif], SAI_PORT_ATTR_DISABLE_DECREMENT_TTL, False, verify=True)

    def disable_decrement_ttl(self, port_pif):
        # this attr means disable decrement ttl, set to false means enable
        self.set_object_attr(self.ports[port_pif], SAI_PORT_ATTR_DISABLE_DECREMENT_TTL, True, verify=True)

    def configure_router_mac(self, mac):
        return self.set_object_attr(self.switch_id, SAI_SWITCH_ATTR_SRC_MAC_ADDRESS, mac, verify=True)

    def create_inseg_entry(self, mpls_label, args=[], verify=[True, False], warm_boot=False):
        inseg_entry = sai_inseg_entry_t(self.switch_id, mpls_label)
        attrs = []

        for key in args:
            attrs.append([key, args[key]])

        self.obj_wrapper.create_object(SAI_OBJECT_TYPE_INSEG_ENTRY, inseg_entry, attrs, verify, warm_boot)
        return [SAI_OBJECT_TYPE_INSEG_ENTRY, inseg_entry]

    def remove_inseg_entry(self, mpls_label):
        inseg_entry = sai_inseg_entry_t(self.switch_id, mpls_label)
        self.remove_object([SAI_OBJECT_TYPE_INSEG_ENTRY, inseg_entry])

    def create_lag(self, label="", verify=[True, False], warm_boot=False):
        attrs = []
        attrs.append([SAI_LAG_ATTR_LABEL, label])
        return self.obj_wrapper.create_object(SAI_OBJECT_TYPE_LAG, self.switch_id, attrs)

    @object_check("remove", SAI_OBJECT_TYPE_LAG)
    def remove_lag(self, obj_id):
        return self.obj_wrapper.remove_object(obj_id)

    def get_lag_label(self, lag_id):
        return self.get_object_attr(lag_id, SAI_LAG_ATTR_LABEL)

    def set_lag_label(self, lag_id, lag_label):
        self.set_object_attr(lag_id, SAI_LAG_ATTR_LABEL, lag_label)

    def create_lag_member(self, lag_id, port_index, verify=[True, False], warm_boot=False):
        attrs = []
        attrs.append([SAI_LAG_MEMBER_ATTR_LAG_ID, lag_id])
        attrs.append([SAI_LAG_MEMBER_ATTR_PORT_ID, self.ports[port_index]])

        return self.obj_wrapper.create_object(SAI_OBJECT_TYPE_LAG_MEMBER, self.switch_id, attrs, verify, warm_boot)

    @object_check("remove", SAI_OBJECT_TYPE_LAG_MEMBER)
    def remove_lag_member(self, obj_id):
        return self.obj_wrapper.remove_object(obj_id)

    def set_lag_mem_egress_set_state(self, lag_member_id, disable):
        self.set_object_attr(lag_member_id, SAI_LAG_MEMBER_ATTR_EGRESS_DISABLE, disable, verify=True)

    def set_lag_mem_ingress_set_state(self, lag_member_id, disable):
        self.set_object_attr(lag_member_id, SAI_LAG_MEMBER_ATTR_INGRESS_DISABLE, disable, verify=True)

    def create_qos_map(self, qos_map_type, key_value_list, verify=[True, False], warm_boot=False):
        attrs = []
        attrs.append([SAI_QOS_MAP_ATTR_TYPE, qos_map_type])
        attrs.append([SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST, st_utils.sai_qos_map(qos_map_type, key_value_list)])

        return self.obj_wrapper.create_object(SAI_OBJECT_TYPE_QOS_MAP, self.switch_id, attrs, verify, warm_boot)

    @object_check("create", SAI_OBJECT_TYPE_SCHEDULER)
    def create_scheduler(self, type, weight=0, pir=0, meter_type = 1, verify=[True, False], warm_boot=False):
        attrs = []
        attrs.append([SAI_SCHEDULER_ATTR_SCHEDULING_TYPE, type])
        attrs.append([SAI_SCHEDULER_ATTR_SCHEDULING_WEIGHT, weight])
        attrs.append([SAI_SCHEDULER_ATTR_MAX_BANDWIDTH_RATE, pir])
        attrs.append([SAI_SCHEDULER_ATTR_METER_TYPE, meter_type])

        return self.obj_wrapper.create_object(SAI_OBJECT_TYPE_SCHEDULER, self.switch_id, attrs, verify, warm_boot)

    def create_virtual_router(self, vrf_mac = None, verify=[True, False], warm_boot=False):
        attrs = []
        if vrf_mac is not None:
            attrs.append([SAI_VIRTUAL_ROUTER_ATTR_SRC_MAC_ADDRESS, vrf_mac])
        return self.obj_wrapper.create_object(SAI_OBJECT_TYPE_VIRTUAL_ROUTER, self.switch_id, attrs, verify, warm_boot)

    def configure_vrfs(self, total_num):
        vrf_list = []
        for i in range(0, total_num):
            vrf_list.append(self.create_virtual_router())
        return vrf_list

    @object_check("remove", SAI_OBJECT_TYPE_VIRTUAL_ROUTER)
    def remove_virtual_router(self, obj_id):
        return self.obj_wrapper.remove_object(obj_id)

    def set_route_attribute(self, vrf_id, route_prefix, route_mask, attr_id, attr_val):
        api_addr = U.sai_ip(route_prefix)
        api_mask = U.sai_ip(route_mask)
        route_entry = sai_route_entry_t(self.switch_id, vrf_id, api_addr, api_mask)
        self.set_object_attr([SAI_OBJECT_TYPE_ROUTE_ENTRY, route_entry], attr_id, attr_val)

    # If num_of_routes != 1, adding num_of_routes consecutive routes with same parameters, except for route_prefix
    #    In this case, route prefix is increased by 2^inc_start_bit for each added route
    #    This is done for boosting performance when adding big amount of routes
    def create_route(
            self,
            vrf_id,
            route_prefix,
            route_mask,
            nh_id,
            action=None,
            user_meta=None,
            num_of_routes=1,
            inc_start_bit=1,
            verify=[
                True,
                False],
            warm_boot=False,
            bulk_operation=False):
        api_addr = U.sai_ip(route_prefix)  # v6 or v4 address
        api_mask = U.sai_ip(route_mask)  # v6 or v4 address
        route_entry = sai_route_entry_t(self.switch_id, vrf_id, api_addr, api_mask)

        attrs = []
        if nh_id is not None:
            attrs.append([SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID, nh_id])
        if action is not None:
            attrs.append([SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION, action])
        if user_meta is not None:
            # TODO skip-verify because when adding route for rif, user-meta is not programmed...
            # Check with satish for reasons why add_ipv4_subnet() does NOT take user-meta to be programmed in LPM
            attrs.append([SAI_ROUTE_ENTRY_ATTR_META_DATA, user_meta, "skip_verify"])

        if num_of_routes == 1:
            self.obj_wrapper.create_object(SAI_OBJECT_TYPE_ROUTE_ENTRY, route_entry, attrs, verify, warm_boot)
            return [SAI_OBJECT_TYPE_ROUTE_ENTRY, route_entry]
        else:
            sai_attrs = []
            for attr in attrs:
                sai_attrs.append(sai_attribute_t(attr[0], attr[1]))
            swig_test_create_route_entries(route_entry, sai_attrs, num_of_routes, inc_start_bit, bulk_operation)

    # bulk create routes
    route_entry_params_t = namedtuple('route_entry_params_t',
                                      'vrf_id, route_prefix, route_mask, nh_id, action, user_meta')

    def create_routes(self, route_entry_params_list, verify=[True, False], warm_boot=False):

        route_attr_entries = []

        for params in route_entry_params_list:
            api_addr = U.sai_ip(params.route_prefix)  # v6 or v4 address
            api_mask = U.sai_ip(params.route_mask)  # v6 or v4 address
            route_entry = sai_route_entry_t(self.switch_id, params.vrf_id, api_addr, api_mask)

            attrs = []
            if params.nh_id is not None:
                attrs.append(sai_attribute_t(SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID, params.nh_id))
            if params.action is not None:
                attrs.append(sai_attribute_t(SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION, params.action))
            if params.user_meta is not None:
                attrs.append(sai_attribute_t(SAI_ROUTE_ENTRY_ATTR_META_DATA, params.user_meta))

            route_attr_entries.append((route_entry, attrs))

        swig_create_route_entries(route_attr_entries)

    def remove_route(self, vrf_id, route_prefix, route_mask):
        addr = U.sai_ip(route_prefix)
        mask = U.sai_ip(route_mask)
        route_entry = sai_route_entry_t(self.switch_id, vrf_id, addr, mask)
        self.remove_object([SAI_OBJECT_TYPE_ROUTE_ENTRY, route_entry])

    def get_route_attribute(self, vrf_id, route_prefix, route_mask, attr_id):
        addr = U.sai_ip(route_prefix)
        mask = U.sai_ip(route_mask)
        route_entry = sai_route_entry_t(self.switch_id, vrf_id, addr, mask)
        return self.get_object_attr([SAI_OBJECT_TYPE_ROUTE_ENTRY, route_entry], attr_id)

    def create_fdb_entry(
            self,
            bv_id,
            mac,
            port_obj_id,
            user_meta=None,
            entry_type=SAI_FDB_ENTRY_TYPE_STATIC,
            verify=[
                True,
                False],
            warm_boot=False):
        '''
        bv_id: SAI vlan object ID, sai_object_id
        mac: MAC address, string
        port_obj_id: SAI Port object ID, sai_object_id
        '''
        fdb_entry = sai_fdb_entry_t(self.switch_id, U.sai_mac(mac), bv_id)

        attrs = []
        attrs.append([SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID, port_obj_id])
        if self.is_hw():
            attrs.append([SAI_FDB_ENTRY_ATTR_TYPE, entry_type])
        else:
            # for some reason we always get back SAI_FDB_ENTRY_TYPE_DYNAMIC on nsim (see below)
            attrs.append([SAI_FDB_ENTRY_ATTR_TYPE, entry_type, "skip_verify"])

        if user_meta is not None:
            attrs.append([SAI_FDB_ENTRY_ATTR_META_DATA, user_meta])

        self.obj_wrapper.create_object(SAI_OBJECT_TYPE_FDB_ENTRY, fdb_entry, attrs, verify, warm_boot)
        return [SAI_OBJECT_TYPE_FDB_ENTRY, fdb_entry]
        """
        # Ido: this was the old code. I think we need to understand why the behavior on nsim is like this
        if self.is_hw():
            assert attrs[1].value.s32 == out_attr.value.s32
        else:
            # NSIM behavior is different than HW
            assert out_attr.value.s32 == SAI_FDB_ENTRY_TYPE_DYNAMIC
        """

    def set_fdb_entry_type(self, bv_id, mac, entry_type):
        fdb_entry = sai_fdb_entry_t(self.switch_id, U.sai_mac(mac), bv_id)
        self.set_object_attr([SAI_OBJECT_TYPE_FDB_ENTRY, fdb_entry], SAI_FDB_ENTRY_ATTR_TYPE, entry_type, verify=True)

    def set_fdb_entry_port_id(self, bv_id, mac, port_obj_id):
        '''
        Set bridge_port_obj_id in fdb
        bv_id: vlan object ID for fdb entry
        mac: MAC address in string for fdb entry
        port_obj_id: SAI Port object ID
        '''
        fdb_entry = sai_fdb_entry_t(self.switch_id, U.sai_mac(mac), bv_id)
        self.set_object_attr([SAI_OBJECT_TYPE_FDB_ENTRY, fdb_entry], SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID, port_obj_id, verify=True)

    def get_fdb_entry_type(self, bv_id, mac):
        fdb_entry = sai_fdb_entry_t(self.switch_id, U.sai_mac(mac), bv_id)
        return self.set_object_attr([SAI_OBJECT_TYPE_FDB_ENTRY, fdb_entry], SAI_FDB_ENTRY_ATTR_TYPE)

    def get_fdb_entry_port_id(self, bv_id, mac):
        '''
        find and return SAI Bridge Port Object ID by FDB entry
        return bridge_port_obj_id, SAI Bridge Port Object ID
        '''
        fdb_entry = sai_fdb_entry_t(self.switch_id, U.sai_mac(mac), bv_id)
        return self.get_object_attr([SAI_OBJECT_TYPE_FDB_ENTRY, fdb_entry], SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID)

    @object_check("remove", SAI_OBJECT_TYPE_FDB_ENTRY)
    def remove_fdb_entry(self, bv_id, mac):
        fdb_entry = sai_fdb_entry_t(self.switch_id, U.sai_mac(mac), bv_id)
        self.remove_object([SAI_OBJECT_TYPE_FDB_ENTRY, fdb_entry])

    def create_neighbor(self, rif_id, ip, mac, no_host=False, user_meta=None, verify=[True, False], warm_boot=False):
        addr = U.sai_ip(ip)
        nbr = sai_neighbor_entry_t(self.switch_id, rif_id, addr)
        attrs = []
        attrs.append([SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS, mac])
        if no_host:
            attrs.append([SAI_NEIGHBOR_ENTRY_ATTR_NO_HOST_ROUTE, no_host])

        if user_meta is not None:
            attrs.append([SAI_NEIGHBOR_ENTRY_ATTR_META_DATA, user_meta])

        self.obj_wrapper.create_object(SAI_OBJECT_TYPE_NEIGHBOR_ENTRY, nbr, attrs, verify, warm_boot)
        return [SAI_OBJECT_TYPE_NEIGHBOR_ENTRY, nbr]

    def remove_neighbor(self, rif_id, ip):
        addr = U.sai_ip(ip)
        nbr = sai_neighbor_entry_t(self.switch_id, rif_id, addr)
        self.remove_object([SAI_OBJECT_TYPE_NEIGHBOR_ENTRY, nbr])

    def create_next_hop(
            self,
            ip,
            rif_id,
            nh_type=SAI_NEXT_HOP_TYPE_IP,
            label=None,
            verify=[
                True,
                False],
            warm_boot=False,
            mac_addr=None):
        attrs = []

        if nh_type == SAI_NEXT_HOP_TYPE_IP:
            attrs.append([SAI_NEXT_HOP_ATTR_TYPE, SAI_NEXT_HOP_TYPE_IP])
            attrs.append([SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID, rif_id])
        elif nh_type == SAI_NEXT_HOP_TYPE_MPLS:
            attrs.append([SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID, rif_id])
            assert(label is not None)
            if not isinstance(label, list):
                label = [label]
            attrs.append([SAI_NEXT_HOP_ATTR_TYPE, SAI_NEXT_HOP_TYPE_MPLS])
            attrs.append([SAI_NEXT_HOP_ATTR_LABELSTACK, label])
        elif nh_type == SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP:
            attrs.append([SAI_NEXT_HOP_ATTR_TUNNEL_ID, rif_id])
            attrs.append([SAI_NEXT_HOP_ATTR_TYPE, SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP])
            if mac_addr is not None:
                attrs.append([SAI_NEXT_HOP_ATTR_TUNNEL_MAC, mac_addr])

        attrs.append([SAI_NEXT_HOP_ATTR_IP, ip])

        return self.obj_wrapper.create_object(SAI_OBJECT_TYPE_NEXT_HOP, self.switch_id, attrs, verify, warm_boot)

    def create_next_hop_group_member(self, nh_group, nh, weight=1, verify=[True, False], warm_boot=False):
        attrs = []
        attrs.append([SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID, nh_group])
        attrs.append([SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID, nh])
        attrs.append([SAI_NEXT_HOP_GROUP_MEMBER_ATTR_WEIGHT, weight])
        return self.obj_wrapper.create_object(SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER, self.switch_id, attrs, verify, warm_boot)

    def configure_next_hop_group_member_weight(self, nh_group_mem_id, weight):
        self.obj_wrapper.set_attr(nh_group_mem_id, SAI_NEXT_HOP_GROUP_MEMBER_ATTR_WEIGHT, weight, verify=True)

    def create_next_hop_group(self, verify=[True, False], warm_boot=False):
        attr = [[SAI_NEXT_HOP_GROUP_ATTR_TYPE, SAI_NEXT_HOP_GROUP_TYPE_ECMP]]
        return self.obj_wrapper.create_object(SAI_OBJECT_TYPE_NEXT_HOP_GROUP, self.switch_id, attr, verify, warm_boot)

    @object_check("remove", SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER)
    def remove_next_hop_group_member(self, nhg_mem):
        self.obj_wrapper.remove_object(nhg_mem)

    @object_check("remove", SAI_OBJECT_TYPE_NEXT_HOP_GROUP)
    def remove_next_hop_group(self, nhg):
        self.obj_wrapper.remove_object(nhg)

    @object_check("remove", SAI_OBJECT_TYPE_NEXT_HOP)
    def remove_next_hop(self, nh_id):
        self.obj_wrapper.remove_object(nh_id)

    def configure_notification(self):
        attrs = []
        attrs.append(sai_attribute_t(SAI_SWITCH_ATTR_PACKET_EVENT_NOTIFY, sai_packet_event_callback))
        attrs.append(sai_attribute_t(SAI_SWITCH_ATTR_PORT_STATE_CHANGE_NOTIFY, sai_port_state_change_callback))
        attrs.append(sai_attribute_t(SAI_SWITCH_ATTR_FDB_EVENT_NOTIFY, sai_fdb_evt_callback))
        attrs.append(sai_attribute_t(SAI_SWITCH_ATTR_TAM_EVENT_NOTIFY, sai_tam_event_callback))
        attrs.append(sai_attribute_t(SAI_SWITCH_ATTR_QUEUE_PFC_DEADLOCK_NOTIFY, sai_queue_pfc_deadlock_event_callback))
        return attrs

    def setup_vrf_punt_path(self, vrf, ip_addr, ip_mask):
        self.cpu_port = self.get_object_attr(self.switch_id, SAI_SWITCH_ATTR_CPU_PORT)
        self.create_route(vrf, ip_addr, ip_mask, self.cpu_port)

    def get_trap_group(self, trap_id):
        return self.get_object_attr(trap_id, SAI_HOSTIF_TRAP_ATTR_TRAP_GROUP)

    def get_default_trap_group(self):
        return self.get_object_attr(self.switch_id, SAI_SWITCH_ATTR_DEFAULT_TRAP_GROUP)

    def set_trap_group(self, trap_id, group):
        self.set_object_attr(trap_id, SAI_HOSTIF_TRAP_ATTR_TRAP_GROUP, group, verify=True)

    def set_trap_action(self, trap_id, action):
        self.set_object_attr(trap_id, SAI_HOSTIF_TRAP_ATTR_PACKET_ACTION, action, verify=True)

    def set_trap_priority(self, trap_id, priority):
        self.set_object_attr(trap_id, SAI_HOSTIF_TRAP_ATTR_TRAP_PRIORITY, priority, verify=True)

    @object_check("remove", SAI_OBJECT_TYPE_HOSTIF_TRAP)
    def remove_trap(self, trap_id):
        return self.obj_wrapper.remove_object(trap_id)

    def create_trap(self, trap_type, action, priority=0xFFFF, group=0xFFFF, verify=[True, False], warm_boot=False):
        attrs = []
        attrs.append([SAI_HOSTIF_TRAP_ATTR_TRAP_TYPE, trap_type])
        attrs.append([SAI_HOSTIF_TRAP_ATTR_PACKET_ACTION, action])

        if priority != 0xFFFF:
            attrs.append([SAI_HOSTIF_TRAP_ATTR_TRAP_PRIORITY, priority])

        if group != 0xFFFF:
            attrs.append([SAI_HOSTIF_TRAP_ATTR_TRAP_GROUP, group])

        return self.obj_wrapper.create_object(SAI_OBJECT_TYPE_HOSTIF_TRAP, self.switch_id, attrs, verify, warm_boot)

    def get_queue_list(self, port_obj_id):
        '''
        port_obj_id: SAI Port object ID (sai_object_id)
        '''
        queue_list = sai_object_list_t([0])
        lst = sai_attribute_t(SAI_PORT_ATTR_QOS_QUEUE_LIST, queue_list)
        with st_utils.expect_sai_error(SAI_STATUS_BUFFER_OVERFLOW):
            self.apis[SAI_API_PORT].get_port_attribute(port_obj_id, 1, lst)

        attr = sai_attribute_t(SAI_PORT_ATTR_QOS_NUMBER_OF_QUEUES, 0)
        self.apis[SAI_API_PORT].get_port_attribute(port_obj_id, 1, attr)

        assert(lst.value.objlist.count == attr.value.u32)

        queue_list = sai_object_list_t([0] * attr.value.u32)
        attr = sai_attribute_t(SAI_PORT_ATTR_QOS_QUEUE_LIST, queue_list)
        self.apis[SAI_API_PORT].get_port_attribute(port_obj_id, 1, attr)

        return queue_list

    def switch_get_clear_helper(self, counters_idx_list, counter_type):
        if not isinstance(counters_idx_list, list):
            counters_idx_list = [counters_idx]

        if counter_type == SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST:
            range_base = SAI_SWITCH_STAT_IN_DROP_REASON_RANGE_BASE
        elif conter_type == SAI_DEBUG_COUNTER_ATTR_OUT_DROP_REASON_LIST:
            range_base = SAI_SWITCH_STAT_OUT_DROP_REASON_RANGE_BASE
        else:
            raise

        counter_ids = switchStatVec(len(counters_idx_list))
        for i in range(len(counters_idx_list)):
            counter_ids[i] = counters_idx_list[i] + range_base

        return counter_ids

    def clear_switch_stats(self, counters_idx_list, counter_type):
        counter_ids = self.switch_get_clear_helper(counters_idx_list, counter_type)

        self.apis[SAI_API_SWITCH].clear_switch_stats(self.switch_id, counter_ids)

    def get_switch_stats(self, counters_idx_list, counter_type, clear=False):
        if clear:
            mode = SAI_STATS_MODE_READ_AND_CLEAR
        else:
            mode = SAI_STATS_MODE_READ

        if not isinstance(counters_idx_list, list):
            counters_idx_list = [counters_idx_list]

        counter_ids = self.switch_get_clear_helper(counters_idx_list, counter_type)
        return getSwitchCountersExt(self.switch_id, counter_ids, mode)

    def port_get_clear_helper(self, counters_idx_list, counter_type):
        if not isinstance(counters_idx_list, list):
            counters_idx_list = [counters_idx]

        if counter_type == SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST:
            range_base = SAI_PORT_STAT_IN_DROP_REASON_RANGE_BASE
        elif conter_type == SAI_DEBUG_COUNTER_ATTR_OUT_DROP_REASON_LIST:
            range_base = SAI_PORT_STAT_OUT_DROP_REASON_RANGE_BASE
        else:
            raise

        counter_ids = portStatVec(len(counters_idx_list))
        for i in range(len(counters_idx_list)):
            counter_ids[i] = counters_idx_list[i] + range_base

        return counter_ids

    def get_port_stats_debug_counter(self, port_obj_id, counters_idx_list, counter_type, clear=False):
        if clear:
            mode = SAI_STATS_MODE_READ_AND_CLEAR
        else:
            mode = SAI_STATS_MODE_READ

        if not isinstance(counters_idx_list, list):
            counters_idx_list = [counters_idx_list]

        counter_ids = self.port_get_clear_helper(counters_idx_list, counter_type)
        return getPortCountersExt(port_obj_id, counter_ids, mode)

    def get_port_stats(self, port_obj_id, clear=False):
        portIds = portStatVec(63)

        portIds[0] = SAI_PORT_STAT_ETHER_STATS_RX_NO_ERRORS
        portIds[1] = SAI_PORT_STAT_ETHER_STATS_TX_NO_ERRORS
        portIds[2] = SAI_PORT_STAT_ETHER_IN_PKTS_64_OCTETS
        portIds[3] = SAI_PORT_STAT_ETHER_IN_PKTS_65_TO_127_OCTETS
        portIds[4] = SAI_PORT_STAT_ETHER_IN_PKTS_128_TO_255_OCTETS
        portIds[5] = SAI_PORT_STAT_ETHER_IN_PKTS_256_TO_511_OCTETS
        portIds[6] = SAI_PORT_STAT_ETHER_IN_PKTS_512_TO_1023_OCTETS
        portIds[7] = SAI_PORT_STAT_ETHER_IN_PKTS_1024_TO_1518_OCTETS
        portIds[8] = SAI_PORT_STAT_ETHER_IN_PKTS_1519_TO_2047_OCTETS
        portIds[9] = SAI_PORT_STAT_ETHER_OUT_PKTS_64_OCTETS
        portIds[10] = SAI_PORT_STAT_ETHER_OUT_PKTS_65_TO_127_OCTETS
        portIds[11] = SAI_PORT_STAT_ETHER_OUT_PKTS_128_TO_255_OCTETS
        portIds[12] = SAI_PORT_STAT_ETHER_OUT_PKTS_256_TO_511_OCTETS
        portIds[13] = SAI_PORT_STAT_ETHER_OUT_PKTS_512_TO_1023_OCTETS
        portIds[14] = SAI_PORT_STAT_ETHER_OUT_PKTS_1024_TO_1518_OCTETS
        portIds[15] = SAI_PORT_STAT_ETHER_OUT_PKTS_1519_TO_2047_OCTETS
        portIds[16] = SAI_PORT_STAT_PAUSE_RX_PKTS
        portIds[17] = SAI_PORT_STAT_PAUSE_TX_PKTS
        portIds[18] = SAI_PORT_STAT_IF_IN_OCTETS
        portIds[19] = SAI_PORT_STAT_IF_IN_ERRORS
        portIds[20] = SAI_PORT_STAT_IF_OUT_OCTETS
        portIds[21] = SAI_PORT_STAT_IF_OUT_ERRORS
        portIds[22] = SAI_PORT_STAT_ETHER_STATS_UNDERSIZE_PKTS
        portIds[23] = SAI_PORT_STAT_ETHER_STATS_OVERSIZE_PKTS
        portIds[24] = SAI_PORT_STAT_ETHER_RX_OVERSIZE_PKTS
        portIds[25] = SAI_PORT_STAT_ETHER_STATS_CRC_ALIGN_ERRORS

        portIds[26] = SAI_PORT_STAT_IF_IN_UCAST_PKTS
        portIds[27] = SAI_PORT_STAT_IF_OUT_UCAST_PKTS

        portIds[28] = SAI_PORT_STAT_IF_IN_BROADCAST_PKTS
        portIds[29] = SAI_PORT_STAT_IF_IN_MULTICAST_PKTS
        portIds[30] = SAI_PORT_STAT_IF_IN_NON_UCAST_PKTS
        portIds[31] = SAI_PORT_STAT_IF_OUT_BROADCAST_PKTS
        portIds[32] = SAI_PORT_STAT_IF_OUT_MULTICAST_PKTS
        portIds[33] = SAI_PORT_STAT_IF_OUT_NON_UCAST_PKTS
        portIds[34] = SAI_PORT_STAT_IF_IN_DISCARDS
        portIds[35] = SAI_PORT_STAT_IF_OUT_DISCARDS
        portIds[36] = SAI_PORT_STAT_ECN_MARKED_PACKETS

        portIds[37] = SAI_PORT_STAT_PFC_0_RX_PKTS
        portIds[38] = SAI_PORT_STAT_PFC_0_TX_PKTS
        portIds[39] = SAI_PORT_STAT_PFC_1_RX_PKTS
        portIds[40] = SAI_PORT_STAT_PFC_1_TX_PKTS
        portIds[41] = SAI_PORT_STAT_PFC_2_RX_PKTS
        portIds[42] = SAI_PORT_STAT_PFC_2_TX_PKTS
        portIds[43] = SAI_PORT_STAT_PFC_3_RX_PKTS
        portIds[44] = SAI_PORT_STAT_PFC_3_TX_PKTS
        portIds[45] = SAI_PORT_STAT_PFC_4_RX_PKTS
        portIds[46] = SAI_PORT_STAT_PFC_4_TX_PKTS
        portIds[47] = SAI_PORT_STAT_PFC_5_RX_PKTS
        portIds[48] = SAI_PORT_STAT_PFC_5_TX_PKTS
        portIds[49] = SAI_PORT_STAT_PFC_6_RX_PKTS
        portIds[50] = SAI_PORT_STAT_PFC_6_TX_PKTS
        portIds[51] = SAI_PORT_STAT_PFC_7_RX_PKTS
        portIds[52] = SAI_PORT_STAT_PFC_7_TX_PKTS

        portIds[53] = SAI_PORT_STAT_PFC_0_TX_PAUSE_DURATION
        portIds[54] = SAI_PORT_STAT_PFC_1_TX_PAUSE_DURATION
        portIds[55] = SAI_PORT_STAT_PFC_2_TX_PAUSE_DURATION
        portIds[56] = SAI_PORT_STAT_PFC_3_TX_PAUSE_DURATION
        portIds[57] = SAI_PORT_STAT_PFC_4_TX_PAUSE_DURATION
        portIds[58] = SAI_PORT_STAT_PFC_5_TX_PAUSE_DURATION
        portIds[59] = SAI_PORT_STAT_PFC_6_TX_PAUSE_DURATION
        portIds[60] = SAI_PORT_STAT_PFC_7_TX_PAUSE_DURATION

        portIds[61] = SAI_PORT_STAT_WRED_DROPPED_PACKETS
        portIds[62] = SAI_PORT_STAT_WRED_DROPPED_BYTES

        mode = SAI_STATS_MODE_READ_AND_CLEAR if clear else SAI_STATS_MODE_READ
        counters = getPortCountersExt(port_obj_id, portIds, mode)

        assert counters[26] == counters[0]
        assert counters[27] == counters[1]
        assert counters[28] == 0
        assert counters[29] == 0
        assert counters[30] == 0
        assert counters[31] == 0
        assert counters[32] == 0
        assert counters[33] == 0

        return counters

    def dump_port_stats(self, portvec):
        if portvec[0] != 0:
            print("mac_counters.ether_stats_rx_no_errors {}" .format(portvec[0]))
        if portvec[18] != 0:
            print(" mac_counters.if_in_octets {}" .format(portvec[18]))
        if portvec[19] != 0:
            print(" mac_counters.if_in_errors {}" .format(portvec[19]))
        if portvec[2] != 0:
            print(" mac_counters.ether_in_pkts_64_octets {}" .format(portvec[2]))
        if portvec[3] != 0:
            print(" mac_counters.ether_in_pkts_65_to_127_octets {}" .format(portvec[3]))
        if portvec[4] != 0:
            print(" mac_counters.ether_in_pkts_128_to_255_octets {}" .format(portvec[4]))
        if portvec[5] != 0:
            print(" mac_counters.ether_in_pkts_256_to_511_octets {}" .format(portvec[5]))
        if portvec[6] != 0:
            print(" mac_counters.ether_in_pkts_512_to_1023_octets {}" .format(portvec[6]))
        if portvec[7] != 0:
            print(" mac_counters.ether_in_pkts_1024_to_1518_octets {}" .format(portvec[7]))
        if portvec[8] != 0:
            print(" mac_counters.ether_in_pkts_1519_to_2047_octets {}" .format(portvec[8]))
        if portvec[16] != 0:
            print(" mac_counters.pause_rx_pkts {}" .format(portvec[16]))
        if portvec[22] != 0:
            print(" mac_counters.ether_stats_undersize_pkts {}" .format(portvec[22]))
        if portvec[23] != 0:
            print(" mac_counters.ether_stats_oversize_pkts {}" .format(portvec[23]))
        if portvec[24] != 0:
            print(" mac_counters.ether_rx_oversize_pkts {}" .format(portvec[24]))
        if portvec[25] != 0:
            print(" mac_counters.ether_stats_crc_align_errors {}" .format(portvec[25]))

        if portvec[1] != 0:
            print(" mac_counters.ether_stats_tx_no_errors {}" .format(portvec[1]))
        if portvec[20] != 0:
            print(" mac_counters.if_out_octets {}" .format(portvec[20]))
        if portvec[21] != 0:
            print(" mac_counters.if_out_errors {}" .format(portvec[21]))
        if portvec[9] != 0:
            print(" mac_counters.ether_out_pkts_64_octets {}" .format(portvec[9]))
        if portvec[10] != 0:
            print(" mac_counters.ether_out_pkts_65_to_127_octets {}" .format(portvec[10]))
        if portvec[11] != 0:
            print(" mac_counters.ether_out_pkts_128_to_255_octets {}" .format(portvec[11]))
        if portvec[12] != 0:
            print(" mac_counters.ether_out_pkts_256_to_511_octets {}" .format(portvec[12]))
        if portvec[13] != 0:
            print(" mac_counters.ether_out_pkts_512_to_1023_octets {}" .format(portvec[13]))
        if portvec[14] != 0:
            print(" mac_counters.ether_out_pkts_1024_to_1518_octets {}" .format(portvec[14]))
        if portvec[15] != 0:
            print(" mac_counters.ether_out_pkts_1519_to_2047_octets {}" .format(portvec[15]))
        if portvec[17] != 0:
            print(" mac_counters.pause_tx_pkts {}" .format(portvec[17]))

    def obj_type_from_id(self, obj_id):
        return obj_id >> 56  # 8 msbs of obj_id are the obj_type

    def get_obj_stats_info(self, obj_id):
        obj_type = self.obj_type_from_id(obj_id)
        return sai_stats_info[obj_type]["stat_ids"], sai_stats_info[obj_type]["get_func"], sai_stats_info[obj_type]["stat_vec"]

    def get_obj_stats(self, obj_id, stat_ids=[], dump=False):
        all_stat_ids, get_func, stat_vec_name = self.get_obj_stats_info(obj_id)
        if stat_ids == []:
            for key in all_stat_ids.keys():
                stat_ids.append(key)

        stat_vec = eval("{}(len(stat_ids))".format(stat_vec_name))
        for i in range(len(stat_ids)):
            stat_vec[i] = stat_ids[i]
        res_stat_vec = eval("{}(obj_id, stat_vec)".format(get_func))

        res_dict = {}
        for i in range(len(stat_ids)):
            res_dict[stat_ids[i]] = res_stat_vec[i]

        if dump:
            print("*** stats for obj_id {} ***".format(hex(obj_id)))
            for i in range(len(stat_ids)):
                key = stat_ids[i]
                print("  {}: {}".format(all_stat_ids[key], res_stat_vec[i]))

        return res_dict

    def get_router_interface_stats(self, obj_id, stat_ids=[], dump=False):
        assert self.obj_type_from_id(obj_id) == SAI_OBJECT_TYPE_ROUTER_INTERFACE
        return self.get_obj_stats(obj_id, stat_ids, dump)

    def get_egress_port_stats(self, port_obj_id):
        portIds = portStatVec(2)
        portIds[0] = SAI_PORT_STAT_ETHER_STATS_TX_NO_ERRORS
        portIds[1] = SAI_PORT_STAT_IF_OUT_OCTETS
        counters = getPortCounters(port_obj_id, portIds)

    def get_egress_bridge_port_stats(self, bridge_port_obj_id):
        bportIds = bridgePortStatVec(2)
        bportIds[0] = SAI_BRIDGE_PORT_STAT_OUT_PACKETS
        bportIds[1] = SAI_BRIDGE_PORT_STAT_OUT_OCTETS
        return getBridgePortCounters(bridge_port_obj_id, bportIds)

    def get_ingress_bridge_port_stats(self, bridge_port_obj_id):
        bportIds = bridgePortStatVec(2)
        bportIds[0] = SAI_BRIDGE_PORT_STAT_IN_PACKETS
        bportIds[1] = SAI_BRIDGE_PORT_STAT_IN_OCTETS
        return getBridgePortCounters(bridge_port_obj_id, bportIds)

    def get_queue_stats(self, queue_id):
        queueIds = queueStatVec(6)
        queueIds[0] = SAI_QUEUE_STAT_PACKETS
        queueIds[1] = SAI_QUEUE_STAT_BYTES
        queueIds[2] = SAI_QUEUE_STAT_DROPPED_PACKETS
        queueIds[3] = SAI_QUEUE_STAT_DROPPED_BYTES
        queueIds[4] = SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES
        queueIds[5] = SAI_QUEUE_STAT_WATERMARK_BYTES
        return getQueueCounters(queue_id, queueIds)

    def get_policer_stats(self, policer_id):
        policerIds = policerStatVec(6)
        policerIds[0] = SAI_POLICER_STAT_GREEN_PACKETS
        policerIds[1] = SAI_POLICER_STAT_GREEN_BYTES
        policerIds[2] = SAI_POLICER_STAT_YELLOW_PACKETS
        policerIds[3] = SAI_POLICER_STAT_YELLOW_BYTES
        policerIds[4] = SAI_POLICER_STAT_RED_PACKETS
        policerIds[5] = SAI_POLICER_STAT_RED_BYTES
        return getPolicerCounters(policer_id, policerIds)

    def get_buffer_pool_stats(self, buffer_pool_id):
        bufferPoolIds = bufferPoolStatVec(2)
        bufferPoolIds[0] = SAI_BUFFER_POOL_STAT_WATERMARK_BYTES
        bufferPoolIds[1] = SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES
        return getBufferPoolCounters(buffer_pool_id, bufferPoolIds)

    def set_trap_group_queue(self, trap_group_id, queue_id):
        self.set_object_attr(trap_group_id, SAI_HOSTIF_TRAP_GROUP_ATTR_QUEUE, queue_id, verify=True)

    def set_trap_group_policer(self, trap_group_id, policer_id):
        self.set_object_attr(trap_group_id, SAI_HOSTIF_TRAP_GROUP_ATTR_POLICER, policer_id, verify=True)

    def create_policer(self, args, verify=[True, False], warm_boot=False):
        return self.create_object(SAI_OBJECT_TYPE_POLICER, args, verify, warm_boot)

    @object_check("remove", SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP)
    def remove_trap_group(self, trap_group_id):
        return self.obj_wrapper.remove_object(trap_group_id)

    def create_trap_group(self, queue_index=0xFFFF, verify=[True, False], warm_boot=False):
        attrs = []

        if queue_index != 0xFFFF:
            attrs.append([SAI_HOSTIF_TRAP_GROUP_ATTR_QUEUE, queue_index])
        return self.obj_wrapper.create_object(SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP, self.switch_id, attrs, verify, warm_boot)

    def create_router_interface(
            self,
            vrf_id=None,
            port_index=0,
            rif_type=SAI_ROUTER_INTERFACE_TYPE_LOOPBACK,
            mac_addr=None,
            vlan=None,
            out_tag_vlan=None, no_mac_addr = False, verify=[True, False], warm_boot=False):
        attrs = []

        if vrf_id is not None:
            attrs.append([SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID, vrf_id])

        attrs.append([SAI_ROUTER_INTERFACE_ATTR_TYPE, rif_type])

        if (rif_type == SAI_ROUTER_INTERFACE_TYPE_PORT or rif_type == SAI_ROUTER_INTERFACE_TYPE_SUB_PORT):
            attrs.append([SAI_ROUTER_INTERFACE_ATTR_PORT_ID, self.ports[port_index]])
            if (vlan is not None and rif_type == SAI_ROUTER_INTERFACE_TYPE_SUB_PORT):
                attrs.append([SAI_ROUTER_INTERFACE_ATTR_OUTER_VLAN_ID, vlan])
        else:
            if vlan is not None:
                attrs.append([SAI_ROUTER_INTERFACE_ATTR_VLAN_ID, self.vlans[vlan]])

        if (rif_type == SAI_ROUTER_INTERFACE_TYPE_PORT or rif_type == SAI_ROUTER_INTERFACE_TYPE_VLAN) and not no_mac_addr:
            if mac_addr is None:
                mac_str = self.router_mac
            else:
                mac_str = mac_addr
            attrs.append([SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS, mac_str])

        if out_tag_vlan is not None:
            # get not implemented for below yet
            attrs.append([SAI_ROUTER_INTERFACE_ATTR_EXT_EGR_DOT1Q_TAG_VLAN, out_tag_vlan, "skip_verify"])

        return self.obj_wrapper.create_object(SAI_OBJECT_TYPE_ROUTER_INTERFACE, self.switch_id, attrs, verify, warm_boot)

    @object_check("remove", SAI_OBJECT_TYPE_ROUTER_INTERFACE)
    def remove_router_interface(self, obj_id):
        return self.obj_wrapper.remove_object(obj_id)

    def set_mtu_router_interface(self, rif_id, mtu):
        self.set_object_attr(rif_id, SAI_ROUTER_INTERFACE_ATTR_MTU, mtu)
        out_mtu = self.get_object_attr(rif_id, SAI_ROUTER_INTERFACE_ATTR_MTU)

        if mtu != out_mtu:
            print("Error: mtu get value is {0} and set mtu is {1}" .format(out_mtu, mtu))

    def create_bridge(self, type="1q", verify=[True, False], warm_boot=False):
        if type == "1q":
            return self.get_object_attr(self.switch_id, SAI_SWITCH_ATTR_DEFAULT_1Q_BRIDGE_ID)
        else:
            assert(type == "1d")
            attr = [[SAI_BRIDGE_ATTR_TYPE, SAI_BRIDGE_TYPE_1D]]
            return self.obj_wrapper.create_object(SAI_OBJECT_TYPE_BRIDGE, self.switch_id, attr, verify, warm_boot)

    @object_check("remove", SAI_OBJECT_TYPE_BRIDGE)
    def remove_bridge(self, obj_id):
        if obj_id != self.get_object_attr(self.switch_id, SAI_SWITCH_ATTR_DEFAULT_1Q_BRIDGE_ID):
            self.remove_object(obj_id)

    def create_bridge_port(self, port_num, verify=[True, False], warm_boot=False):
        attrs = []
        attrs.append([SAI_BRIDGE_PORT_ATTR_TYPE, SAI_BRIDGE_PORT_TYPE_PORT])
        if port_num in self.ports:
            attrs.append([SAI_BRIDGE_PORT_ATTR_PORT_ID, self.ports[port_num]])
        else:
            attrs.append([SAI_BRIDGE_PORT_ATTR_PORT_ID, port_num])

        self.bridge_ports[port_num] = self.obj_wrapper.create_object(
            SAI_OBJECT_TYPE_BRIDGE_PORT, self.switch_id, attrs, verify, warm_boot)
        return self.bridge_ports[port_num]

    @object_check("remove", SAI_OBJECT_TYPE_BRIDGE_PORT)
    def remove_bridge_port(self, obj_id):
        self.obj_wrapper.remove_object(obj_id)

    def configure_bridge_ports(self, ports):
        for port in ports:
            self.create_bridge_port(port)

    def deconfigure_bridge_ports(self):
        for bport in self.bridge_ports.keys():
            self.obj_wrapper.remove_object(self.bridge_ports[bport])
        self.bridge_ports = {}

    def set_bridge_attr(self, bridge_obj_id, attr, value):
        self.set_object_attr(bridge_obj_id, attr, value)

    def get_bridge_attr(self, bridge_obj_id, attr):
        return self.get_object_attr(bridge_obj_id, attr)

    def set_bridge_port_attr(self, bridge_port_obj_id, attr, value):
        self.set_object_attr(bridge_port_obj_id, attr, value)

    def get_bridge_port_attr(self, bridge_port_obj_id, attr):
        return self.get_object_attr(bridge_port_obj_id, attr)

    def create_vlan(self, vlan_id, verify=[True, False], warm_boot=False):
        attr = [[SAI_VLAN_ATTR_VLAN_ID, vlan_id]]

        return self.obj_wrapper.create_object(SAI_OBJECT_TYPE_VLAN, self.switch_id, attr, verify, warm_boot)

    @object_check("remove", SAI_OBJECT_TYPE_VLAN)
    def remove_vlan(self, obj_id):
        self.obj_wrapper.remove_object(obj_id)

    def configure_vlans(self, vlan_ids):
        for vlan_id in vlan_ids:
            self.vlans[vlan_id] = self.create_vlan(vlan_id)

    def deconfigure_vlans(self):
        for key in self.vlans.keys():
            self.remove_vlan(self.vlans[key])

    def create_vlan_member(
            self,
            vlan_obj_id,
            bridge_port_obj_id,
            is_tag=False,
            out_tag_vlan=None,
            verify=[
                True,
                False],
            warm_boot=False):
        attrs = []
        attrs.append([SAI_VLAN_MEMBER_ATTR_VLAN_ID, vlan_obj_id])
        attrs.append([SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID, bridge_port_obj_id])

        if is_tag:
            tag_mode = SAI_VLAN_TAGGING_MODE_TAGGED
        else:
            tag_mode = SAI_VLAN_TAGGING_MODE_UNTAGGED
        # get not implemented for below yet
        attrs.append([SAI_VLAN_MEMBER_ATTR_VLAN_TAGGING_MODE, tag_mode, "skip_verify"])

        if out_tag_vlan is not None:
            attrs.append([SAI_VLAN_MEMBER_ATTR_EXT_EGR_DOT1Q_TAG_VLAN, out_tag_vlan])

        return self.obj_wrapper.create_object(SAI_OBJECT_TYPE_VLAN_MEMBER, self.switch_id, attrs, verify, warm_boot)

    # @object_check("remove", SAI_OBJECT_TYPE_VLAN_MEMBER)
    # vlan member not removed when we remove it. The bridge port becomes member in default vlan.
    def remove_vlan_member(self, obj_id):
        self.obj_wrapper.remove_object(obj_id)

    def configure_vlan_members(self, vlan_members):
        new_obj_ids = []
        for vlan_member in vlan_members:
            if 'is_tag' not in vlan_member:
                vlan_member['is_tag'] = False
            if 'out_tag_vlan' not in vlan_member:
                vlan_member['out_tag_vlan'] = None
            vlan_obj_id = self.create_vlan_member(self.vlans[vlan_member["vlan"]],
                                                  self.bridge_ports[vlan_member["port"]],
                                                  vlan_member["is_tag"],
                                                  vlan_member["out_tag_vlan"])

            new_obj_ids.append(vlan_obj_id)

            port = vlan_member["port"]
            if port in self.ports:
                port = self.ports[port]
                if not vlan_member["is_tag"]:
                    self.set_object_attr(port, SAI_PORT_ATTR_PORT_VLAN_ID, vlan_member["vlan"])
            else:
                if not vlan_member["is_tag"]:
                    self.set_object_attr(port, SAI_LAG_ATTR_PORT_VLAN_ID, vlan_member["vlan"])

            self.vlan_mem_table.add_row([vlan_member["vlan"],
                                         hex(vlan_member["port"]),
                                         vlan_member["is_tag"],
                                         vlan_member["out_tag_vlan"],
                                         hex(vlan_member["vlan"]),
                                         hex(self.bridge_ports[vlan_member["port"]]),
                                         hex(port)])

        return new_obj_ids

    def deconfigure_vlan_members(self):
        num_obj_ids, obj_ids = self.get_object_keys(SAI_OBJECT_TYPE_VLAN_MEMBER)
        for index in range(0, num_obj_ids):
            self.remove_vlan_member(obj_ids[index])

    def create_wred(self, args, verify=[True, False], warm_boot=False):
        return self.create_object(SAI_OBJECT_TYPE_WRED, args, verify, warm_boot)

    def create_hostif(
            self,
            type=SAI_HOSTIF_TYPE_NETDEV,
            obj_id=SAI_OBJECT_TYPE_VLAN,
            name="TestEth0",
            mcgrp=None,
            verify=[
                True,
                False],
            warm_boot=False):
        attrs = []
        attrs.append([SAI_HOSTIF_ATTR_TYPE, type])
        if obj_id is not None:
            attrs.append([SAI_HOSTIF_ATTR_OBJ_ID, obj_id])
        attrs.append([SAI_HOSTIF_ATTR_NAME, name])
        if mcgrp is not None:
            attrs.append([SAI_HOSTIF_ATTR_GENETLINK_MCGRP_NAME, mcgrp])
        if not self.is_hw():
            return self.obj_wrapper.create_object(SAI_OBJECT_TYPE_HOSTIF, self.switch_id, attrs, verify, warm_boot)
        else:
            # todo: fix
            return SAI_OBJECT_TYPE_NULL

    @object_check("remove", SAI_OBJECT_TYPE_HOSTIF)
    def remove_hostif(self, hostif_id):
        self.obj_wrapper.remove_object(hostif_id)

    def create_hostif_table_entry(
            self,
            entry_type,
            port_id,
            trap_id,
            action_channel,
            hostif=None,
            verify=[
                True,
                False],
            warm_boot=False):
        attrs = []
        attrs.append([SAI_HOSTIF_TABLE_ENTRY_ATTR_TYPE, entry_type])
        if port_id is not None:
            attrs.append([SAI_HOSTIF_TABLE_ENTRY_ATTR_OBJ_ID, port_id])
        attrs.append([SAI_HOSTIF_TABLE_ENTRY_ATTR_TRAP_ID, trap_id])
        attrs.append([SAI_HOSTIF_TABLE_ENTRY_ATTR_CHANNEL_TYPE, action_channel])
        if hostif is not None:
            attrs.append([SAI_HOSTIF_TABLE_ENTRY_ATTR_HOST_IF, hostif])
        return self.obj_wrapper.create_object(SAI_OBJECT_TYPE_HOSTIF_TABLE_ENTRY, self.switch_id, attrs, verify, warm_boot)

    @object_check("remove", SAI_OBJECT_TYPE_HOSTIF_TABLE_ENTRY)
    def remove_hostif_table_entry(self, hostif_table_entry_id):
        self.obj_wrapper.remove_object(hostif_table_entry_id)

    def set_switch_attribute(self, attr, value):
        self.set_object_attr(self.switch_id, attr, value)

    def get_switch_attribute(self, attr_name):
        return self.get_object_attr(self.switch_id, attr_name)

    def get_qos_map_attribute(self, qos_map_id, attr_name, attr_init_val):
        attr = sai_attribute_t(attr_name, attr_init_val)
        self.apis[SAI_API_QOS_MAP].get_qos_map_attribute(qos_map_id, 1, attr)
        return attr

    # need to be class object for the object_check decorator
    @classmethod
    def get_object_keys(cls, type, do_overflow_test=False):
        count = sai_get_object_count(cls.switch_id, type)

        if count == 0:
            return 0, []

        if type is SAI_OBJECT_TYPE_FDB_ENTRY:
            obj_fdblist = fdb_entry_array(count)
        elif type is SAI_OBJECT_TYPE_ROUTE_ENTRY:
            obj_routelist = route_entry_array(count)
        elif type is SAI_OBJECT_TYPE_NEIGHBOR_ENTRY:
            obj_neighborlist = neighbor_entry_array(count)
        else:
            obj_listint = int_array(count)

        if(do_overflow_test):
            overflow_test_count = count - 1
            if type is SAI_OBJECT_TYPE_FDB_ENTRY:
                overflow_obj_fdblist = fdb_entry_array(count)
            elif type is SAI_OBJECT_TYPE_ROUTE_ENTRY:
                overflow_obj_routelist = route_entry_array(count)
            elif type is SAI_OBJECT_TYPE_NEIGHBOR_ENTRY:
                overflow_obj_neighborlist = neighbor_entry_array(count)
            else:
                overflow_obj_listint = int_array(overflow_test_count)
            with st_utils.expect_sai_error(SAI_STATUS_BUFFER_OVERFLOW):
                if type is SAI_OBJECT_TYPE_FDB_ENTRY:
                    overflow_test_count = sai_get_object_key(cls.switch_id, type, overflow_test_count, overflow_obj_fdblist)
                elif type is SAI_OBJECT_TYPE_ROUTE_ENTRY:
                    overflow_test_count = sai_get_object_key(cls.switch_id, type, overflow_test_count, overflow_obj_routelist)
                elif type is SAI_OBJECT_TYPE_NEIGHBOR_ENTRY:
                    overflow_test_count = sai_get_object_key(cls.switch_id, type, overflow_test_count, overflow_obj_neighborlist)
                else:
                    overflow_test_count = sai_get_object_key(cls.switch_id, type, overflow_test_count, overflow_obj_listint)
                assert(overflow_test_count == count)

        if count != 0:
            if type is SAI_OBJECT_TYPE_FDB_ENTRY:
                sai_get_object_key(cls.switch_id, type, count, obj_fdblist)
                return count, obj_fdblist
            elif type is SAI_OBJECT_TYPE_ROUTE_ENTRY:
                # on load test we crash here because of Python/swig overhead
                if count < 100:
                    sai_get_object_key(cls.switch_id, type, count, obj_routelist)
                    return count, obj_routelist
                else:
                    return 0, []
            elif type is SAI_OBJECT_TYPE_NEIGHBOR_ENTRY:
                sai_get_object_key(cls.switch_id, type, count, obj_neighborlist)
                return count, obj_neighborlist
            else:
                sai_get_object_key(cls.switch_id, type, count, obj_listint)
                return count, obj_listint
        else:
            return 0, []

    def inject_packet_up(self, pkt):
        attrs = []

        attrs.append(sai_attribute_t(SAI_HOSTIF_PACKET_ATTR_HOSTIF_TX_TYPE, SAI_HOSTIF_TX_TYPE_PIPELINE_LOOKUP))
        hex_pkt = U.scapy_to_hex(pkt)

        self.la_device.flush()
        self.apis[SAI_API_HOSTIF].send_hostif_packet_wrapper(self.switch_id, len(hex_pkt), hex_pkt, attrs)

    def inject_packet_down(self, pkt, out_port, queue_index=0):
        attrs = []

        attr = sai_attribute_t(SAI_HOSTIF_PACKET_ATTR_HOSTIF_TX_TYPE, SAI_HOSTIF_TX_TYPE_PIPELINE_BYPASS)
        attrs.append(attr)

        attr = sai_attribute_t(SAI_HOSTIF_PACKET_ATTR_EGRESS_PORT_OR_LAG, self.ports[out_port])
        attrs.append(attr)

        if(st_utils.is_sai_17x_or_higher()):
            attr = sai_attribute_t(SAI_HOSTIF_PACKET_ATTR_EGRESS_QUEUE_INDEX, queue_index)
            attrs.append(attr)

        hex_pkt = U.scapy_to_hex(pkt)

        self.la_device.flush()
        self.apis[SAI_API_HOSTIF].send_hostif_packet_wrapper(self.switch_id, len(hex_pkt), hex_pkt, attrs)

    def generate_ipv4_acl_key(self):
        args = {}

        for attr in [
                SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
                SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
                SAI_ACL_TABLE_ATTR_FIELD_DSCP,
                SAI_ACL_TABLE_ATTR_FIELD_ECN,
                SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL,
                SAI_ACL_TABLE_ATTR_FIELD_IP_FLAGS,
                SAI_ACL_TABLE_ATTR_FIELD_TTL,
                SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT,
                SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT,
                SAI_ACL_TABLE_ATTR_FIELD_TCP_FLAGS,
                SAI_ACL_TABLE_ATTR_FIELD_ICMP_CODE,
                SAI_ACL_TABLE_ATTR_FIELD_ICMP_TYPE]:
            args[attr] = True

        return args

    def generate_ipv6_acl_key(self):
        args = {}

        for attr in [
                # Enable when object group ACL is available.
                # SAI_ACL_TABLE_ATTR_FIELD_SRC_IPV6,
                SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6,
                SAI_ACL_TABLE_ATTR_FIELD_DSCP,
                SAI_ACL_TABLE_ATTR_FIELD_ECN,
                SAI_ACL_TABLE_ATTR_FIELD_IPV6_NEXT_HEADER,
                # SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_FRAG,
                SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT,
                SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT,
                # SAI_ACL_TABLE_ATTR_FIELD_TCP_FLAGS,
                SAI_ACL_TABLE_ATTR_FIELD_ICMPV6_CODE,
                SAI_ACL_TABLE_ATTR_FIELD_ICMPV6_TYPE]:
            args[attr] = True

        return args

    def generate_combined_v4_v6_acl_key(self):
        args = {}
        for attr in [
                SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
                SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
                SAI_ACL_TABLE_ATTR_FIELD_DSCP,
                SAI_ACL_TABLE_ATTR_FIELD_ECN,
                SAI_ACL_TABLE_ATTR_FIELD_TTL,
                SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT,
                SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT,
                # SAI_ACL_TABLE_ATTR_FIELD_TCP_FLAGS,
                SAI_ACL_TABLE_ATTR_FIELD_ICMP_CODE,
                SAI_ACL_TABLE_ATTR_FIELD_ICMP_TYPE]:
            args[attr] = True

        for attr in [
                # Enable when object group ACL is available.
                # SAI_ACL_TABLE_ATTR_FIELD_SRC_IPV6,
                SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6,
                SAI_ACL_TABLE_ATTR_FIELD_DSCP,
                SAI_ACL_TABLE_ATTR_FIELD_ECN,
                SAI_ACL_TABLE_ATTR_FIELD_IPV6_NEXT_HEADER,
                SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT,
                SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT,
                # SAI_ACL_TABLE_ATTR_FIELD_TCP_FLAGS,
                SAI_ACL_TABLE_ATTR_FIELD_ICMPV6_CODE,
                SAI_ACL_TABLE_ATTR_FIELD_ICMPV6_TYPE]:
            args[attr] = True

        return args

    def bind_acl_to_port(self, port_index, attr_id, val):
        self.set_object_attr(self.ports[port_index], attr_id, val)

    def bind_acl_to_rif(self, rif_id, attr_id, val):
        self.set_object_attr(rif_id, attr_id, val)

    def bind_acl_to_lag(self, lag_id, attr_id, val):
        self.set_object_attr(lag_id, attr_id, val)

    def bind_acl_to_switch(self, attr_id, val):
        # attr_id can be SAI_SWITCH_ATTR_INGRESS_ACL/SAI_SWITCH_ATTR_EGRESS_ACL
        # val is OID of ACL or null OID
        self.set_object_attr(self.switch_id, attr_id, val, verify=True)

    def get_port_ingress_acl(self, port_index):
        return self.get_object_attr(self.ports[port_index], SAI_PORT_ATTR_INGRESS_ACL)

    def get_port_egress_acl(self, port_index):
        return self.get_object_attr(self.ports[port_index], SAI_PORT_ATTR_EGRESS_ACL)

    def get_rif_ingress_acl(self, rif_id):
        return self.get_object_attr(rif_id, SAI_ROUTER_INTERFACE_ATTR_INGRESS_ACL)

    def get_rif_egress_acl(self, rif_id):
        return self.get_object_attr(rif_id, SAI_ROUTER_INTERFACE_ATTR_EGRESS_ACL)

    def get_lag_ingress_acl(self, lag_id):
        return self.get_object_attr(lag_id, SAI_LAG_ATTR_INGRESS_ACL)

    def get_lag_egress_acl(self, lag_id):
        return self.get_object_attr(lag_id, SAI_LAG_ATTR_EGRESS_ACL)

    def get_ingress_capability(self):
        return self.get_object_attr(self.switch_id, SAI_SWITCH_ATTR_ACL_STAGE_INGRESS)

    def get_ipv4_route_available_entry(self):
        return self.get_object_attr(self.switch_id, SAI_SWITCH_ATTR_AVAILABLE_IPV4_ROUTE_ENTRY)

    def get_ipv6_route_available_entry(self):
        return self.get_object_attr(self.switch_id, SAI_SWITCH_ATTR_AVAILABLE_IPV6_ROUTE_ENTRY)

    def get_ipv4_nexthop_entry_available(self):
        return self.get_object_attr(self.switch_id, SAI_SWITCH_ATTR_AVAILABLE_IPV4_NEXTHOP_ENTRY)

    def get_ipv6_nexthop_entry(self):
        return self.get_object_attr(self.switch_id, SAI_SWITCH_ATTR_AVAILABLE_IPV6_NEXTHOP_ENTRY)

    def get_ipv4_neighbor_available_entry(self):
        return self.get_object_attr(self.switch_id, SAI_SWITCH_ATTR_AVAILABLE_IPV4_NEIGHBOR_ENTRY)

    def get_ipv6_neighbor_available_entry(self):
        return self.get_object_attr(self.switch_id, SAI_SWITCH_ATTR_AVAILABLE_IPV6_NEIGHBOR_ENTRY)

    def get_next_hop_group_member_entry_available(self):
        return self.get_object_attr(self.switch_id, SAI_SWITCH_ATTR_AVAILABLE_NEXT_HOP_GROUP_MEMBER_ENTRY)

    def get_next_hop_group_entry_available(self):
        return self.get_object_attr(self.switch_id, SAI_SWITCH_ATTR_AVAILABLE_NEXT_HOP_GROUP_ENTRY)

    def get_fdb_available_entry(self):
        return self.get_object_attr(self.switch_id, SAI_SWITCH_ATTR_AVAILABLE_FDB_ENTRY)

    def get_acl_entry_min_priority(self):
        return self.get_object_attr(self.switch_id, SAI_SWITCH_ATTR_ACL_ENTRY_MINIMUM_PRIORITY)

    def get_acl_entry_max_priority(self):
        return self.get_object_attr(self.switch_id, SAI_SWITCH_ATTR_ACL_ENTRY_MAXIMUM_PRIORITY)

    def get_acl_table_available(self):
        return self.get_switch_attribute(SAI_SWITCH_ATTR_AVAILABLE_ACL_TABLE)

    def get_acl_table_group_available(self):
        return self.get_switch_attribute(SAI_SWITCH_ATTR_AVAILABLE_ACL_TABLE_GROUP)

    def get_acl_table_entry_available(self, acl_table):
        return self.get_object_attr(acl_table, SAI_ACL_TABLE_ATTR_AVAILABLE_ACL_ENTRY)

    def get_acl_table_counter_available(self, acl_table):
        return self.get_object_attr(acl_table, SAI_ACL_TABLE_ATTR_AVAILABLE_ACL_COUNTER)

    def get_fdb_aging_time(self):
        return self.get_object_attr(self.switch_id, SAI_SWITCH_ATTR_FDB_AGING_TIME)

    def set_fdb_aging_time(self, age_time):
        self.set_object_attr(self.switch_id, SAI_SWITCH_ATTR_FDB_AGING_TIME, age_time, verify=True)

    def get_ecmp_default_hash(self):
        return self.get_object_attr(self.switch_id, SAI_SWITCH_ATTR_ECMP_DEFAULT_HASH_SEED)

    def get_lag_default_hash(self):
        return self.get_object_attr(self.switch_id, SAI_SWITCH_ATTR_LAG_DEFAULT_HASH_SEED)

    def get_number_of_unicast_queues(self):
        return self.get_object_attr(self.switch_id, SAI_SWITCH_ATTR_NUMBER_OF_UNICAST_QUEUES)

    def get_number_of_multicast_queues(self):
        return self.get_object_attr(self.switch_id, SAI_SWITCH_ATTR_NUMBER_OF_MULTICAST_QUEUES)

    def get_number_of_queues(self):
        return self.get_object_attr(self.switch_id, SAI_SWITCH_ATTR_NUMBER_OF_QUEUES)

    def get_number_of_cpu_queues(self):
        return self.get_object_attr(self.switch_id, SAI_SWITCH_ATTR_NUMBER_OF_CPU_QUEUES)

    def inject_network_packet(self, pkt, slice, ifg, pif):
        pkt_desc = nsim.sim_packet_info_desc()
        pkt_desc.packet = U.scapy_to_hex(pkt)
        pkt_desc.slice = slice
        pkt_desc.ifg = ifg
        pkt_desc.pif = pif
        self.la_device.flush()
        self.nsim_provider.inject_packet(pkt_desc)
        self.nsim_provider.step_packet()

    def get_punt_packet(self):
        return cvar.sai_num_punt_pkts, cvar.sai_last_punt_pkt, cvar.sai_last_punt_pkt_sip, cvar.sai_last_punt_pkt_trap_id, cvar.sai_last_punt_pkt_dst_port, cvar.sai_last_punt_pkt_inglag

    def get_packet(self):
        out_packet = self.nsim_provider.get_packet()
        if out_packet.packet == '':
            return (False, out_packet)

        return (True, out_packet)

    def nsim_inject_packet(self, ipacket):
        self.la_device.flush()
        self.nsim_provider.inject_packet(ipacket)

    def nsim_step_packet(self):
        return self.nsim_provider.step_packet()

    def stop_kernel_thread(self):
        if not self.is_hw():
            self.kernel.close_connected_sockets()

    def start_simulator_and_user_space_kernel(self):
        name_exists = True
        while name_exists:
            random_dev_no = random.randint(0, pow(2, 31))  # need to fit into unsigned int
            kernel_file_name = "/tmp/leaba{0}_0".format(random_dev_no)
            kernel_file = Path(kernel_file_name)
            if not kernel_file.exists():
                name_exists = False

        test_dev_name = "/dev/testdev{0}".format(random_dev_no)
        self.nsim_provider = nsim.create_and_run_simulator_server(None, 0, test_dev_name)
        if self.nsim_provider is None:
            raise Exception("Failed to start nsim")

        self.nsim = self.nsim_provider
        self.nsim.packet_dma_enable(True)

        self.kernel = nsim_kernel.user_space_kernel()
        self.kernel.initialize(1, self.nsim_provider.get_connection_handle())
        self.kernel.start_listening_for_packets()
        self.set_logging(self.nsim_provider)
        return self.nsim_provider.get_connection_handle()

    def is_hw(self):
        return self.is_hw_dev

    def update_config_for_nsim_accurate(self, config):
        cwd = os.getcwd()

        try:
            index = cwd.rindex('sai', 0)
        except BaseException:
            index = -1

        if index != -1:
            # we are not in the root of the workspace
            full_path = os.path.join(cwd[0:cwd.rindex('sai', 0) + len('sai')], 'res', config)
        else:
            # we are in the root of the workspace
            full_path = os.path.join(cwd, 'sai', 'res', config)

        if not os.path.exists(full_path):
            raise Exception("failed to find config file at {}".format(full_path))

        with open(full_path, 'r+') as f:
            data = json.load(f)

        for dev in data['devices']:
            if 'device_property' not in dev.keys():
                dev['device_property'] = {}
            dev['device_property']['enable_nsim_accurate_scale_model'] = True

        tmp_dir = tempfile._get_default_tempdir()
        tmp_name = next(tempfile._get_candidate_names())
        tmp_path = os.path.join(tmp_dir, tmp_name + '.json')

        with open(tmp_path, 'w') as f:
            json.dump(data, f, indent=4)

        return tmp_path

    # When running from Fishnet, we get device_name, and board_type
    def setUp(self, device_name=None, board_type=None, config_file=None, nsim_accurate=False, optional_switch_create_time_attrs=[]):
        if device_name is None:
            device_name = os.getenv('SDK_DEVICE_NAME')

        if device_name == "/dev/uio0":
            self.is_hw_dev = True
            self.set_logging(None)
        else:
            self.is_hw_dev = False
            device_name = self.start_simulator_and_user_space_kernel()

        if board_type is None:
            default_board = "blacktip" if st_utils.is_asic_env_gibraltar() else "sherman"
            board_type = os.getenv('BOARD_TYPE', default_board)

        if config_file is None or config_file == '':
            config_file = "config/{0}.json".format(board_type)

        if nsim_accurate:
            config_file = self.update_config_for_nsim_accurate(config_file)
            self.temp_config_file = config_file
            self.log("[ENV] nsim accurate enabled, modified config at {}".format(config_file))

        self.create_sai_switch(device_name, config_file, nsim_accurate, optional_switch_create_time_attrs)

    def create_sai_switch(self, device_name, config_file, nsim_accurate, attrs=[]):

        self.update_config_file(config_file)

        self.device_name = device_name
        attr = sai_attribute_t(SAI_SWITCH_ATTR_SWITCH_HARDWARE_INFO, device_name)
        attrs.append(attr)

        if self.fw_path_name is not None and self.fw_path_name != "":
            self.log("[ENV] sai_test_base.fw_path_name = {}".format(self.fw_path_name))
            attr = sai_attribute_t(SAI_SWITCH_ATTR_FIRMWARE_PATH_NAME, self.fw_path_name)
            attrs.append(attr)

        if self.config["wb_init"]:
            attrs.append(sai_attribute_t(SAI_SWITCH_ATTR_RESTART_WARM, True))
        else:
            attrs.append(sai_attribute_t(SAI_SWITCH_ATTR_SRC_MAC_ADDRESS, U.sai_mac(self.router_mac)))

            # add attributes for notifications
            attrs += self.configure_notification()

        # register the profile_get_value function
        service = sai_service_method_table_t(profile_get_value, None)
        sai_api_initialize(0, service)

        self.get_apis()
        self.obj_wrapper = sai_obj_wrapper.lsai_obj_wrapper(self)

        # need this to be class attribute for the object_check decorator
        sai_test_base.switch_id = self.apis[SAI_API_SWITCH].create_switch(attrs)

        # these need to be after create_switch. We want the switch to be created for real
        if self.config["wb_init"]:
            self.obj_wrapper.set_mode("wb_init")
        elif self.config["wb_shutdown_count"] != 0:
            self.obj_wrapper.set_mode("save")

        self.is_gb = (st_utils.get_device_type(self.switch_id) == "gibraltar")

        self.la_device = sdk.la_get_device(0)

        self.create_hostif()

        self.virtual_router_id = self.get_object_attr(self.switch_id, SAI_SWITCH_ATTR_DEFAULT_VIRTUAL_ROUTER_ID)

        # This should be removed. Each test should take care of what it needs
        # Leaving it for now, because we use this function for HW boards bringup to some default state
        self.arp_trap = self.create_trap(SAI_HOSTIF_TRAP_TYPE_ARP_REQUEST, SAI_PACKET_ACTION_TRAP, 255)
        self.ndp_trap = self.create_trap(SAI_HOSTIF_TRAP_TYPE_IPV6_NEIGHBOR_DISCOVERY, SAI_PACKET_ACTION_TRAP, 255)
        self.ip2me_trap = self.create_trap(SAI_HOSTIF_TRAP_TYPE_IP2ME, SAI_PACKET_ACTION_TRAP)

        count, vrflist = self.get_object_keys(SAI_OBJECT_TYPE_VIRTUAL_ROUTER)

        self.set_object_attr(sai_test_base.switch_id, SAI_SWITCH_ATTR_COUNTER_REFRESH_INTERVAL, 0)

    def number_of_ecmp_members_in_group(self, ecmp_group_num):
        ecmp_groups = self.la_device.get_objects(sdk.la_object.object_type_e_ECMP_GROUP)
        ecmp_members = ecmp_groups[ecmp_group_num].get_members()
        return len(ecmp_members)

    def tearDown(self):
        if not self.is_hw():
            self.kernel.close_connected_sockets()
            self.kernel.destroy()
        if self.switch_id is not None:
            self.remove_object(self.switch_id)
        if hasattr(self, 'nsim_provider') and self.nsim_provider is not None:
            self.nsim_provider.destroy_simulator()
        if self.temp_config_file is not None and os.path.exists(self.temp_config_file):
            self.log("[ENV] removing temp config file {}".format(self.temp_config_file))
            os.remove(self.temp_config_file)

    def update_config_file(self, config_file="config/sherman_p5.json"):
        cvar.config_file_name = config_file

    if (st_utils.is_sai_17x_or_higher()):
        @object_check("create", SAI_OBJECT_TYPE_SYSTEM_PORT)
        def create_system_port(self, sysport_cfg, optional_args=[], verify=[True, False], warm_boot=False):
            attrs = [[SAI_SYSTEM_PORT_ATTR_CONFIG_INFO, sysport_cfg]] + optional_args
            return self.obj_wrapper.create_object(SAI_OBJECT_TYPE_SYSTEM_PORT, self.switch_id, attrs, verify, warm_boot)

        def get_fp_system_ports(self):
            '''
            Queries the switch's system port list, returning all non-internal
            system ports (i.e. front-panel SPs)
            '''
            num_sysports = self.get_object_attr(self.switch_id, SAI_SWITCH_ATTR_NUMBER_OF_SYSTEM_PORTS)
            sysports = self.get_object_attr(self.switch_id, SAI_SWITCH_ATTR_SYSTEM_PORT_LIST)
            assert len(sysports) == num_sysports
            port_cfg = st_utils.PortConfig()
            fp_sysports = []
            for sp_oid in sysports:
                cfg_info = self.get_object_attr(sp_oid, SAI_SYSTEM_PORT_ATTR_CONFIG_INFO)
                acpi = cfg_info[3]
                if (acpi != port_cfg.host_serdes_id) and (acpi != port_cfg.recycle_serdes_id):
                    fp_sysports.append(sp_oid)
            return fp_sysports
