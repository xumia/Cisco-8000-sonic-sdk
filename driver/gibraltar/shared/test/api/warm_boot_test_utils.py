#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

import os
import sys
import inspect
import ctypes
import gc
import re
import decor
from leaba import sdk
import lldcli
import cpu2jtagcli
import hw_tablescli
import test_hldcli
import test_racli
import time
import uuid
import atexit

warm_boot_supported = False
leaba_kernel_module_reload_enabled = False


def support_warm_boot():
    global warm_boot_supported
    warm_boot_supported = True


def is_warm_boot_supported():
    return warm_boot_supported


def enable_leaba_kernel_module_reload():
    global leaba_kernel_module_reload_enabled
    leaba_kernel_module_reload_enabled = True


def is_leaba_kernel_module_reload_enabled():
    return leaba_kernel_module_reload_enabled


RAM_DISK_PATH = '/dev/shm/'


def get_warm_boot_file_name():
    return get_tmp_file_name('.warm_boot')


tmp_wb_files = []


def get_tmp_file_name(ext):
    # get name of tmp file;
    # if RAM disk is available, file will be created on RAM disk;
    # otherwise, file will be created in /tmp/
    if os.path.exists(RAM_DISK_PATH):
        filename = os.path.join(RAM_DISK_PATH, str(uuid.uuid4())) + ext
        while os.path.exists(filename):
            filename = os.path.join(RAM_DISK_PATH, str(uuid.uuid4())) + ext
    else:
        sys.stdout.write(
            'WARNING: RAM disk {} not available, tmp file with ext \'{}\' will be created in /tmp/\n'.format(RAM_DISK_PATH, ext))
        sys.stdout.flush()
        filename = os.path.join('/tmp/', str(uuid.uuid4())) + ext
        while os.path.exists(filename):
            filename = os.path.join('/tmp/', str(uuid.uuid4())) + ext

    # Add to list of tmp files that will be cleaned up at the end of program execution
    tmp_wb_files.append(os.path.abspath(filename))

    return filename


# mutator methods of SDK API objects
# any method with name <mutator>[_*] triggers warm boot if warm boot is enabled
MUTATOR_KEYWORDS = [
    'create',
    'set',
    'append',
    'insert',
    'erase',
    'clear',
    'write',
    'add',
    'remove',
    'attach',
    'push',
    'pop',
    'modify',
    'delete',
    'reconfigure',
    'replace'
]

GETTER_KEYWORDS = [
    'get',
    'read'
]


# MAX_WB_INVOCATIONS_PER_TESTCASE   - max number of WB invocations per single test case
# MAX_WB_INVOCATIONS_PER_SDK_METHOD - max number of times that specific SDK method can trigger WB in one test file
MAX_WB_INVOCATIONS_PER_TESTCASE = sys.maxsize
if decor.is_hw_device():
    MAX_WB_INVOCATIONS_PER_SDK_METHOD = 3
else:
    MAX_WB_INVOCATIONS_PER_SDK_METHOD = 10

wb_invocations_per_testcase = 0
wb_invocations_per_sdk_method = {}


# helper class
class RefInfo:
    def __init__(self, referrer, ref_key):
        self.referrer = referrer
        self.ref_key = ref_key


class HashableDict(dict):
    def __hash__(self):
        return hash(frozenset(self))


class WarmBootDurationStats():
    def __init__(self):
        self.save_py_objects_duration = 0
        self.sdk_disconnect_duration = 0
        self.unload_kernel_module_duration = 0
        self.load_kernel_module_duration = 0
        self.sdk_reconnect_duration = 0
        self.restore_py_objects_duration = 0

    def to_string(self):
        out_str = ''
        out_str += '- Save python objects            : {}\n'.format(self.save_py_objects_duration)
        out_str += '- SDK disconnect                 : {}\n'.format(self.sdk_disconnect_duration)
        if decor.is_hw_device() and is_leaba_kernel_module_reload_enabled():
            out_str += '- Unload leaba kernel module     : {}\n'.format(self.unload_kernel_module_duration)
            out_str += '- Load leaba kernel module       : {}\n'.format(self.load_kernel_module_duration)
        out_str += '- SDK reconnect                  : {}\n'.format(self.sdk_reconnect_duration)
        out_str += '- Restore python objects         : {}\n\n'.format(self.restore_py_objects_duration)

        total = 0

        save_and_restore_py_objects_duration = self.save_py_objects_duration + self.restore_py_objects_duration
        out_str += '- Save and restore python objects: {}\n'.format(save_and_restore_py_objects_duration)
        total += save_and_restore_py_objects_duration

        sdk_disconnect_and_reconnect_duration = self.sdk_disconnect_duration + self.sdk_reconnect_duration
        out_str += '- SDK disconnect and reconnect   : {}\n'.format(sdk_disconnect_and_reconnect_duration)
        total += sdk_disconnect_and_reconnect_duration

        if decor.is_hw_device() and is_leaba_kernel_module_reload_enabled():
            reload_kernel_module_duration = self.unload_kernel_module_duration + self.load_kernel_module_duration
            out_str += '- Reload kernel module           : {}\n'.format(reload_kernel_module_duration)
            total += reload_kernel_module_duration

        out_str += '- Total                          : {}\n'.format(total)

        return out_str


def is_swig_object(obj):
    return hasattr(obj, '__class__') and hasattr(obj.__class__, '__swig_setmethods__')


def is_la_object(obj):
    return re.search('proxy of <Swig Object of type .*silicon_one::la_', str(obj)) and hasattr(obj, 'oid')


def get_class_name_of_sdk_obj(obj):
    # extract class name from SDK object's string representation
    # example:
    #   str repr: <leaba.sdk.la_device; proxy of <Swig Object of type ...
    #   result  : la_device
    try:
        return str(obj).split('<', 1)[1].split(';', 1)[0].split('.')[-1].strip()
    except BaseException:
        return ''


def is_la_device(obj):
    return get_class_name_of_sdk_obj(obj) == 'la_device'


def is_ll_device(obj):
    return get_class_name_of_sdk_obj(obj) == 'll_device'


def is_ll_pacific_tree(obj):
    return get_class_name_of_sdk_obj(obj) == 'pacific_tree'


def is_ll_gibraltar_tree(obj):
    return get_class_name_of_sdk_obj(obj) == 'gibraltar_tree'


def is_lld_register(obj):
    return get_class_name_of_sdk_obj(obj) == 'lld_register'


def is_lld_memory(obj):
    return get_class_name_of_sdk_obj(obj) == 'lld_memory'


def is_lld_block(obj):
    return get_class_name_of_sdk_obj(obj) == 'lld_block'


def is_la_ip_mc_route_info(obj):
    return get_class_name_of_sdk_obj(obj) == 'la_ip_mc_route_info'


def is_la_ip_route_info(obj):
    return get_class_name_of_sdk_obj(obj) == 'la_ip_route_info'


def is_la_ipv4_route_entry_parameters(obj):
    return get_class_name_of_sdk_obj(obj) == 'la_ipv4_route_entry_parameters'


def is_la_ipv6_route_entry_parameters(obj):
    return get_class_name_of_sdk_obj(obj) == 'la_ipv6_route_entry_parameters'


def is_la_lpts_result(obj):
    return get_class_name_of_sdk_obj(obj) == 'la_lpts_result'


def is_la_oq_pg(obj):
    return get_class_name_of_sdk_obj(obj) == 'la_oq_pg'


def is_lpts_entry_desc(obj):
    return get_class_name_of_sdk_obj(obj) == 'lpts_entry_desc'


def is_la_acl_command_action(obj):
    return get_class_name_of_sdk_obj(obj) == 'la_acl_command_action'


def is_acl_entry_desc(obj):
    return get_class_name_of_sdk_obj(obj) == 'acl_entry_desc'


def is_la_mpls_route_info(obj):
    return get_class_name_of_sdk_obj(obj) == 'la_mpls_route_info'


def is_la_ipmcg_member_info(obj):
    return get_class_name_of_sdk_obj(obj) == 'member_info'


def is_cpu2jtag_handler(obj):
    return get_class_name_of_sdk_obj(obj) == 'cpu2jtag'


def is_apb_handler(obj):
    return get_class_name_of_sdk_obj(obj) == 'apb'


def is_cem(obj):
    return get_class_name_of_sdk_obj(obj) == 'cem'


def is_resource_manager(obj):
    return get_class_name_of_sdk_obj(obj) == 'resource_manager'


def is_ctm_manager(obj):
    return get_class_name_of_sdk_obj(obj) == 'ctm_mgr'


def is_ctm_config(obj):
    return get_class_name_of_sdk_obj(obj) == 'ctm_config'


def is_ctm_config_tcam(obj):
    return get_class_name_of_sdk_obj(obj) == 'ctm_config_tcam'


def is_la_mpls_multicast_group_member_info(obj):
    return get_class_name_of_sdk_obj(obj) == 'la_mpls_multicast_group_member_info'


def get_obj_ref_keys(referrer, obj, invalidate=False):
    ref_keys = []

    if isinstance(referrer, dict):
        variables = referrer.items()
    elif isinstance(referrer, list):
        variables = enumerate(referrer)
    elif isinstance(referrer, set):
        variables = [(None, obj)]
    elif isinstance(referrer, tuple):
        variables = enumerate(referrer)
    elif inspect.isframe(referrer):
        variables = referrer.f_locals.items()
    else:
        raise Exception("Unsupported referrer type {}!".format(type(referrer)))

    for key, value in variables:
        if id(value) == id(obj):
            ref_keys.append(key)

            if invalidate:
                ref_key = obj if isinstance(referrer, set) else key
                update_single_referrer(referrer, ref_key, None)

    return ref_keys


def get_obj_referrers(obj, ignore=[], invalidate=False):
    refs = []
    referrers = gc.get_referrers(obj)

    ignore.append(id(inspect.currentframe()))
    ignore.append(id(referrers))

    for referrer in referrers:
        if id(referrer) in ignore:
            continue

        ref_keys = get_obj_ref_keys(referrer, obj, invalidate)
        for ref_key in ref_keys:
            ref_info = RefInfo(referrer, ref_key)
            refs.append(ref_info)

    ignore.pop()
    ignore.pop()
    return refs


def update_single_referrer(referrer, obj_key, new_obj):
    if referrer is None:
        return

    # Referrers of object are discovered by calling gc.get_referrers(obj).
    # Types of referrers that are supported:
    # - dict - if object is referenced by dict or by class field
    # - list - if object is element of the list
    # - set  - if object is element of the set
    # - tuple - if object is element of the tuple
    # - frame - if object is referenced by local variable

    if isinstance(referrer, dict):
        # handling of case when object is referenced by class field
        # simple updating of dict does not work in this case for some reason, so using setattr
        if '__module__' in referrer:
            for ref in gc.get_referrers(referrer):
                if inspect.isclass(ref) and hasattr(ref, obj_key):
                    setattr(ref, obj_key, new_obj)
                    return

        referrer[obj_key] = new_obj
    elif isinstance(referrer, list):
        referrer[obj_key] = new_obj
    elif isinstance(referrer, set):
        if obj_key:
            referrer.remove(obj_key)
        if new_obj:
            referrer.add(new_obj)
    elif isinstance(referrer, tuple):
        old_obj_addr = id(referrer[obj_key])
        if old_obj_addr != id(None):
            ref_count = (ctypes.c_longlong).from_address(old_obj_addr)
            ref_count.value -= 1

        ref_addr = id(referrer)
        element_ptr = (ctypes.c_longlong).from_address(ref_addr + (3 + obj_key) * 8)
        element_ptr.value = id(new_obj)
        if new_obj:
            ref_count = (ctypes.c_longlong).from_address(id(new_obj))
            ref_count.value += 1
    elif inspect.isframe(referrer):
        referrer.f_locals.update({obj_key: new_obj})
        ctypes.pythonapi.PyFrame_LocalsToFast(ctypes.py_object(referrer), ctypes.c_int(0))
    else:
        raise Exception('WARM_BOOT: Unsupported referrer type {}!'.format(type(referrer)))


def invalidate_objs_refs(ref_infos):
    for obj, refs in ref_infos:
        for ref_info in refs:
            ref_key = obj if isinstance(ref_info.referrer, set) else ref_info.ref_key
            update_single_referrer(ref_info.referrer, ref_key, None)


def get_la_object_instances_by_oid(dev_id, oid):
    gc.collect()
    objs = []
    all_objects = gc.get_objects()
    for obj in all_objects:
        if is_swig_object(obj) and is_la_object(obj) and not is_la_device(obj):
            # Skip if the object has only two referrers, which are:
            # - current frame (local variable obj)
            # - local list of objects, returned by gc.get_objects() call
            if len(gc.get_referrers(obj)) == 2:
                continue

            if obj.get_device().get_id() == dev_id and obj.oid() == oid:
                objs.append(obj)
    return objs


# must be up-to-date with implementation
SDK_STRUCT_WITH_UNION_MAP = {
    'la_acl_command_action': {
        'type': {
            'data': {
                sdk.la_acl_action_type_e_TRAFFIC_CLASS: 'traffic_class',
                sdk.la_acl_action_type_e_COLOR: 'color',
                sdk.la_acl_action_type_e_QOS_OR_METER_COUNTER_OFFSET: 'qos_offset',
                sdk.la_acl_action_type_e_ENCAP_EXP: 'encap_exp',
                sdk.la_acl_action_type_e_REMARK_FWD: 'remark_fwd',
                sdk.la_acl_action_type_e_REMARK_GROUP: 'remark_group',
                sdk.la_acl_action_type_e_DROP: 'drop',
                sdk.la_acl_action_type_e_PUNT: 'punt',
                sdk.la_acl_action_type_e_DO_MIRROR: 'do_mirror',
                sdk.la_acl_action_type_e_MIRROR_CMD: 'mirror_cmd',
                sdk.la_acl_action_type_e_COUNTER_TYPE: 'counter_type',
                sdk.la_acl_action_type_e_COUNTER: 'counter',
                sdk.la_acl_action_type_e_L2_DESTINATION: 'l2_dest',
                sdk.la_acl_action_type_e_L3_DESTINATION: 'l3_dest',
                sdk.la_acl_action_type_e_METER: 'meter',
            },
        },
    },
}


def get_nested_la_obj_info(obj, info_save_and_restore, info_invalidate_only, names=[], visit_members=[]):
    # iterates through struct members recursively and collects metadata about
    # nested la_object and their references

    if is_la_object(obj):
        ref_name = '.'.join(names)

        # if reference points to an la_object that was destroyed, just invalidate the reference
        for destroyed_obj, destroyed_obj_oid in destroyed_la_objs_map:
            if obj.this == destroyed_obj:
                info_invalidate_only.append((ref_name, destroyed_obj_oid))
                return

        oid = obj.oid()
        info_save_and_restore.append((ref_name, oid))
        return

    selectors = SDK_STRUCT_WITH_UNION_MAP.get(get_class_name_of_sdk_obj(obj), {})
    visit_members_map = {}
    for selector, unions in selectors.items():
        if hasattr(obj, selector):
            selector_val = eval('obj.{}'.format(selector))
            for union, union_members in unions.items():
                visit_members_map.setdefault(union, []).append(union_members[selector_val])

    # create list of tuples (<member_name>, <member_value>)
    if len(visit_members):
        members = []
        for member_name in visit_members:
            members.append((member_name, eval('obj.{}'.format(member_name))))
    else:
        members = [m for m in inspect.getmembers(obj) if not (m[0].startswith('__') or m[0] == 'this')]

    for name, value in members:
        if is_swig_object(value):
            names.append(name)
            get_nested_la_obj_info(value, info_save_and_restore, info_invalidate_only, names, visit_members_map.get(name, []))
            names.pop()


def get_non_la_obj_non_primitive_obj_info(obj, invalidate=False):
    res = HashableDict()
    info_save_and_restore = []
    info_invalidate_only = []
    get_nested_la_obj_info(obj, info_save_and_restore, info_invalidate_only)

    if invalidate:
        for ref_name, _ in info_save_and_restore + info_invalidate_only:
            exec('obj.{} = None'.format(ref_name))

    res['obj'] = obj
    res['nested_la_obj_info'] = info_save_and_restore
    return res


def is_non_primitive_sdk_obj(obj, level=0):
    if level and is_la_object(obj):
        return True

    res = False
    member_objs = [m[1] for m in inspect.getmembers(obj) if not (m[0].startswith('__') or m[0] == 'this')]
    for member_obj in member_objs:
        if is_swig_object(member_obj):
            res |= is_non_primitive_sdk_obj(member_obj, level + 1)
        elif isinstance(member_obj, list):
            for elem in member_obj:
                res |= is_non_primitive_sdk_obj(elem, level + 2)
    return res


class LeabaObjRefCollection():

    def __init__(self, la_dev):
        self.reset()

        self.la_dev_id = la_dev.get_id()
        self.la_dev_path = la_dev.get_ll_device().get_device_path()

    def reset(self):
        self.la_dev_id = None               # la_device ID
        self.la_dev_path = None             # device path
        self.la_dev_refs = []               # list of RefInfo instances
        self.la_obj_refs = {}               # dict where key is la_object's oid, value is list of RefInfo instances
        self.ll_dev_refs = []               # list of RefInfo instances
        self.ll_pacific_tree_refs = []      # list of RefInfo instances
        self.ll_gibraltar_tree_refs = []    # list of RefInfo instances
        self.lld_block_refs = {}            # dict where key is block name, value is list of RefInfo instances
        self.lld_register_refs = {}         # dict where key is register name, value is list of RefInfo instances
        self.lld_memory_refs = {}           # dict where key is memory name, value is list of RefInfo instances
        self.cpu2jtag_handler_refs = []     # list of RefInfo instances
        self.apb_handler_refs = {}          # dict where key is interface type, value is list of RefInfo instances
        self.resource_manager_refs = []     # list of RefInfo instances
        self.ctm_manager_refs = []          # list of RefInfo instances
        self.ctm_config_refs = []           # list of RefInfo instances
        self.ctm_config_tcam_refs = []      # list of RefInfo instances
        self.cem_refs = []                  # list of RefInfo instances

        # for each non-la_object non-primitive sdk object, we store:
        # 1) object itself with invalidated nested references to la_object instances
        # 2) metadata needed to retrieve la_object instances whose references are invalidated:
        #       - path to la_object nested in non-primitive struct
        #       - la_object's oid
        # 3) list of RefInfo instances that represent referrers to non-primitive objects
        #
        # dict where key is hashable dict that stores 1) and 2) info in format:
        # {'obj': <actual non-primitive object>,
        #  'nested_la_obj_info': [(<nested la_object path>, <oid>), ...]}
        # value is array of RefInfo instances
        self.non_la_object_non_primitive_refs = {}

    def add_object(self, obj, ignore=[]):
        ignore.append(id(inspect.currentframe()))

        if is_la_object(obj):
            self.add_la_object(obj, ignore)
        elif is_ll_device(obj):
            self.add_ll_device(obj, ignore)
        elif is_ll_pacific_tree(obj):
            self.add_ll_pacific_tree(obj, ignore)
        elif is_ll_gibraltar_tree(obj):
            self.add_ll_gibraltar_tree(obj, ignore)
        elif is_lld_block(obj):
            self.add_lld_block(obj, ignore)
        elif is_lld_register(obj):
            self.add_lld_register(obj, ignore)
        elif is_lld_memory(obj):
            self.add_lld_memory(obj, ignore)
        elif is_cpu2jtag_handler(obj):
            self.add_cpu2jtag_handler(obj, ignore)
        elif decor.is_gibraltar() and is_apb_handler(obj):
            self.add_apb_handler(obj, ignore)
        elif is_resource_manager(obj):
            self.add_resource_manager(obj, ignore)
        elif is_ctm_manager(obj):
            self.add_ctm_manager(obj, ignore)
        elif is_ctm_config_tcam(obj):
            self.add_ctm_config_tcam(obj, ignore)
        elif is_ctm_config(obj):
            self.add_ctm_config(obj, ignore)
        elif is_cem(obj):
            self.add_cem(obj, ignore)
        elif is_non_primitive_sdk_obj(obj):
            if is_la_ip_mc_route_info(obj) or \
               is_la_ip_route_info(obj) or \
               is_la_ipv4_route_entry_parameters(obj) or \
               is_la_ipv6_route_entry_parameters(obj) or \
               is_la_lpts_result(obj) or \
               is_la_oq_pg(obj) or \
               is_lpts_entry_desc(obj) or \
               is_la_acl_command_action(obj) or \
               is_acl_entry_desc(obj) or \
               is_la_mpls_route_info(obj) or \
               is_la_ipmcg_member_info(obj) or \
               is_la_mpls_multicast_group_member_info(obj):
                self.add_non_la_object_non_primitive(obj, ignore)
            else:
                raise Exception('WARM_BOOT: Obj type "{}" not supported!'.format(type(obj)))
        else:
            pass

        ignore.pop()

    def add_la_object(self, obj, ignore=[]):
        ignore.append(id(inspect.currentframe()))

        if is_la_device(obj):
            self.add_la_device(obj, ignore)
        else:
            refs = get_obj_referrers(obj, ignore, invalidate=True)
            if len(refs):
                la_obj_oid = obj.oid()
                self.la_obj_refs.setdefault(la_obj_oid, []).extend(refs)

        ignore.pop()

    def add_la_device(self, obj, ignore=[]):
        ignore.append(id(inspect.currentframe()))
        refs = get_obj_referrers(obj, ignore, invalidate=True)
        ignore.pop()

        if obj.get_id() != self.la_dev_id:
            raise Exception("WARM_BOOT: Detected multiple devices, not supported!")

        self.la_dev_refs.extend(refs)

    def add_ll_device(self, obj, ignore=[]):
        ignore.append(id(inspect.currentframe()))
        refs = get_obj_referrers(obj, ignore, invalidate=True)
        ignore.pop()

        self.ll_dev_refs.extend(refs)

    def add_ll_pacific_tree(self, obj, ignore=[]):
        ignore.append(id(inspect.currentframe()))
        refs = get_obj_referrers(obj, ignore, invalidate=True)
        ignore.pop()

        self.ll_pacific_tree_refs.extend(refs)

    def add_ll_gibraltar_tree(self, obj, ignore=[]):
        ignore.append(id(inspect.currentframe()))
        refs = get_obj_referrers(obj, ignore, invalidate=True)
        ignore.pop()

        self.ll_gibraltar_tree_refs.extend(refs)

    def add_lld_block(self, obj, ignore=[]):
        ignore.append(id(inspect.currentframe()))
        refs = get_obj_referrers(obj, ignore, invalidate=True)
        ignore.pop()

        block_name = obj.get_name()
        self.lld_block_refs.setdefault(block_name, []).extend(refs)

    def add_lld_register(self, obj, ignore=[]):
        ignore.append(id(inspect.currentframe()))
        refs = get_obj_referrers(obj, ignore, invalidate=True)
        ignore.pop()

        reg_name = obj.get_name()
        self.lld_register_refs.setdefault(reg_name, []).extend(refs)

    def add_lld_memory(self, obj, ignore=[]):
        ignore.append(id(inspect.currentframe()))
        refs = get_obj_referrers(obj, ignore, invalidate=True)
        ignore.pop()

        mem_name = obj.get_name()
        self.lld_memory_refs.setdefault(mem_name, []).extend(refs)

    def add_cpu2jtag_handler(self, obj, ignore=[]):
        ignore.append(id(inspect.currentframe()))
        refs = get_obj_referrers(obj, ignore, invalidate=True)
        ignore.pop()

        self.cpu2jtag_handler_refs.extend(refs)

    def add_apb_handler(self, obj, ignore=[]):
        ignore.append(id(inspect.currentframe()))
        refs = get_obj_referrers(obj, ignore, invalidate=True)
        ignore.pop()

        self.apb_handler_refs.setdefault(obj.get_interface_type(), []).extend(refs)

    def add_resource_manager(self, obj, ignore=[]):
        ignore.append(id(inspect.currentframe()))
        refs = get_obj_referrers(obj, ignore, invalidate=True)
        ignore.pop()

        self.resource_manager_refs.extend(refs)

    def add_ctm_manager(self, obj, ignore=[]):
        ignore.append(id(inspect.currentframe()))
        refs = get_obj_referrers(obj, ignore, invalidate=True)
        ignore.pop()

        self.ctm_manager_refs.extend(refs)

    def add_ctm_config(self, obj, ignore=[]):
        ignore.append(id(inspect.currentframe()))
        refs = get_obj_referrers(obj, ignore, invalidate=True)
        ignore.pop()

        self.ctm_config_refs.extend(refs)

    def add_ctm_config_tcam(self, obj, ignore=[]):
        ignore.append(id(inspect.currentframe()))
        refs = get_obj_referrers(obj, ignore, invalidate=True)
        ignore.pop()

        self.ctm_config_tcam_refs.extend(refs)

    def add_cem(self, obj, ignore=[]):
        ignore.append(id(inspect.currentframe()))
        refs = get_obj_referrers(obj, ignore, invalidate=True)
        ignore.pop()

        self.cem_refs.extend(refs)

    def add_non_la_object_non_primitive(self, obj, ignore=[]):
        ignore.append(id(inspect.currentframe()))
        refs = get_obj_referrers(obj, ignore, invalidate=True)
        ignore.pop()

        key = get_non_la_obj_non_primitive_obj_info(obj, invalidate=True)
        self.non_la_object_non_primitive_refs.setdefault(key, []).extend(refs)

    def restore_objects(self, la_dev):
        # update la_device refs
        for ref_info in self.la_dev_refs:
            update_single_referrer(ref_info.referrer, ref_info.ref_key, la_dev)

        # update la_object refs
        for la_obj_oid, la_obj_refs in self.la_obj_refs.items():
            la_obj = la_dev.get_object(la_obj_oid).downcast()
            for ref_info in la_obj_refs:
                update_single_referrer(ref_info.referrer, ref_info.ref_key, la_obj)

        # update ll_device refs
        ll_dev = la_dev.get_ll_device()
        for ref_info in self.ll_dev_refs:
            update_single_referrer(ref_info.referrer, ref_info.ref_key, ll_dev)

        # update ll_pacific_tree refs
        ll_pacific_tree = ll_dev.get_pacific_tree()
        for ref_info in self.ll_pacific_tree_refs:
            update_single_referrer(ref_info.referrer, ref_info.ref_key, ll_pacific_tree)

        # update ll_gibraltar_tree refs
        ll_gibraltar_tree = ll_dev.get_gibraltar_tree()
        for ref_info in self.ll_gibraltar_tree_refs:
            update_single_referrer(ref_info.referrer, ref_info.ref_key, ll_gibraltar_tree)

        if ll_dev.is_pacific():
            device_tree = ll_pacific_tree
        else:
            device_tree = ll_gibraltar_tree

        # update lld_block refs
        for block_name, lld_block_refs in self.lld_block_refs.items():
            if block_name == '':
                lld_block = ll_dev.get_device_tree()
            else:
                lld_block = eval('device_tree.{}'.format(block_name))
            for ref_info in lld_block_refs:
                update_single_referrer(ref_info.referrer, ref_info.ref_key, lld_block)

        # update lld_register refs
        for reg_name, lld_reg_refs in self.lld_register_refs.items():
            lld_reg = eval('device_tree.{}'.format(reg_name))
            for ref_info in lld_reg_refs:
                update_single_referrer(ref_info.referrer, ref_info.ref_key, lld_reg)

        # update lld_memory refs
        for mem_name, lld_mem_refs in self.lld_memory_refs.items():
            lld_mem = eval('device_tree.{}'.format(mem_name))
            for ref_info in lld_mem_refs:
                update_single_referrer(ref_info.referrer, ref_info.ref_key, lld_mem)

        # update cpu2jtag_handler refs
        cpu2jtag_handler = la_dev.get_cpu2jtag_handler()
        for ref_info in self.cpu2jtag_handler_refs:
            update_single_referrer(ref_info.referrer, ref_info.ref_key, cpu2jtag_handler)

        # update apb_handler refs
        for apb_interface_type, apb_handler_refs in self.apb_handler_refs.items():
            apb_handler = la_dev.get_apb_handler(apb_interface_type)
            for ref_info in apb_handler_refs:
                update_single_referrer(ref_info.referrer, ref_info.ref_key, apb_handler)

        # update resource_manager refs
        resource_manager = test_hldcli.la_device_get_resource_manager(la_dev)
        for ref_info in self.resource_manager_refs:
            update_single_referrer(ref_info.referrer, ref_info.ref_key, resource_manager)

        # update ctm_mgr refs
        ctm_manager = resource_manager.get_ctm_mgr()
        for ref_info in self.ctm_manager_refs:
            update_single_referrer(ref_info.referrer, ref_info.ref_key, ctm_manager)

        # update ctm_config refs
        ctm_config = ctm_manager.get_ctm_config()
        for ref_info in self.ctm_config_refs:
            update_single_referrer(ref_info.referrer, ref_info.ref_key, ctm_config)

        # update ctm_config_tcam refs
        ctm_config_tcam = test_racli.ctm_config_to_ctm_config_tcam(ctm_config)
        for ref_info in self.ctm_config_tcam_refs:
            update_single_referrer(ref_info.referrer, ref_info.ref_key, ctm_config_tcam)

        # update cem refs
        cem = resource_manager.get_cem()
        for ref_info in self.cem_refs:
            update_single_referrer(ref_info.referrer, ref_info.ref_key, cem)

        # update non-la_object non-primitive refs
        la_obj_oids = [o.oid() for o in la_dev.get_objects()]
        for obj_info, refs in self.non_la_object_non_primitive_refs.items():
            obj = obj_info['obj']
            nested_la_obj_info = obj_info['nested_la_obj_info']
            for ref_name, oid in nested_la_obj_info:
                # retrieve only if the la_object still exists;
                # if the la_object that should be referenced by field of the struct does not
                # exist anymore (its oid is not in the oid list of all la_device objects), then the
                # inner reference will remain None (invalidated in save python objects phase)
                if oid in la_obj_oids:
                    nested_la_obj = la_dev.get_object(oid).downcast()
                    exec('obj.{} = nested_la_obj'.format(ref_name))
            for ref_info in refs:
                update_single_referrer(ref_info.referrer, ref_info.ref_key, obj)

    def save_and_invalidate_objects(self, ignore=[]):
        gc.collect()
        all_objects = gc.get_objects()

        ignore.append(id(all_objects))
        ignore.append(id(inspect.currentframe()))

        for obj in all_objects:
            if is_swig_object(obj):
                self.add_object(obj, ignore)


def unload_kernel_module():
    if is_leaba_kernel_module_reload_enabled() and decor.is_hw_device():
        cmd = 'rmmod leaba_module'
        rc = os.system(cmd)
        if rc != 0:
            sys.stdout.writelines('WARM_BOOT: Failed removing leaba_module!')
            sys.stdout.flush()
            exit(1)


def load_kernel_module():
    if is_leaba_kernel_module_reload_enabled() and decor.is_hw_device():
        leaba_module_path = os.getenv('LEABA_KERNEL_MODULE_PATH')
        cmd = 'insmod {} m_add_wrapper_header=1'.format(leaba_module_path)
        if decor.is_gibraltar():
            cmd += ' m_gb_packet_dma_workaround=1'
        rc = os.system(cmd)
        if rc != 0:
            sys.stdout.write('WARM_BOOT: Failed installing leaba_module from {}!'.format(leaba_module_path))
            sys.stdout.flush()
            exit(1)


def close_sockets_and_store_pci_ports_info(la_dev):
    for la_dev_referrer in gc.get_referrers(la_dev):
        if isinstance(la_dev_referrer, dict) and \
                'pci_port_slice_to_network_interface_name' in la_dev_referrer and \
                'sockets_opened' in la_dev_referrer:
            if is_leaba_kernel_module_reload_enabled() and la_dev_referrer['sockets_opened']:
                # close sockets
                from uut_provider import hw_device
                for o in gc.get_referrers(la_dev_referrer):
                    if isinstance(o, hw_device):
                        o.close_sockets()
                        break
            for pci_port in la_dev.get_objects(sdk.la_object.object_type_e_PCI_PORT):
                slice = pci_port.get_slice()
                interface_name = la_dev.get_ll_device().get_network_interface_name(slice)
                la_dev_referrer['pci_port_slice_to_network_interface_name'][slice] = interface_name
            break


wb_disconnect_cnt = 0
wb_reconnect_cnt = 0

is_wb_in_progress = False
is_auto_wb_ignored = False


# Controls whether WB will be triggered by mutator/getter methods through WB ignore flag.
# Should be used to temporarily disable auto-WB in parts of code of utility functions that
# we don't want to trigger WB.
#
# For example:
# uut_provider.destroy(obj) is wrapper of method la_device.destroy(obj) that does python
# objects' invalidation in addition to destroying object. Triggering WB in the middle of
# that method can cause segfault because of invalid python objects.
def set_ignore_auto_wb(ignore):
    global is_auto_wb_ignored
    is_auto_wb_ignored = ignore


def warm_boot_disconnect(la_dev, warm_boot_file, duration_stats=None):
    global is_wb_in_progress
    is_wb_in_progress = True

    global wb_disconnect_cnt
    wb_disconnect_cnt += 1
    sys.stdout.write('Warm Boot disconnect [{}] ...\n'.format(wb_disconnect_cnt))
    sys.stdout.flush()

    # Store info about PCI ports, needed to inject packets.
    # This enables sending traffic while SDK is down (between warm_boot_disconnect()
    # and warm_boot_reconnect()).
    # Close sockets if opened.
    close_sockets_and_store_pci_ports_info(la_dev)

    start_py_obj_save = time.time()
    ignore = []
    ignore.append(id(inspect.currentframe()))
    sdk_py_objs_metadata = LeabaObjRefCollection(la_dev)
    sdk_py_objs_metadata.save_and_invalidate_objects(ignore)
    end_py_obj_save = time.time()

    la_dev.flush()

    start_sdk_disconnect = time.time()
    la_dev.warm_boot_disconnect()
    sdk.la_warm_boot_save_and_destroy(la_dev, warm_boot_file, True)
    end_sdk_disconnect = time.time()

    start_kernel_module_unload = time.time()
    unload_kernel_module()
    end_kernel_module_unload = time.time()

    if duration_stats:
        duration_stats.save_py_objects_duration = end_py_obj_save - start_py_obj_save
        duration_stats.sdk_disconnect_duration = end_sdk_disconnect - start_sdk_disconnect
        if decor.is_hw_device() and is_leaba_kernel_module_reload_enabled():
            duration_stats.unload_kernel_module_duration = end_kernel_module_unload - start_kernel_module_unload

    la_dev = None
    destroyed_la_objs_map.clear()
    gc.collect()

    return sdk_py_objs_metadata


def warm_boot_reconnect(sdk_py_objs_metadata, warm_boot_file, duration_stats=None):
    global wb_reconnect_cnt
    wb_reconnect_cnt += 1
    sys.stdout.write('Warm Boot reconnect  [{}] ...\n'.format(wb_reconnect_cnt))
    sys.stdout.flush()

    start_kernel_module_load = time.time()
    load_kernel_module()
    end_kernel_module_load = time.time()

    start_sdk_reconnect = time.time()
    la_dev = sdk.la_warm_boot_restore(sdk_py_objs_metadata.la_dev_path, warm_boot_file)
    la_dev.warm_boot_reconnect()
    end_sdk_reconnect = time.time()

    start_py_obj_restore = time.time()
    sdk_py_objs_metadata.restore_objects(la_dev)
    sdk_py_objs_metadata.reset()
    end_py_obj_restore = time.time()

    if duration_stats:
        if decor.is_hw_device() and is_leaba_kernel_module_reload_enabled():
            duration_stats.load_kernel_module_duration = end_kernel_module_load - start_kernel_module_load
        duration_stats.sdk_reconnect_duration = end_sdk_reconnect - start_sdk_reconnect
        duration_stats.restore_py_objects_duration = end_py_obj_restore - start_py_obj_restore

    global is_wb_in_progress
    is_wb_in_progress = False


def warm_boot(la_dev, duration_stats=None):
    warm_boot_filename = get_warm_boot_file_name()

    try:
        sdk_py_objs_metadata = warm_boot_disconnect(la_dev, warm_boot_filename, duration_stats)
        warm_boot_reconnect(sdk_py_objs_metadata, warm_boot_filename, duration_stats)
    except sdk.BaseException:
        if os.path.exists(warm_boot_filename):
            os.remove(warm_boot_filename)
        raise

    if os.path.exists(warm_boot_filename):
        os.remove(warm_boot_filename)


def is_called_from_test_function():
    test_file_name = None
    test_case_name = None

    for frame_info in inspect.stack():
        file_name = frame_info.filename
        function_name = frame_info.function
        if function_name == 'setUp' or function_name == 'setUpClass' or function_name == 'tearDown' or function_name == 'tearDownClass':
            return False
        if os.path.basename(file_name).startswith('test_') and os.path.basename(file_name).endswith('.py'):
            test_file_name = file_name
        if function_name.startswith('test_'):
            test_case_name = frame_info.function

    return test_file_name is not None and test_case_name is not None


wb_start_at_invocation = 0
auto_wb_cnt = 0


# list containing info about SDK la_object instances that are destroyed by calling device.destroy(obj);
# this is a list of tuples (<SWIG_object>, <la_object_oid>)
destroyed_la_objs_map = []


def warm_boot_getattribute(self, name):
    attr = object.__getattribute__(self, name)

    if not is_auto_wb_ignored and not is_wb_in_progress and callable(attr) and not name.startswith('__') \
            and name not in ['type', 'get_device', 'get_id', 'oid', 'get_init_phase']:    # avoid recursion

        class Wrapper:
            def __init__(self, la_obj, attr_name):
                self.la_obj = la_obj
                self.attr_name = attr_name

            def __call__(self, *args, **kwargs):
                # There are special cases where call to some mutator methods destroy some other SDK object.
                # If test holds reference to such object, it needs to be invalidated after the actual object
                # is destroyed, because the object doesn't exist anymore. Here we get info about referrers
                # of the objects that will be destroyed by specific SDK mutator. Actual invalidation of python
                # references is done after the SDK mutator method is executed.
                #
                # Covers these cases:
                # - la_lsr::delete_vpn_decap() - destroys object passed as first argument of type la_mpls_vpn_decap
                # - la_mac_port::reconfigure() - destroys old interface scheduler of type la_interface_scheduler
                py_objs_to_invalidate = []
                destroyed_la_obj_info = ()
                if (self.la_obj.type() == sdk.la_object.object_type_e_LSR) and (self.attr_name == 'delete_vpn_decap'):
                    device_id = self.la_obj.get_device().get_id()
                    vpn_decap_oid = args[0].oid()
                    py_objs_to_invalidate.extend(get_la_object_instances_by_oid(device_id, vpn_decap_oid))
                elif (self.la_obj.type() == sdk.la_object.object_type_e_MAC_PORT) and (self.attr_name == 'reconfigure'):
                    set_ignore_auto_wb(True)
                    scheduler = self.la_obj.get_scheduler()
                    set_ignore_auto_wb(False)
                    if scheduler is not None:
                        device_id = self.la_obj.get_device().get_id()
                        scheduler_id = scheduler.oid()
                        scheduler = None
                        py_objs_to_invalidate.extend(get_la_object_instances_by_oid(device_id, scheduler_id))
                elif (self.la_obj.type() == sdk.la_object.object_type_e_DEVICE) and (self.attr_name == 'destroy'):
                    # don't update destroyed_la_objs_map immediately because at this point we don't know if object
                    # will be destroyed successfully ('destroy' call may raise an exception); so append this info
                    # to destroyed_la_objs_map after actual 'destroy' method is called
                    destroyed_la_obj_info = (args[0].this, args[0].oid())

                # do WB if all conditions are met
                if (self.attr_name.split('_')[0] in (MUTATOR_KEYWORDS + GETTER_KEYWORDS)) and \
                        self.la_obj.get_device().get_init_phase() == sdk.la_device.init_phase_e_TOPOLOGY:
                    global wb_invocations_per_testcase, wb_invocations_per_sdk_method
                    if is_called_from_test_function():
                        key_per_method = '{}:{}'.format(self.la_obj.type(), self.attr_name)
                        if wb_invocations_per_testcase < MAX_WB_INVOCATIONS_PER_TESTCASE and wb_invocations_per_sdk_method.setdefault(
                                key_per_method, 0) < MAX_WB_INVOCATIONS_PER_SDK_METHOD:
                            wb_invocations_per_testcase += 1
                            wb_invocations_per_sdk_method[key_per_method] += 1

                            global auto_wb_cnt
                            auto_wb_cnt += 1

                            # trigger Warm Boot
                            if auto_wb_cnt < wb_start_at_invocation:
                                sys.stdout.write(
                                    '* IGNORING Warm Boot [{}], triggered by {}::{}()\n'.format(auto_wb_cnt, self.la_obj.__class__.__name__, self.attr_name))
                                sys.stdout.flush()
                            else:
                                sys.stdout.write(
                                    '* STARTING Warm Boot [{}], triggered by {}::{}()\n'.format(auto_wb_cnt, self.la_obj.__class__.__name__, self.attr_name))
                                sys.stdout.flush()
                                warm_boot(self.la_obj.get_device())
                    else:
                        wb_invocations_per_testcase = 0

                # execute actual method
                ret = object.__getattribute__(self.la_obj, self.attr_name)(*args, **kwargs)

                for obj in py_objs_to_invalidate:
                    for ref_info in get_obj_referrers(obj):
                        ref_key = obj if isinstance(ref_info.referrer, set) else ref_info.ref_key
                        update_single_referrer(ref_info.referrer, ref_key, None)

                if destroyed_la_obj_info:
                    destroyed_la_objs_map.append(destroyed_la_obj_info)

                return ret

        return Wrapper(self, name)

    return attr


def enable_auto_warm_boot():
    support_warm_boot()
    la_object_classes = [t[1] for t in inspect.getmembers(sdk, inspect.isclass) if hasattr(t[1], 'oid')]

    # SDK objects are also exposed through module leaba.hldcli; if this module is imported after leaba.sdk module in test,
    # all created SDK objects will be wrapped with classes from leaba.hldcli instead of leaba.sdk; because of that, we also
    # need to intercept calls to methods of la_object classes from leaba.hldcli, to make sure SDK objects are handled properly
    # in WB
    from leaba import hldcli
    la_object_classes += [t[1] for t in inspect.getmembers(hldcli, inspect.isclass) if hasattr(t[1], 'oid')]

    for la_object_class in la_object_classes:
        setattr(la_object_class, '__getattribute__', warm_boot_getattribute)

    global wb_start_at_invocation
    wb_start_at_invocation = int(os.environ.get('WB_START_AT_INVOCATION', 0))


def invalidate_la_object_python_references():
    all_objects = gc.get_objects()
    ignore = [id(all_objects), id(inspect.currentframe())]

    for obj in all_objects:
        if is_swig_object(obj) and is_la_object(obj):
            get_obj_referrers(obj, ignore, invalidate=True)

    all_objects = None
    obj = None
    gc.collect()


# remove tmp WB files
@atexit.register
def cleanup():
    for tmp_file in tmp_wb_files:
        if os.path.exists(tmp_file):
            os.remove(tmp_file)
