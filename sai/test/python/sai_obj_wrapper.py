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

from saicli import *
import sai_gen_attr_info
import sai_obj_info
import sai_packet_utils as PU
import sai_test_utils as TU
import pdb


class lsai_attrib_handling():
    def __init__(self):
        base_attrib_inst = self.base_attrib()
        self.attr_conv_class = {}

        self.attr_conv_class["sai_acl_action_data_t sai_object_id_t"] = self.acl_action_data_oid_attrib()
        self.attr_conv_class["sai_acl_action_data_t sai_object_list_t"] = self.acl_action_data_object_list_attrib()
        self.attr_conv_class["sai_acl_action_data_t sai_packet_action_t"] = self.acl_action_data_u32_attrib()
        self.attr_conv_class["sai_acl_action_data_t sai_uint8_t"] = self.acl_action_data_u8_attrib()

        self.attr_conv_class["sai_acl_field_data_t sai_acl_ip_type_t"] = self.acl_field_data_base_attrib("u32")
        self.attr_conv_class["sai_acl_field_data_t sai_acl_ip_frag_t"] = self.acl_field_data_base_attrib("u32")
        self.attr_conv_class["sai_acl_field_data_t sai_ip4_t"] = self.acl_field_data_ip4_attrib()
        self.attr_conv_class["sai_acl_field_data_t sai_ip6_t"] = self.acl_field_data_ip6_attrib()
        self.attr_conv_class["sai_acl_field_data_t sai_mac_t"] = self.acl_field_data_mac_attrib()
        self.attr_conv_class["sai_acl_field_data_t sai_object_list_t"] = self.acl_field_data_objlist_attrib()
        self.attr_conv_class["sai_acl_field_data_t sai_uint32_t"] = self.acl_field_data_base_attrib("u32")
        self.attr_conv_class["sai_acl_field_data_t sai_uint16_t"] = self.acl_field_data_base_attrib("u16")
        self.attr_conv_class["sai_acl_field_data_t sai_uint8_t"] = self.acl_field_data_base_attrib("u8")

        for type in [
            "enum",
            "sai_uint64_t",
            "sai_int64_t",
            "sai_uint32_t",
            "sai_int32_t",
            "sai_uint16_t",
            "sai_int16_t",
            "sai_uint8_t",
                "sai_int8_t"]:
            self.attr_conv_class[type] = base_attrib_inst

        # list types
        self.attr_conv_class["sai_object_list_t"] = self.object_list_attrib()
        self.attr_conv_class["sai_s32_list_t"] = self.s32_list_attrib()
        self.attr_conv_class["sai_u32_list_t"] = self.u32_list_attrib()
        self.attr_conv_class["sai_s8_list_t"] = self.s8_list_attrib()
        # u8_list is used for ipv6 creation in swig. No attribute using it

        self.attr_conv_class["sai_acl_capability_t"] = self.acl_capability_attrib()
        self.attr_conv_class["sai_acl_resource_list_t"] = self.acl_resource_list_attrib()
        self.attr_conv_class["bool"] = self.bool_attrib()
        self.attr_conv_class["char"] = self.char_attrib()
        self.attr_conv_class["sai_ip_address_t"] = self.ip_addr_attrib()
        self.attr_conv_class["sai_mac_t"] = self.mac_attrib()
        self.attr_conv_class["sai_object_id_t"] = self.oid_attrib()
        self.attr_conv_class["sai_pointer_t"] = self.pointer_attrib()
        self.attr_conv_class["sai_qos_map_list_t"] = self.qos_map_list_attrib()
        self.attr_conv_class["sai_u32_range_t"] = self.u32_range_attrib()
        self.attr_conv_class["sai_system_port_config_t"] = self.system_port_config_attrib()
        self.attr_conv_class["sai_system_port_config_list_t"] = self.system_port_config_list_attrib()
        self.attr_conv_class["sai_map_list_t"] = self.map_list_attrib()

    class base_attrib():
        def create_attribute(self, attr_id, val=0):
            return sai_attribute_t(attr_id, val)

        def print_attribute(self, attr):
            print("{0}: {1}".format(attr.id, self.attr_to_py(attr)))

        def attr_to_py(self, attr):
            return attr.value.u64

        # helper for comparing argument in Python format to argument we got back from sai
        def compare(self, py_val, sai_val):
            # return type will by list, so convert to list to be able to compare
            if isinstance(py_val, range):
                py_val = [*py_val]

            return py_val == sai_val

    class object_list_attrib(base_attrib):
        def create_attribute(self, attr_id, val=[0] * 100):
            return sai_attribute_t(attr_id, sai_object_list_t(val))

        def attr_to_py(self, attr):
            return sai_py_object_list(attr.value.objlist)

    class s32_list_attrib(base_attrib):
        def create_attribute(self, attr_id, val=[0] * 100):
            return sai_attribute_t(attr_id, sai_s32_list_t(val))

        def attr_to_py(self, attr):
            return sai_py_s32_list(attr.value.s32list)

    class u32_list_attrib(s32_list_attrib):
        def create_attribute(self, attr_id, val=[0] * 100):
            return sai_attribute_t(attr_id, sai_u32_list_t(val))

        def attr_to_py(self, attr):
            return sai_py_u32_list(attr.value.u32list)

    class s8_list_attrib(base_attrib):
        def create_attribute(self, attr_id, val=[0] * 100):
            return sai_attribute_t(attr_id, sai_s8_list_t(val))

        def attr_to_py(self, attr):
            return sai_py_bytes_list(attr.value.s8list)

    class acl_action_data_oid_attrib(base_attrib):
        def create_attribute(self, attr_id, val=[False, 0]):
            return sai_attribute_t(attr_id, sai_acl_action_data_t(val[0], val[1]))

        def attr_to_py(self, attr):
            return [attr.value.aclaction.enable, attr.value.aclaction.parameter.oid]

    class acl_action_data_u32_attrib(base_attrib):
        def create_attribute(self, attr_id, val=[False, 19]):
            return sai_attribute_t(attr_id, sai_acl_action_data_t(val[0], val[1]))

        def attr_to_py(self, attr):
            return [attr.value.aclaction.enable, attr.value.aclaction.parameter.u32]

    class acl_action_data_u8_attrib(base_attrib):
        def create_attribute(self, attr_id, val=[False, 7]):
            return sai_attribute_t(attr_id, sai_acl_action_data_t(val[0], val[1]))

        def attr_to_py(self, attr):
            return [attr.value.aclaction.enable, attr.value.aclaction.parameter.u8]

    class acl_action_data_object_list_attrib(base_attrib):
        def create_attribute(self, attr_id, val=[False, [0] * 10]):
            return sai_attribute_t(attr_id, sai_acl_action_data_t(val[0], sai_object_list_t(val[1])))

        def attr_to_py(self, attr):
            return [attr.value.aclaction.enable, sai_py_object_list(attr.value.aclaction.parameter.objlist)]

    class acl_capability_attrib(base_attrib):
        def create_attribute(self, attr_id, val=[False, 2]):
            return sai_attribute_t(attr_id, sai_acl_capability_t(val[0], val[1]))

        def attr_to_py(self, attr):
            return [attr.value.aclcapability.is_action_list_mandatory, sai_py_s32_list(attr.value.aclcapability.action_list)]

    class acl_field_data_base_attrib(base_attrib):
        def __init__(self, inner_type):
            self.get_data = "attr.value.aclfield.get_data_{0}()".format(inner_type)
            self.get_mask = "attr.value.aclfield.get_mask_{0}()".format(inner_type)

        def create_attribute(self, attr_id, val=[False, 0, 0]):
            return sai_attribute_t(attr_id, sai_acl_field_data_t(val[0], val[1], val[2]))

        def attr_to_py(self, attr):
            if not attr.value.aclfield.enable:
                # in case of false, other values are random
                return [False, 0, 0]
            else:
                return [attr.value.aclfield.enable, eval(self.get_data), eval(self.get_mask)]

    class acl_field_data_ip4_attrib(base_attrib):
        def create_attribute(self, attr_id, val=[False, 0, 0]):
            return sai_attribute_t(attr_id, sai_acl_field_data_t(val[0], PU.sai_ip(val[1]), PU.sai_ip(val[2])))

        def attr_to_py(self, attr):
            if not attr.value.aclfield.enable:
                # in case of false, other values are random
                return [False, 0, 0]
            else:
                return [
                    attr.value.aclfield.enable, PU.sai_ip_to_string(
                        attr.value.aclfield.get_data_ip4()), PU.sai_ip_to_string(
                        attr.value.aclfield.get_mask_ip4())]

    class acl_field_data_ip6_attrib(acl_field_data_ip4_attrib):
        def attr_to_py(self, attr):
            if not attr.value.aclfield.enable:
                # in case of false, other values are random
                return [False, 0, 0]
            else:
                return [
                    attr.value.aclfield.enable, PU.sai_ip_to_string(
                        attr.value.aclfield.get_data_ip6()), PU.sai_ip_to_string(
                        attr.value.aclfield.get_mask_ip6())]

    class acl_field_data_mac_attrib(base_attrib):
        def create_attribute(self, attr_id, val=[False, "00:00:00:00:00:00", "00:00:00:00:00:00"]):
            return sai_attribute_t(attr_id, sai_acl_field_data_t(val[0], PU.sai_mac(val[1]), PU.sai_mac(val[2])))

        def attr_to_py(self, attr):
            if not attr.value.aclfield.enable:
                # in case of false, other values are random
                return [False, 0, 0]
            else:
                return [
                    attr.value.aclfield.enable, PU.sai_attr_to_mac(
                        attr.value.aclfield.get_data_mac()), PU.sai_attr_to_mac(
                        attr.value.aclfield.get_mask_mac())]

    class acl_field_data_objlist_attrib(base_attrib):
        def create_attribute(self, attr_id, val=[False, [0] * 5, 0]):
            return sai_attribute_t(attr_id, sai_acl_field_data_t(val[0], sai_object_list_t(val[1])))

        def attr_to_py(self, attr):
            if not attr.value.aclfield.enable:
                # in case of false, other values are random
                return [False, [], 0]
            else:
                objlist = list(attr.value.aclfield.data.objlist.to_pylist())
                return [attr.value.aclfield.enable, objlist, 0]

    class acl_resource_list_attrib(base_attrib):
        def create_attribute(self, attr_id, val=0):
            return sai_attribute_t(attr_id, sai_acl_resource_list_t(10))

        def attr_to_py(self, attr):
            res = []
            for x in range(attr.value.aclresource.count):
                res.append([attr.value.aclresource.get_index(x).bind_point,
                            attr.value.aclresource.get_index(x).stage,
                            attr.value.aclresource.get_index(x).avail_num])
            return res

    class bool_attrib(base_attrib):
        def attr_to_py(self, attr):
            return attr.value.booldata

    # type char means the type is 'char chardata[32]'
    class char_attrib(base_attrib):
        def attr_to_py(self, attr):
            return attr.value.chardata

    class ip_addr_attrib(base_attrib):
        def create_attribute(self, attr_id, val=0):
            return sai_attribute_t(attr_id, PU.sai_ip(val))

        def attr_to_py(self, attr):
            if attr.value.ipaddr.addr_family == SAI_IP_ADDR_FAMILY_IPV4:
                return PU.sai_ip_to_string(sai_ip_address_t(attr.value.ipaddr.addr.ip4))
            else:
                return PU.sai_ip_to_string(sai_ip_address_t(attr.value.ipaddr.addr.ip6))

    class mac_attrib(base_attrib):
        def create_attribute(self, attr_id, val="00:00:00:00:00:00"):
            return sai_attribute_t(attr_id, PU.sai_mac(val))

        def attr_to_py(self, attr):
            ret = []
            return PU.sai_attr_to_mac(attr)

    class oid_attrib(base_attrib):
        def create_attribute(self, attr_id, val=0):
            return sai_attribute_t(attr_id, val)

        def attr_to_py(self, attr):
            return attr.value.oid

    class pointer_attrib(base_attrib):
        def attr_to_py(self, attr):
            # Can't compare pointers from different runs. Just check if it is null or not
            if attr.value.ptr != 0:
                return 0xabab
            else:
                return 0

    class qos_map_list_attrib(base_attrib):
        def create_attribute(self, attr_id, val= None):
            if val is None:
                val = []
                for i in range(100):
                    if (TU.is_sai_15x()):
                        val.append([[0] * 7, [0] * 7])
                    else:
                        val.append([[0] * 8, [0] * 8])
            return sai_attribute_t(attr_id, sai_qos_map_list_t(val))

        def attr_to_py(self, attr):
            return sai_py_qos_map_list_t(attr.value.qosmap).list

    class u32_range_attrib(base_attrib):
        def create_attribute(self, attr_id, val=[0, 0]):
            return sai_attribute_t(attr_id, sai_u32_range_t(val[0], val[1]))

        def attr_to_py(self, attr):
            return [attr.value.u32range.min, attr.value.u32range.max]

    class system_port_config_attrib(base_attrib):
        def create_attribute(self, attr_id, val=[0] * 6):
            sp_config = sai_system_port_config_t(val)
            return sai_attribute_t(attr_id, sp_config)

        def attr_to_py(self, attr):
            return [attr.value.sysportconfig.port_id,
                    attr.value.sysportconfig.attached_switch_id,
                    attr.value.sysportconfig.attached_core_index,
                    attr.value.sysportconfig.attached_core_port_index,
                    attr.value.sysportconfig.speed,
                    attr.value.sysportconfig.num_voq]

    class system_port_config_list_attrib(base_attrib):
        # NB: Python list '*' operator doesn't deep-copy
        def create_attribute(self, attr_id, val=[[0] * 6 for i in range(256)]):
            cfg_list = sai_system_port_config_list_t(val)
            return sai_attribute_t(attr_id, cfg_list)

        def attr_to_py(self, attr):
            # Not implemented
            return None

    class map_list_attrib(base_attrib):
        def create_attribute(self, attr_id, val=[[0] * 100, [0] * 100]):
            return sai_attribute_t(attr_id, sai_map_list_t(val))

        def attr_to_py(self, attr):
            return sai_py_map_list_t(attr.value.maplist).list

    def create_attribute(self, attr_type, attr_id, val=None):
        if attr_type not in self.attr_conv_class:
            print("attribute type {0} not supported".format(attr_type))
            return None
        if val is not None:
            return self.attr_conv_class[attr_type].create_attribute(attr_id, val)
        else:
            return self.attr_conv_class[attr_type].create_attribute(attr_id)

    def attr_to_py(self, attr_type, attr):
        if attr_type not in self.attr_conv_class:
            print("attribute type {0} not supported".format(attr_type))
            return None
        return self.attr_conv_class[attr_type].attr_to_py(attr)

    def compare(self, attr_type, py_val, sai_val):
        return self.attr_conv_class[attr_type].compare(py_val, sai_val)


class lsai_obj_wrapper():
    def __init__(self, tb):
        self._debug = False
        self.tb = tb
        self.mode = None
        self.attrib_handle = lsai_attrib_handling()
        self.obj_handle = sai_obj_info.lsai_obj_info(tb)
        self.attr_info = sai_gen_attr_info.all_sai_attributes_info

    def set_mode(self, mode):
        file_name = "sai_obj_wrap_save.txt"
        # going out of save mod
        if self.mode == "save" and mode != "save":
            self.save_file.close()

        # getting into save mode
        if mode == "save" and self.mode != "save":
            self.save_file = open(file_name, "wt")

        # going into "wb_init" mode
        if mode == "wb_init" and self.mode != "wb_init":
            self.save_file = open(file_name, "r")
            self.file_cont = self.save_file.read().split("\n")
            self.file_cont.pop()  # last empty line
            self.save_file.close()
            self.file_index = 0

        self.mode = mode

    def get_attr_capability(self, obj_type, attr_id):
        try:
            ret = self.tb.query_attribute_capability(obj_type, attr_id)
        except BaseException:
            ret = {"create": False, "get": False, "set": False}
        return ret

    def create_object(self, obj_type, extra_arg, py_attrs, verify=[False, False], do_warm_boot=False):
        if self.mode == "wb_init":
            # we have a file with lines in the form of:
            # object_type created_obj_id
            # verifying that obj_type matches the object_type from the file
            # insted of creating an object, we return the created_obj_id from last run
            file_line = self.file_cont[self.file_index].split(" ")
            assert int(file_line[0]) == obj_type
            # will be none in case create function did not return obj_id (create_route/inseg_entry, etc)
            if file_line[1] == "None":
                ret_val = None
            else:
                ret_val = int(file_line[1])

            self.file_index += 1
            # After we finished replaying the file, switch to normal operation mode
            if self.file_index == len(self.file_cont):
                self.mode = None
            if self._debug:
                print("returning {0} {1} without creating".format(obj_type, ret_val))
            return ret_val

        verify_attrs = verify[0]
        verify_add = verify[1]
        if self._debug:
            print("Creating object of type {0} with attributes:".format(obj_type))
            for attr in py_attrs:
                attr_id = attr[0]
                attr_val = attr[1]
                print("  {0}: {1}".format(self.attr_info[obj_type][attr_id]["name"], attr[1]))

        sai_attrs = []
        for attr in py_attrs:
            attr_id = attr[0]
            attr_val = attr[1]
            attr_type = self.attr_info[obj_type][attr_id]["type"]
            sai_attrs.append(self.attrib_handle.create_attribute(attr_type, attr_id, attr_val))

        create_func = self.obj_handle.create_func(obj_type)
        if verify_add:
            num_objs_before, obj_list_before = self.tb.get_object_keys(obj_type)
        ret_obj_id = create_func(extra_arg, sai_attrs)
        if verify_add:
            num_objs_after, obj_list_after = self.tb.get_object_keys(obj_type)
            assert(num_objs_after == num_objs_before + 1)
            # obj in obj_list_after does not work because obj_list_after is a swig defined object of type int_array
            obj_found = False
            for index in range(0, num_objs_after):
                if obj_list_after[index] == ret_obj_id:
                    obj_found = True
            assert(obj_found)

        if verify_attrs:
            for attr in py_attrs:
                if len(attr) > 2 and attr[2] == "skip_verify":
                    continue
                attr_id = attr[0]
                py_attr_val = attr[1]
                attr_type = self.attr_info[obj_type][attr_id]["type"]
                if ret_obj_id is None:
                    # for route/neighbor/fdb/inseg_entry
                    # these types return SAI_STATUS_SUCCESS, not object_id
                    get_attr_val = self.get_attr([obj_type, extra_arg], attr_id)
                else:
                    get_attr_val = self.get_attr(ret_obj_id, attr_id)
                assert self.attrib_handle.compare(
                    attr_type, py_attr_val, get_attr_val), "attr_type({}), attr_id({}), py_attr_val({}), get_attr_val({})".format(
                    attr_type, attr_id, py_attr_val, get_attr_val)

        if do_warm_boot:
            self.tb.do_warm_boot()
        else:
            self.tb.do_warm_boot(type="wb_create")

        if self.mode == "save":
            self.save_file.write("{0} {1}\n".format(obj_type, ret_obj_id))

        return ret_obj_id

    def remove_object(self, obj_id, verify_remove=False):
        if self.mode == "wb_init":
            return
        # for cases like route_entry, neighbor_entry in which the key is not object id
        if isinstance(obj_id, list):
            obj_type = obj_id[0]
            obj_id = obj_id[1]
            if self._debug:
                print("Removing object of type {0}".format(obj_type))
        else:
            obj_type = obj_id >> 56  # 8 msbs of obj_id are the obj_type
            if self._debug:
                print("Removing object of type {0} oid {1}".format(obj_type, hex(obj_id)))

        remove_func = self.obj_handle.remove_func(obj_type)
        if verify_remove:
            num_objs_before, obj_list_before = self.tb.get_object_keys(obj_type)
        remove_func(obj_id)
        if verify_remove:
            num_objs_after, obj_list_after = self.tb.get_object_keys(obj_type)
            assert(num_objs_after == num_objs_before - 1)

    def set_attr(self, obj_id, attr_id, val, verify=False):
        orig_obj_id = obj_id
        # for cases like route_entry, neighbor_entry in which the key is not object id
        if isinstance(obj_id, list):
            obj_type = obj_id[0]
            obj_id = obj_id[1]
        else:
            obj_type = obj_id >> 56  # 8 msbs of obj_id are the obj_type
        set_func = self.obj_handle.set_func(obj_type)
        attr_type = self.attr_info[obj_type][attr_id]["type"]
        attr = self.attrib_handle.create_attribute(attr_type, attr_id, val)
        set_func(obj_id, attr)
        if verify:
            get_attr_val = self.get_attr(orig_obj_id, attr_id)
            assert self.attrib_handle.compare(attr_type, val, get_attr_val)
            if self._debug:
                print("verified {0} {1}".format(orig_obj_id, attr_id))

    def get_attr_by_type(self, obj_type, obj_id, attr_id):
        if isinstance(obj_id, int):
            return self.get_attr(obj_id, attr_id)
        else:
            return self.get_attr([obj_type, obj_id], attr_id)

    def get_attr(self, obj_id, attr_id):
        # for cases like route_entry, neighbor_entry in which the key is not object id
        if isinstance(obj_id, list):
            obj_type = obj_id[0]
            obj_id = obj_id[1]
        else:
            obj_type = obj_id >> 56  # 8 msbs of obj_id are the obj_type
        get_func = self.obj_handle.get_func(obj_type)
        attr_type = self.attr_info[obj_type][attr_id]["type"]
        attr_name = self.attr_info[obj_type][attr_id]["name"]
        attr = self.attrib_handle.create_attribute(attr_type, attr_id)
        if attr is None:
            return None

        try:
            get_func(obj_id, 1, attr)
        except Exception as e:
            err_str = "{0}".format(e)
            err_num = int(err_str.split(":")[1][1:])
            # no point trying to get unsupported or unimplemented attribute over and over again
            if err_num == SAI_STATUS_NOT_IMPLEMENTED or err_num == SAI_STATUS_ATTR_NOT_IMPLEMENTED_0 or err_num == SAI_STATUS_NOT_SUPPORTED or err_num == SAI_STATUS_ATTR_NOT_SUPPORTED_0:
                # del self.attr_info[obj_type][attr_id] - Can't del the attribute, because it might support only set and not get
                pass
            else:
                # only cases allowed to fail
                if (obj_type == SAI_OBJECT_TYPE_NEXT_HOP and attr_id == SAI_NEXT_HOP_ATTR_TUNNEL_ID) or (obj_type == SAI_OBJECT_TYPE_ROUTER_INTERFACE) or (
                        obj_type == SAI_OBJECT_TYPE_ACL_ENTRY) or (attr_id == SAI_BRIDGE_PORT_ATTR_VLAN_ID and err_num == SAI_STATUS_INVALID_OBJECT_ID):
                    pass
                else:
                    print("get attribute {0} failed with error {1}".format(attr_name, e))
            return None
        if attr is not None:
            py_attr = self.attrib_handle.attr_to_py(attr_type, attr)
        return py_attr
