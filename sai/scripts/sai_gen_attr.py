#!/usr/bin/python
# BEGIN_LEGAL
#
# Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

# This file is used to generate auto_gen_attr.h and auto_tostrings.cpp
# get new SAI dir, do make and xml directory is create
# cd to xml
# <this script> -d .
#
import string
import logging
import argparse
import os
import re

from xml.etree.ElementTree import parse

do_not_print = [
    #'SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6',
    #'SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6',
    #'SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IPV6',
    #'SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IPV6',
    #'SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_IPV6',
    #'SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_IPV6',
    #'SAI_PORT_ATTR_EYE_VALUES'
] 

attr_value_dict = {
        'bool' : 'booldata',
        'char' : 'chardata[32]',
        'sai_uint8_t' : 'u8',
        'sai_int8_t' : 's8',
        'sai_uint16_t' : 'u16',
        'sai_int16_t' : 's16',
        'sai_uint32_t' : 'u32',
        'sai_int32_t' : 's32',
        'sai_uint64_t' : 'u64',
        'sai_int64_t' : 's64',
        'sai_pointer_t' : 'ptr',
        'sai_mac_t' : 'mac',
        'sai_ip4_t' : 'ip4',
        'sai_ip6_t' : 'ip6',
        'sai_ip_address_t' : 'ipaddr',
        'sai_ip_prefix_t' : 'ipprefix',
        'sai_object_id_t' : 'oid',
        'sai_object_list_t' : 'objlist',
        'sai_u8_list_t' : 'u8list',
        'sai_s8_list_t' : 's8list',
        'sai_u16_list_t' : 'u16list',
        'sai_s16_list_t' : 's16list',
        'sai_u32_list_t' : 'u32list',
        'sai_s32_list_t' : 's32list',
        'sai_u32_range_t' : 'u32range',
        'sai_s32_range_t' : 's32range',
        'sai_vlan_list_t' : 'vlanlist',
        'sai_qos_map_list_t' : 'qosmap',
        'sai_map_list_t' : 'maplist',
        'sai_acl_field_data_t' : 'aclfield',
        'sai_acl_action_data_t' : 'aclaction',
        'sai_acl_capability_t' : 'aclcapability',
        'sai_acl_resource_list_t' : 'aclresource',
        'sai_tlv_list_t' : 'tlvlist',
        'sai_segment_list_t' : 'segmentlist',
        'sai_ip_address_list_t' : 'ipaddrlist',
        'sai_timespec_t' : 'timespec',
        'sai_port_eye_values_list_t' : 'porteyevalues',
        'sai_macsec_auth_key_t' : 'macsecauthkey',
        'sai_port_err_status_list_t' : 'porterror',
        'sai_fabric_port_reachability_t' : 'reachability',
        'sai_macsec_sak_t' : 'macsecsak',
        'sai_macsec_salt_t' :  'macsecsalt',
        'sai_system_port_config_list_t' : 'sysportconfiglist',
        'sai_system_port_config_t' : 'sysportconfig',
        }

class dictlist(dict):
    def __setitem__(self, key, value):
        try:
            self[key]
        except KeyError:
            super(dictlist, self).__setitem__(key, [])

        if value in self[key]:
            return
        self[key].append(value)


def_temp_dict = dictlist()
value_of_dict = {}
attr_struct_dict = {}
enum_dict = {}
base_dict = {}
scratch_list = []
attr_structs = set()

filetype_regex = '(.*_8h\.xml)$'

def is_hex(s):
    try:
        n = int(s, 16)
        return True, n
    except ValueError:
        return False, 0

def collect_files(user_dirs):
    collected_files = []

    for root in user_dirs:
        for directory, sub_directories, files in os.walk(root):
            for file in files:
                path = os.path.join(directory, file)
                if re.search(filetype_regex, path):
                    collected_files.append(path)

    return collected_files

def stripUnder(inname):
    if inname[0] == '_':
        alname = inname[1:]
    else:
        alname = inname
    return alname


def parse_enum(xfile): 
    xparse = parse(xfile)
    if xparse == None:
        return
    doxygen = xparse.getroot()
    for compounddef in doxygen:
        for innerclass in compounddef:
            for memberdef in innerclass:
                name = memberdef.find('name')
                if name == None:
                    continue
                kind = memberdef.get('kind')
                if kind != None and kind == "enum":
                    alname = stripUnder(name.text)
                    if alname in attr_value_dict:
                        continue
                    attr_value_dict[alname] = 's32'


#def collect_attr_type_def(alname, enumvalue, base):
def collect_attr_type_def(alname, enumvalue, sai_ver):
    enumName = enumvalue.find('name')
    initializer = enumvalue.find('initializer')
    if enumName != None and "ATTR_START" in enumName.text:
        return
    if initializer != None:
        exist_text = initializer.text.split('=')[1].split()[0] 
        if exist_text in value_of_dict:
            return
        if exist_text in scratch_list:
            return
        if "ATTR_START" in initializer.text:
            initializer = None
    if enumName != None:
        if alname in enum_dict:
            if enumName.text not in enum_dict[alname]:
                enum_dict[alname].append(enumName.text)
        else:
            enum_dict[alname] = [enumName.text]
        
        for detaileddescription in enumvalue:
            for para in detaileddescription:
                for simplesect in para:
                    for para in simplesect:
                        try:
                            paralist = para.text.split()
                            tp = paralist[0]
                            if paralist[1] == "sai_acl_action_data_t" or paralist[1] == "sai_acl_field_data_t":
                                tpname = [paralist[1], paralist[2]]
                            else:
                                tpname = [paralist[1]]
                        except:
                            continue
                        if tp == "@@type":
                            try:
                                value_of_dict[enumName.text] = tpname
                                def_temp_dict[alname] = tpname
                                tmp_type = attr_value_dict[tpname[0]]
                                if len(tpname) > 1:
                                    tmpval = tpname[1]
                                    if tpname[0] == 'sai_acl_field_data_t':
                                        if tmpval == 'bool':
                                            tmpval = 'sai_uint8_t'
                                        elif tmpval == 'sai_object_id_t':
                                            if sai_ver > 0x010502:
                                                tmpval = 'sai_uint64_t'
                                            else:
                                                tmpval = 'sai_uint32_t' 
                                        elif tmpval == 'sai_object_list_t':
                                            tmpval = 'sai_u8_list_t'
                                    tmp_type = make_attr_struct(tmp_type,attr_value_dict[tmpval])
                                attr_struct_dict[enumName.text] = make_attr_struct(alname,tmp_type)
                                return
                            except:
                                return
    
            for simplesect in detaileddescription:
                for para in simplesect:
                    try:
                        paralist = para.text.split()
                        tp = paralist[0]
                        if paralist[1] == "sai_acl_action_data_t" or paralist[1] == "sai_acl_field_data_t":
                            tpname = [paralist[1], paralist[2]]
                        else:
                            tpname = [paralist[1]]
                    except:
                        continue
                    if tp == "@@type":
                        try:
                            value_of_dict[enumName.text] = tpname
                            def_temp_dict[alname] = tpname
                            tmp_type = attr_value_dict[tpname[0]]
                            if len(tpname) > 1:
                                tmpval = tpname[1]
                                if tpname[0] == 'sai_acl_field_data_t':
                                    if tmpval == 'bool':
                                        tmpval = 'sai_uint8_t'
                                    elif tmpval == 'sai_object_id_t':
                                        if sai_ver > 0x010502:
                                            tmpval = 'sai_uint64_t'
                                        else:
                                            tmpval = 'sai_uint32_t'
                                    elif tmpval == 'sai_object_list_t':
                                        tmpval = 'sai_u8_list_t'
                                tmp_type = make_attr_struct(tmp_type,attr_value_dict[tmpval])
                            attr_struct_dict[enumName.text] = make_attr_struct(alname,tmp_type)
                            return
                        except:
                            return
    

def collect_type_def(alname, enumvalue):
    enumName = enumvalue.find('name')
    if enumName != None:
        if alname in enum_dict:
            if enumName.text not in enum_dict[alname]:
                enum_dict[alname].append(enumName.text)
        else:
            enum_dict[alname] = [enumName.text]

def parse_attr(xfile, sai_ver): 
    xparse = parse(xfile)
    if xparse == None:
        return
    doxygen = xparse.getroot()
    for compounddef in doxygen:
        for innerclass in compounddef:
            for memberdef in innerclass:
                name = memberdef.find('name')
                if name == None or "_sai_" not in name.text or "_t" not in name.text:
                    continue

                alname = stripUnder(name.text)
                #if "_attr_t" in name.text:
                alname = stripUnder(name.text)
                for enumvalue in memberdef:
                    collect_attr_type_def(alname, enumvalue, sai_ver)
                    collect_type_def(alname, enumvalue)


def make_attr_struct(attr, tname):
    for ch in "[]":
        tname = tname.replace(ch,"_")
    return attr+"_"+tname


def write_to_file(writer, sai_ver):
    logging.debug("writing header in .cpp")
    writer.write("// Automatically generated file - don't change\n")
    writer.write("// \n\n")

    writer.write("#ifndef ___SAI_GEN_ATTR_H__\n")
    writer.write("#define ___SAI_GEN_ATTR_H__\n\n")

    writer.write("// clang-format off\n")

    writer.write('extern "C" {\n')
    writer.write("#include <sai.h>\n")
    writer.write("}\n")
    writer.write("#include <sstream>\n")
    writer.write("#include <unordered_map>\n")

    writer.write("#define DEFINE_salt_attr_templ(_attrT, _field, _struct) \\\n")
    writer.write("template <_attrT V, typename D> \\\n")
    writer.write("struct _struct { \\\n")
    writer.write("    static void get (const sai_attribute_value_t& attr_value, D& d) \\\n")
    writer.write("       {memcpy(d, attr_value._field, 12);} \\\n")
    writer.write("    static void set (sai_attribute_value_t& attr_value, D d) \\\n")
    writer.write("       {memcpy(attr_value._field, d, 12);} \\\n")
    writer.write("};\n\n")

    writer.write("#define DEFINE_sak_attr_templ(_attrT, _field, _struct) \\\n")
    writer.write("template <_attrT V, typename D> \\\n")
    writer.write("struct _struct { \\\n")
    writer.write("    static void get (const sai_attribute_value_t& attr_value, D& d) \\\n")
    writer.write("       {memcpy(d, attr_value._field, 32);} \\\n")
    writer.write("    static void set (sai_attribute_value_t& attr_value, D d) \\\n")
    writer.write("       {memcpy(attr_value._field, d, 32);} \\\n")
    writer.write("};\n\n")

    writer.write("#define DEFINE_authkey_attr_templ(_attrT, _field, _struct) \\\n")
    writer.write("template <_attrT V, typename D> \\\n")
    writer.write("struct _struct { \\\n")
    writer.write("    static void get (const sai_attribute_value_t& attr_value, D& d) \\\n")
    writer.write("       {memcpy(d, attr_value._field, 16);} \\\n")
    writer.write("    static void set (sai_attribute_value_t& attr_value, D d) \\\n")
    writer.write("       {memcpy(attr_value._field, d, 16);} \\\n")
    writer.write("};\n\n")

    writer.write("#define DEFINE_ip6_attr_templ(_attrT, _field, _struct) \\\n")
    writer.write("template <_attrT V, typename D> \\\n")
    writer.write("struct _struct { \\\n")
    writer.write("    static void get (const sai_attribute_value_t& attr_value, D& d) \\\n")
    writer.write("       {memcpy(d, attr_value._field, 16);} \\\n")
    writer.write("    static void set (sai_attribute_value_t& attr_value, D d) \\\n")
    writer.write("       {memcpy(attr_value._field, d, 16);} \\\n")
    writer.write("};\n\n")

    writer.write("#define DEFINE_mac_attr_templ(_attrT, _field, _struct) \\\n")
    writer.write("template <_attrT V, typename D> \\\n")
    writer.write("struct _struct { \\\n")
    writer.write("    static void get (const sai_attribute_value_t& attr_value, D& d) \\\n")
    writer.write("       {memcpy(d, attr_value._field, 6);} \\\n")
    writer.write("    static void set (sai_attribute_value_t& attr_value, D d) \\\n")
    writer.write("       {memcpy(attr_value._field, d, 6);} \\\n")
    writer.write("};\n\n")

    writer.write("#define DEFINE_attr_templ(_attrT, _field, _struct) \\\n")
    writer.write("template <_attrT V, typename D> \\\n")
    writer.write("struct _struct { \\\n")
    writer.write("    static D get (const sai_attribute_value_t& attr_value) \\\n")
    writer.write("       {return (D) attr_value._field; } \\\n")
    writer.write("    static void set (sai_attribute_value_t& attr_value, D d) \\\n")
    writer.write("       {attr_value._field = (D) d;} \\\n")
    writer.write("};\n\n")

    writer.write("#define DEFINE_aclaction_attr_templ(_attrT, _field, _struct) \\\n")
    writer.write("template <_attrT V, typename D> \\\n")
    writer.write("struct _struct { \\\n")
    writer.write("    static void get (const sai_attribute_value_t& attr_value, D& d) \\\n")
    writer.write("       {int s = sizeof(D); \\\n")
    writer.write("        memcpy(&d, &attr_value.aclaction.parameter._field, s); } \\\n")
    writer.write("    static void set (sai_attribute_value_t& attr_value, D d) \\\n")
    writer.write("       {int s = sizeof(D); \\\n")
    writer.write("        memcpy(&attr_value.aclaction.parameter._field, &d, s);} \\\n")
    writer.write("};\n\n")
    
    writer.write("#define DEFINE_aclfield_attr_templ(_attrT, _field, _struct) \\\n")
    writer.write("template <_attrT V, typename D> \\\n")
    writer.write("struct _struct { \\\n")
    writer.write("    static void get_data (const sai_attribute_value_t& attr_value, D& d) \\\n")
    writer.write("       {int s = sizeof(D); \\\n")
    writer.write("        memcpy(&d, &attr_value.aclfield.data._field, s); } \\\n")
    writer.write("    static void set_data (sai_attribute_value_t& attr_value, D d) \\\n")
    writer.write("       {int s = sizeof(D); \\\n")
    writer.write("        memcpy(&attr_value.aclfield.data._field, &d, s);} \\\n")
    writer.write("    static void get_mask (const sai_attribute_value_t& attr_value, D& d) \\\n")
    writer.write("       {int s = sizeof(D); \\\n")
    writer.write("        memcpy(&d, &attr_value.aclfield.mask._field, s); } \\\n")
    writer.write("    static void set_mask (sai_attribute_value_t& attr_value, D d) \\\n")
    writer.write("       {int s = sizeof(D); \\\n")
    writer.write("        memcpy(&attr_value.aclfield.mask._field, &d, s);} \\\n")
    writer.write("};\n\n")

    writer.write("#define get_aclaction_attr_value(attr_def, attr_value, value) \\\n")
    writer.write("        attr_def##_VAL::get(attr_value, value)\n\n")

    writer.write("#define set_aclaction_attr_value(attr_def, attr_value, value) \\\n")
    writer.write("        attr_def##_VAL::set(attr_value, value)\n\n")

    writer.write("#define get_data_aclfield_attr_value(attr_def, attr_value, value) \\\n")
    writer.write("        attr_def##_VAL::get_data(attr_value, value)\n\n")

    writer.write("#define set_data_aclfield_attr_value(attr_def, attr_value, value) \\\n")
    writer.write("        attr_def##_VAL::set_data(attr_value, value)\n\n")

    writer.write("#define get_mask_aclfield_attr_value(attr_def, attr_value, value) \\\n")
    writer.write("        attr_def##_VAL::get_mask(attr_value, value)\n\n")

    writer.write("#define set_mask_aclfield_attr_value(attr_def, attr_value, value) \\\n")
    writer.write("        attr_def##_VAL::set_mask(attr_value, value)\n\n")

    writer.write("#define get_salt_attr_value(attr_def, attr_value, value) \\\n")
    writer.write("        attr_def##_VAL::get(attr_value, value)\n\n")

    writer.write("#define set_salt_attr_value(attr_def, attr_value, value) \\\n")
    writer.write("        attr_def##_VAL::set(attr_value, value)\n\n")

    writer.write("#define get_sak_attr_value(attr_def, attr_value, value) \\\n")
    writer.write("        attr_def##_VAL::get(attr_value, value)\n\n")

    writer.write("#define set_sak_attr_value(attr_def, attr_value, value) \\\n")
    writer.write("        attr_def##_VAL::set(attr_value, value)\n\n")

    writer.write("#define get_authkey_attr_value(attr_def, attr_value, value) \\\n")
    writer.write("        attr_def##_VAL::get(attr_value, value)\n\n")

    writer.write("#define set_authkey_attr_value(attr_def, attr_value, value) \\\n")
    writer.write("        attr_def##_VAL::set(attr_value, value)\n\n")

    writer.write("#define get_ip6_attr_value(attr_def, attr_value, value) \\\n")
    writer.write("        attr_def##_VAL::get(attr_value, value)\n\n")

    writer.write("#define set_ip6_attr_value(attr_def, attr_value, value) \\\n")
    writer.write("        attr_def##_VAL::set(attr_value, value)\n\n")

    writer.write("#define get_mac_attr_value(attr_def, attr_value, value) \\\n")
    writer.write("        attr_def##_VAL::get(attr_value, value)\n\n")

    writer.write("#define set_mac_attr_value(attr_def, attr_value, value) \\\n")
    writer.write("        attr_def##_VAL::set(attr_value, value)\n\n")

    writer.write("#define get_attr_value(attr_def, attr_value) \\\n")
    writer.write("        attr_def##_VAL::get(attr_value)\n\n")

    writer.write("#define set_attr_value(attr_def, attr_value, value)  \\\n")
    writer.write("        attr_def##_VAL::set(attr_value, value)\n\n")

    writer.write("#define get_mac_attrs_value(attr_def, attrs, res, mandatory) \\\n")
    writer.write("{ auto it = attrs.find(attr_def);\\\n")
    writer.write("    if (it != attrs.end()) {\\\n")
    writer.write("        get_mac_attr_value(attr_def, it->second, res);} \\\n")
    writer.write("    else if (mandatory) { \\\n")
    writer.write("        return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING; \\\n")
    writer.write("    }}\n\n")

    writer.write("#define get_ip6_attrs_value(attr_def, attrs, res, mandatory) \\\n")
    writer.write("{ auto it = attrs.find(attr_def);\\\n")
    writer.write("    if (it != attrs.end()) {\\\n")
    writer.write("        get_ip6_attr_value(attr_def, it->second, res);} \\\n")
    writer.write("    else if (mandatory) { \\\n")
    writer.write("        return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING; \\\n")
    writer.write("    }}\n\n")

    writer.write("#define get_salt_attrs_value(attr_def, attrs, res, mandatory) \\\n")
    writer.write("{ auto it = attrs.find(attr_def);\\\n")
    writer.write("    if (it != attrs.end()) {\\\n")
    writer.write("        get_salt_attr_value(attr_def, it->second, res);} \\\n")
    writer.write("    else if (mandatory) { \\\n")
    writer.write("        return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING; \\\n")
    writer.write("    }}\n\n")

    writer.write("#define get_sak_attrs_value(attr_def, attrs, res, mandatory) \\\n")
    writer.write("{ auto it = attrs.find(attr_def);\\\n")
    writer.write("    if (it != attrs.end()) {\\\n")
    writer.write("        get_sak_attr_value(attr_def, it->second, res);} \\\n")
    writer.write("    else if (mandatory) { \\\n")
    writer.write("        return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING; \\\n")
    writer.write("    }}\n\n")

    writer.write("#define get_authkey_attrs_value(attr_def, attrs, res, mandatory) \\\n")
    writer.write("{ auto it = attrs.find(attr_def);\\\n")
    writer.write("    if (it != attrs.end()) {\\\n")
    writer.write("        get_authkey_attr_value(attr_def, it->second, res);} \\\n")
    writer.write("    else if (mandatory) { \\\n")
    writer.write("        return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING; \\\n")
    writer.write("    }}\n\n")

    writer.write("#define get_attrs_value(attr_def, attrs, res, mandatory) \\\n")
    writer.write("{ auto it = attrs.find(attr_def);\\\n")
    writer.write("    if (it != attrs.end()) {\\\n")
    writer.write("        res = get_attr_value(attr_def, it->second);} \\\n")
    writer.write("    else if (mandatory) { \\\n")
    writer.write("        return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING; \\\n")
    writer.write("    }}\n\n")

    for key in sorted (def_temp_dict):
        vlist = def_temp_dict[key]
        for v in sorted (vlist):
            val = attr_value_dict[v[0]]
            attr_struct = make_attr_struct(key,val)
            if val == 'mac':
                if attr_struct not in attr_structs:
                    attr_structs.add(attr_struct)                    
                    writer.write("DEFINE_mac_attr_templ("+key+", "+val+", "+attr_struct+");\n")
            elif val == 'ip6':
                if attr_struct not in attr_structs:
                    attr_structs.add(attr_struct)                    
                    writer.write("DEFINE_ip6_attr_templ("+key+", "+val+", "+attr_struct+");\n")
            elif val == 'macsecsalt':
                if attr_struct not in attr_structs:
                    attr_structs.add(attr_struct)                    
                    writer.write("DEFINE_salt_attr_templ("+key+", "+val+", "+attr_struct+");\n")
            elif val == 'macsecsak':
                if attr_struct not in attr_structs:
                    attr_structs.add(attr_struct)                    
                    writer.write("DEFINE_sak_attr_templ("+key+", "+val+", "+attr_struct+");\n")
            elif val == 'macsecauthkey':
                if attr_struct not in attr_structs:
                    attr_structs.add(attr_struct)                    
                    writer.write("DEFINE_authkey_attr_templ("+key+", "+val+", "+attr_struct+");\n")
            elif val == 'aclfield':
                attr_struct = make_attr_struct(key,val)
                val = attr_value_dict[v[1]]
                if val == 'booldata':
                    val = 'u8'
                if val == 'oid':
                    if sai_ver > 0x010502:
                        val = 'u64'
                    else:
                        val = 'u32'
                if val == 'objlist':
                    val = 'u8list'
                attr_struct = make_attr_struct(attr_struct,val)
                if attr_struct not in attr_structs:
                    attr_structs.add(attr_struct)                    
                    writer.write("DEFINE_aclfield_attr_templ("+key+", "+val+", "+attr_struct+");\n")
            elif val == 'aclaction':
                attr_struct = make_attr_struct(key,val)
                val = attr_value_dict[v[1]]
                attr_struct = make_attr_struct(attr_struct,val)
                if attr_struct not in attr_structs:
                    attr_structs.add(attr_struct)                    
                    writer.write("DEFINE_aclaction_attr_templ("+key+", "+val+", "+attr_struct+");\n")
            else:
                if attr_struct not in attr_structs:
                    attr_structs.add(attr_struct)                    
                    writer.write("DEFINE_attr_templ("+key+", "+val+", "+attr_struct+");\n")

    writer.write("\n")

    for key in sorted (value_of_dict):
        if key in do_not_print:
            continue
        if len(value_of_dict[key]) > 1:
            tmpval = value_of_dict[key][1]
            if value_of_dict[key][0]  == 'sai_acl_field_data_t':
                if tmpval == 'bool':
                    tmpval = 'sai_uint8_t'
                elif tmpval == 'sai_object_id_t':
                    if sai_ver > 0x010502:
                        tmpval = 'sai_uint64_t'
                    else:
                        tmpval = 'sai_uint32_t'
                elif tmpval == 'sai_object_list_t':
                    tmpval = 'sai_u8_list_t'
            writer.write("using "+key+"_VAL"+" = "+attr_struct_dict[key]+"<"+key+", "+tmpval+">;\n")
        else:
            writer.write("using "+key+"_VAL"+" = "+attr_struct_dict[key]+"<"+key+", "+value_of_dict[key][0]+">;\n")

    writer.write("namespace silicon_one\n{\n")
    writer.write("namespace sai\n{\n")
    for key in sorted (enum_dict):
        if "_attr_t" not in key:
            continue
        writer.write("std::string to_string("+key+" a, sai_attribute_value_t v);\n")

    for key in sorted (enum_dict):
        namelist = enum_dict[key]
        writer.write("std::string to_string("+key+"& x);\n")
    writer.write("}\n")
    writer.write("}\n")

    writer.write("// clang-format on\n")

    writer.write("#endif // ___SAI_GEN_ATTR_H__\n")

def write_to_file_autotostrings(writer):
    writer.write("// Automatically generated file - don't change\n")
    writer.write("// clang-format off\n")
    writer.write('#include "sai_strings.h"\n')
    writer.write('#include "common/gen_utils.h"\n')
    writer.write('#include "sai_device.h"\n')
    writer.write('#include <auto_gen_attr.h>\n')
    writer.write('#include <iomanip>\n')
    writer.write('#include <map>\n')
    writer.write("namespace silicon_one\n{\n")
    writer.write("namespace sai\n{\n")
    for key in sorted (enum_dict):
        if "_attr_t" not in key:
            continue
        writer.write("std::string\nto_string("+key+" a, sai_attribute_value_t v)\n")
        writer.write("{\n")
        writer.write("    switch (a) {\n")
        namelist = enum_dict[key]
        for nm in sorted (namelist):
            if "CUSTOM_RANGE_END" in nm or "_ATTR_END" in nm or "_START" in nm:
                continue
            if nm in do_not_print:
                continue
            if nm not in value_of_dict:
                continue
            writer.write("      case "+nm+":\n")
            writer.write("      {\n")
            if value_of_dict[nm][0] == 'sai_mac_t':
                writer.write("          sai_mac_t res;\n")
                writer.write("          get_mac_attr_value("+nm+", v, res);\n")
            elif value_of_dict[nm][0] == 'sai_ip6_t':
                writer.write("          sai_ip6_t res;\n")
                writer.write("          get_ip6_attr_value("+nm+", v, res);\n")
            elif value_of_dict[nm][0] == 'sai_macsec_salt_t':
                writer.write("          sai_macsec_salt_t res;\n")
                writer.write("          get_salt_attr_value("+nm+", v, res);\n")
            elif value_of_dict[nm][0] == 'sai_macsec_sak_t':
                writer.write("          sai_macsec_sak_t res;\n")
                writer.write("          get_sak_attr_value("+nm+", v, res);\n")
            elif value_of_dict[nm][0] == 'sai_macsec_auth_key_t':
                writer.write("          sai_macsec_auth_key_t res;\n")
                writer.write("          get_authkey_attr_value("+nm+", v, res);\n")
            elif value_of_dict[nm][0] == "sai_acl_field_data_t":
                tmpval = value_of_dict[nm][1]
                if tmpval == 'bool':
                    tmpval = 'sai_uint8_t'
                elif tmpval == 'sai_object_id_t':
                    if sai_ver > 0x010502:
                        tmpval = 'sai_uint64_t'
                    else:
                        tmpval = 'sai_uint32_t'
                elif tmpval == 'sai_object_list_t':
                    tmpval = 'sai_u8_list_t'
                writer.write("          "+tmpval+" res_data, res_mask;\n")
                writer.write("          get_data_aclfield_attr_value("+nm+", v, res_data);\n")
                writer.write("          get_mask_aclfield_attr_value("+nm+", v, res_mask);\n")
                writer.write("          return to_string(res_data)+to_string(res_mask);\n")
                writer.write("      }\n")
                continue
            elif value_of_dict[nm][0] == "sai_acl_action_data_t":
                tmpval = value_of_dict[nm][1]
                writer.write("          "+tmpval+" res;\n")
                writer.write("          get_aclaction_attr_value("+nm+", v, res);\n")
            else:
                writer.write("          auto res = get_attr_value("+nm+", v);\n")
            writer.write("          return to_string(res);\n")
            writer.write("      }\n")
        writer.write("      default:\n")
        writer.write("          break;\n")
        writer.write("    }\n")
        writer.write('    return "Unknown";\n')
        writer.write("}\n\n")
        
    for key in sorted (enum_dict):
        custom_start = None
        custom_end = None
        custom = []
        namelist = enum_dict[key]
        writer.write("std::string\nto_string("+key+"& x)\n{\n")
        writer.write("    static std::map<"+key+", const char*> strs = {\n")
        for nm in sorted (namelist):
            if "_ATTR_END" in nm or "_ATTR_START" in nm:
                continue
            writer.write("            {"+nm+', "'+nm+'"},\n')
        writer.write("    };\n\n")

        writer.write("    auto str = strs.find(x);\n")
        writer.write("    if (str != strs.end()) {\n")
        writer.write("        return str->second;\n    }\n")
        writer.write('    return "Unknown";\n}\n')
    writer.write("}\n")
    writer.write("}\n")
    writer.write("// clang-format on\n")


# @brief Helper class for indented file writing
#
# Writes lines to a file, indetnted to a specified depth
class indented_writer:
    # @brief Indented writed constuctor
    #
    # @param[in] fileobj   File object opened for writing

    def __init__(self, fileobj):
        self.indent_len = 4  # default number of indent spaces per depth
        self.depth = 0      # indentation level
        self.fileobj = fileobj

    # @brief Returns an indentation string
    #
    # @return The indentation string
    def indent(self):
        return " " * self.indent_len * self.depth

    # @brief Writes an indented string to a file
    def write(self, str):
        str = str.encode('ascii', 'ignore').decode('ascii')
        self.fileobj.write(self.indent() + str)

    # @brief Writes non-indented string to a file
    def write_noindent(self, str):
        self.fileobj.write(str)
    

if __name__ == '__main__':
    aparser = argparse.ArgumentParser(description='Generate SAI Attribute.')
    aparser.add_argument('-d', '--directory', dest='dirs', action='append', default=[],
                        help='Input sai metadata xml directory.')
    aparser.add_argument('-o', '--out', dest='file', action='store', default=[], help='output file name.')
    aparser.add_argument('--debug', action='store_true', help='print debug information')
    aparser.add_argument('--sai_ver', dest='sai_ver', action='store', default="0x010701")

    args = aparser.parse_args()

    if not args.dirs:
        print('Error: input directory has to be specified.')
        exit(1)

    if not args.file:
        print('Warning: output file has not be specified. Use default file name ./auto_gen_attr.h')
        filename = './auto_gen_attr.h'
    else:
        filename = args.file
    
    if not args.sai_ver:
        sai_ver = 0x010701
    else:
        sai_ver = int(args.sai_ver, 16)

    # enable debugging if debug argument is enable
    if args.debug:
        logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)

    parsefiles = collect_files(args.dirs)
    if len(parsefiles) == 0:
        print("No files to parse for %s%s" % (' '.join(args.file), ' '.join(args.dirs)))
        exit(1)

    for pfile in parsefiles:
        parse_enum(pfile)

    for pfile in parsefiles:
        parse_attr(pfile, sai_ver)

    with open(filename, 'w') as cpp_file: 
        logging.debug("writing to %s", filename)
        writer = indented_writer(cpp_file)
        write_to_file(writer, sai_ver)

    with open('auto_tostrings.cpp', 'w') as cpp_file: 
        logging.debug("writing to %s", filename)
        writer = indented_writer(cpp_file)
        write_to_file_autotostrings(writer)


