import glob
import pprint
import re
import sys

"""
running:
python ~/bin/sai_parse.py <SAI h files directory> <external attribute file name> | sed s/\'rem//g | sed s/rem\'//g > <output file>
example:
python ./scripts/sai_gen_py_attr.py `pwd`/externals/sai/1.6.3/inc  include/sai_attr_ext.h  | sed s/\'rem//g | sed s/rem\'//g > test/python/sai_gen_attr_info.py
make apply-format
"""

class sai_files_parser():
    all_objs_attrs_dict = {}
    all_enums = []

    supported_obj_names = [
        "ACL_COUNTER",
        "ACL_ENTRY",
        "ACL_TABLE",
        "ACL_TABLE_GROUP",
        "ACL_TABLE_GROUP_MEMBER",
        "ACL_RANGE",
        "BRIDGE_PORT",
        "BRIDGE",
        "BUFFER_POOL",
        "BUFFER_PROFILE",
        "DEBUG_COUNTER",
        "FDB_ENTRY",
        "HASH",
        "HOSTIF",
        "HOSTIF_TABLE_ENTRY",
        "HOSTIF_TRAP",
        "HOSTIF_TRAP_GROUP",
        "INSEG_ENTRY",
        "LAG_MEMBER",
        "LAG",
        "MIRROR_SESSION",
        "NEIGHBOR_ENTRY",
        "NEXT_HOP_GROUP",
        "NEXT_HOP_GROUP_MEMBER",
        "NEXT_HOP",
        "POLICER",
        "PORT",
        "QOS_MAP",
        "QUEUE",
        "ROUTE_ENTRY",
        "ROUTER_INTERFACE",
        "SAMPLEPACKET",
        "SCHEDULER",
        "SWITCH",
        "SYSTEM_PORT",
        "TAM",
        "TUNNEL",
        "TUNNEL_MAP",
        "TUNNEL_MAP_ENTRY",
        "TUNNEL_TERM_TABLE_ENTRY",
        "VLAN_MEMBER",
        "VLAN",
        "VIRTUAL_ROUTER",
        "WRED"]

    def __init__(self, base_sai_dir, ext_attr_file):
        # create list of files to parse
        self.base_sai_dir = base_sai_dir
        self.external_attr_file = ext_attr_file
        self.files_to_parse = []
        for obj in self.supported_obj_names:
            # handle ACL_ENTRY, ROUTE_ENTRY where file name is acl.h, route.h
            if "_ENTRY" in obj:
                obj = obj[:-6]
            file_name = "sai{0}.h".format(obj.replace("_", "").lower())
            self.files_to_parse.append(file_name)
        #  mpls.h for INSEG_ENTRY object
        self.files_to_parse.append("saimpls.h")
        # for MIRROR_SESSION
        self.files_to_parse.append("saimirror.h")
        # BUFFER_* objects
        self.files_to_parse.append("saibuffer.h")

    def parse_object_type(self, lines, lnum):
        while lnum < len(lines):
            if lines[lnum][0] == "}":
                return lnum
            # Don't need this for now. We have a list of supported types
            #obj_name = lines[lnum].lstrip().split(" ")[0][16:].lower()
            #self.all_objs_attrs_dict[obj_name] = {}
            lnum += 1

    def parse_saitypes(self):
        sai_type_file = self.base_sai_dir + "/saitypes.h"
        with open(sai_type_file) as f:
            lines = f.readlines()

        lnum = 0
        while lnum < len(lines):
            if lines[lnum] == "typedef enum _sai_object_type_t\n":
                lnum = self.parse_object_type(lines, lnum+2)
                continue
            lnum += 1

    # parse lines starting:
    # typedef enum _sai_<some attribute>_attr_t
    # until }
    def parse_attr_t(self, lines, lnum, obj_name):
        inside_comment = False
        one_obj_attrs_dict = {}
        # add rem, so we can remove this later, with the ' that python print add
        obj_id_rem = "remSAI_OBJECT_TYPE_{0}rem".format(obj_name.upper())
        while lnum < len(lines):
            if lines[lnum][0] == "}":
                # When parsing the external attr file, dict will exists, so need to append
                if obj_id_rem in self.all_objs_attrs_dict.keys():
                    self.all_objs_attrs_dict[obj_id_rem].update(one_obj_attrs_dict)
                else:
                    self .all_objs_attrs_dict[obj_id_rem] = one_obj_attrs_dict
                return lnum
            if "/*" in lines[lnum]:
                # start attribute comment parse
                one_attr_dict = {}
                inside_comment = True
                # some attributes comment is just one line containing both /* and */, so we can't advance lnum at /*
            if "*/" in lines[lnum]:
                inside_comment = False
                # find attribute name
                lnum += 1
                m = re.match("\s+(\w+)", lines[lnum])
                # no type, meaning ATTR_END, ATTR_START, or something similar
                if "type" in one_attr_dict.keys():
                    attr_name_rem = "rem{0}rem".format(m.group(1))  # add rem, so we can remove this with the ' that python print add
                    one_attr_dict["name"] = m.group(1)
                    one_obj_attrs_dict[attr_name_rem] = one_attr_dict

            # parse @ directives
            if inside_comment:
                m = re.match("\s+\* @(\S*) (.*)\n", lines[lnum])
                if m is not None:
                    # only care about type of attribute currently
                    if m.group(1) == "type":
                        # To avoid special treatment for each enum types, treat all of them the same
                        if m.group(2) in self.all_enums:
                            val = "enum"
                        elif m.group(2)[0:13] == "sai_pointer_t":  # Don't care about pointer type
                            val = "sai_pointer_t"
                        elif m.group(2)[0:14] == "sai_s32_list_t":  # list of 32b items. Don't care what type inside
                            val = "sai_s32_list_t"
                        else:
                            val = m.group(2)

                        one_attr_dict[m.group(1)] = val
            lnum += 1

    def parse_attributes(self):
        all_h_files = self.base_sai_dir + "/*.h"
        for file_path in glob.glob(all_h_files):
            file_name = file_path.split("/")[-1]
            if file_name not in self.files_to_parse:
               continue

            with open(file_path) as f:
                lines = f.readlines()

            lnum = 0
            while lnum < len(lines):
                # attr_t enums
                m = re.match("typedef enum _sai_(\w+)_attr_t", lines[lnum])
                if m is not None:
                    lnum = self.parse_attr_t(lines, lnum + 2, m.group(1))
                lnum += 1

    def parse_external_attributes(self):
        with open(self.external_attr_file) as f:
            lines = f.readlines()

        lnum  = 0
        while lnum < len(lines):
            # attr_t enums
            m = re.match("typedef enum _sai_(\w+)_attr_ext_t", lines[lnum])
            if m is not None:
                lnum = self.parse_attr_t(lines, lnum + 2, m.group(1))
            lnum  += 1

    def create_enum_list(self):
        all_h_files = self.base_sai_dir + "/*.h"
        for file_path in glob.glob(all_h_files):
            with open(file_path) as f:
                lines = f.readlines()

            lnum = 0
            while lnum < len(lines):
                # catch all other enums
                m = re.match("typedef enum _(sai_\w+_t)", lines[lnum])
                if m is not None:
                    self.all_enums.append(m.group(1))
                lnum += 1

    def parse_all(self):
        self.create_enum_list()
        self.parse_saitypes()
        self.parse_attributes()
        self.parse_external_attributes()

    def print_header(self):
        print("from saicli import *")
        print("all_sai_attributes_info = \\")

if __name__ == "__main__":
    # original sai files dir
    if len(sys.argv) != 3:
        print("must provide SAI directory name, and sai external attributes file")
        sys.exit()

    parser = sai_files_parser(sys.argv[1], sys.argv[2])
    parser.parse_all()
    parser.print_header()
    pprint.pprint(parser.all_objs_attrs_dict)

