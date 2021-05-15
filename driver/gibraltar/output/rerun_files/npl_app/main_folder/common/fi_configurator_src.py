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

# This directive is read by leaba_format.py script
# pep8_extra_args = "--ignore=E2 --max-line-length 200"
# pep8_extra_args = "--ignore=E2,E5,W2"
# pep8_extra_args "--ignore=E721"
from config_tables_utils import *


def config_tables():
    pass


class Field():
    def __init__(self, offset, width):
        assert(offset >= 0)
        assert(width >= 0)
        self._offset = offset
        self._width = width

    @property
    def width(self):
        return self._width

    @property
    def offset(self):
        return self._offset

    @property
    def start(self):
        return self._offset

    @property
    def end(self):
        return self._offset + self._width

    def __lshift__(self, s):
        return Field(self._offset - s, self._width)

    def Slice(self, end, start):
        assert(end >= start)
        assert(end < self.width)
        assert(start >= 0)
        end = end + 1
        new_width = end - start
        new_offset = self._offset + (self._width - end)
        assert(new_width <= self._width)
        return Field(new_offset, new_width)

    def Union(self, other_field):
        assert(self.Intersects(other_field) == False)
        assert(other_field.start > self.start)
        new_start = min(self.offset, other_field.offset)
        new_end = max(self.end, other_field.end)
        return Field(new_start, new_end - new_start)

    def Intersects(self, other_field):
        s1 = self.offset
        e1 = self.offset + self.width
        s2 = other_field.offset
        e2 = other_field.offset + other_field.width
        return not (s1 >= e2 or e1 <= s2)

    def Intersection(self, other_field):
        if not self.Intersects(other_field):
            return None
        s = max(self.offset, other_field.offset)
        e = min(self.offset + self.width, other_field.offset + other_field.width)
        return Field(s, e - s)


class KeyField(Field):
    def __init__(self, offset, width, shift=0, total_width=40):
        super().__init__(offset, width)
        self._shift = shift
        self._all_1 = 2 ** total_width - 1
        self._mask = ((self._all_1 << (total_width - self.width)) & self._all_1) >> (total_width - self.width)

    @property
    def shift(self):
        return self._shift

    def eval(self, value=0, mask=0):
        return ((value & self._mask) << self.shift, (self._all_1 & self._mask) << self.shift)


class FieldSelect():
    def __init__(self, resolution=4, fs_width=32, cyclic_buffer_size=None):
        self._resolution = resolution
        self._fs_width = fs_width
        self._cyclic_buffer_size = cyclic_buffer_size

    def position(self, field):
        if field is None:
            return Field(0, 0)
        e = field.end  # offset + field.width # e = field.end
        alignment = 0
        if e % self._resolution != 0:
            raise ValueError("alignment needed")
            # alignment = self._resolution - (e % self._resolution)  # align if needed
        e = e + alignment
        fs_offset_in_bits = (e - self._fs_width)
        if self._cyclic_buffer_size:
            fs_offset_in_bits = fs_offset_in_bits % self._cyclic_buffer_size  # 3 f
        assert(fs_offset_in_bits >= 0)
        fs_offset = fs_offset_in_bits / self._resolution
        return Field(int(fs_offset), field.width)

    def configure(self, field):
        if field is None:
            return KeyField(0, 0, 0)
        e = field.end  # offset + field.width # e = field.end
        alignment = 0
        if e % self._resolution != 0:
            raise ValueError("alignment needed")
            # alignment = self._resolution - (e % self._resolution)  # align if needed
        e = e + alignment
        fs_offset_in_bits = (e - self._fs_width)
        if self._cyclic_buffer_size:
            fs_offset_in_bits = fs_offset_in_bits % self._cyclic_buffer_size  # 3 f
        assert(fs_offset_in_bits >= 0)
        fs_offset = fs_offset_in_bits / self._resolution
        return KeyField(int(fs_offset), field.width, alignment)


WINDOW_SIZE = 21  # 21 Bytes. 20 from packet followed by prev macro header_format
TCAM_FS0_RESOLUTION = 4   # nibble resolution
TCAM_FS0_WIDTH = 16  # 16 bit wide
TCAM_FS1_RESOLUTION = 8   # Byte resolution
TCAM_FS1_WIDTH = 32  # 32 bit wide


class FiMacro():
    def __init__(
            self,
            contexts,
            macro_id,
            start_header,
            start_layer,
            last_macro=False,
            header_type=0, # PROTOCOL_TYPE_UNKNOWN  = 5'b00000;
            offset_from_header_start=0):
        self._contexts = contexts
        self._macro_id = macro_id
        self._header_type = header_type
        self._start_header = start_header
        self._start_layer = start_layer
        self._last_macro = last_macro
        self._offset = 8 * offset_from_header_start
        self._buffer_size = 8 * WINDOW_SIZE
        self._fs0 = FieldSelect(TCAM_FS0_RESOLUTION, TCAM_FS0_WIDTH, self._buffer_size)
        self._fs1 = FieldSelect(TCAM_FS1_RESOLUTION, TCAM_FS1_WIDTH, self._buffer_size)
        self.Hardwired(hardwired=4) # FI_HARDWIRED_LOGIC_NONE = 3'd4;
        self._keys = {}
        self.ALU(0, 0, 0, 0)

    def ALU(self, a, b, c, d, mask_alu_flags=0, mask_alu_type=0, mask_alu_size=0):
        # ( (a << b) + c) << d
        # b & d must me const
        # a & c can be either a field or a const
        # d - header size (6b) || header format (8b)
        assert (isinstance(b, int) and isinstance(d, int))
        self._mask_alu_flags = mask_alu_flags
        self._mask_alu_type = mask_alu_type
        self._mask_alu_size = mask_alu_size
        fs = FieldSelect(resolution=4, fs_width=8)
        if isinstance(a, int):
            self._alu_fs1_type = 0
            self._alu_fs1_const = a
            self._alu_fs1 = Field(offset=0, width=0)
        else:
            self._alu_fs1_type = 1
            self._alu_fs1 = fs.position(a) << self._offset
            self._alu_fs1_const = 0

        if isinstance(c, int):
            self._alu_fs2_type = 0
            self._alu_fs2_const = c
            self._alu_fs2 = Field(offset=0, width=0)
        else:
            self._alu_fs2_type = 1
            self._alu_fs2 = fs.position(c) << self._offset
            self._alu_fs2_const = 0
        self._alu_shift_1 = b
        self._alu_shift_2 = d
        return self

    def Hardwired(self, hardwired, mask_hardwired_flags=0, mask_hardwired_type=0, mask_hardwired_size=0):
        self._hardwired = hardwired
        assert(isinstance(mask_hardwired_flags, int))
        assert(mask_hardwired_flags <= 0b111)
        self._mask_hardwired_flags = mask_hardwired_flags
        self._mask_hardwired_type = mask_hardwired_type
        self._mask_hardwired_size = mask_hardwired_size
        return self

    def Key(self, name, packet_field=None):
        # packet fields need to be shifted as packet buffer may be read from middle of the header
        self._keys[name] = packet_field << self._offset
        assert(self._keys[name].start >= 0 and "Field underflows the packet buffer")
        assert(self._keys[name].end <= self._buffer_size and "Field overflows the packet buffer")
        return self

    def Conditions(self, mask_macro_id=0x3f, **args):
        self._entry_key = []
        self._entry_mask = []
        for field_name in args:  # just assert exists
            assert(field_name in [first for first, _ in self._fields_in_key])
        for field_name, field in self._fields_in_key:
            if field_name in args and args[field_name] is not None:
                value = args[field_name]
                if isinstance(value, dict):
                    self._entry_key.insert(0, [field.width, value["key"]])
                    self._entry_mask.insert(0, [field.width, value["mask"]])
                else:
                    self._entry_key.insert(0, [field.width, value])
                    self._entry_mask.insert(0, [field.width, 2**field.width - 1])
            else:
                self._entry_key.insert(0, [field.width, 0])
                self._entry_mask.insert(0, [field.width, 0])
        self._entry_key.insert(0, self._macro_id)
        self._entry_mask.insert(0, [6, mask_macro_id])
        return self

    def Action(self,
               macro,
               next_macro,
               last_macro=None,
               start_header=None,
               start_layer=None,
               advance_data=True,
               mask_alu_flags=None,
               mask_alu_type=None,
               mask_alu_size=None,
               mask_hardwired_advance_data=False,
               mask_hardwired_last_macro=False,
               mask_hardwired_flags=None,
               mask_hardwired_type=None,
               mask_hardwired_size=None,
               header_flags=0,
               header_type=None,
               size=0):

        if last_macro is None:
            last_macro = next_macro._last_macro
        if start_header is None:
            start_header = next_macro._start_header
        if start_layer is None:
            start_layer = next_macro._start_layer
        if header_type is None:
            header_type = self._header_type

        if mask_alu_flags is None:
            mask_alu_flags = self._mask_alu_flags
        if mask_alu_type is None:
            mask_alu_type = self._mask_alu_type
        if mask_alu_size is None:
            mask_alu_size = self._mask_alu_size

        if mask_hardwired_flags is None:
            mask_hardwired_flags = self._mask_hardwired_flags
        if mask_hardwired_type is None:
            mask_hardwired_type = self._mask_hardwired_type
        if mask_hardwired_size is None:
            mask_hardwired_size = self._mask_hardwired_size

        for CONTEXT in self._contexts:
            macro[CONTEXT].append(
                {
                    "key": self._entry_key,
                    "mask": self._entry_mask,
                    "value": [
                        next_macro._macro_id,            # next_macro                             : 6;
                        int(last_macro),                 # last_macro                             : 1;
                        int(start_header),               # start_new_header                       : 1;
                        int(start_layer),                # start_new_layer                        : 1;
                        int(advance_data),               # advance_data                           : 1;
                        mask_alu_flags,                  # tcam_mask_alu_header_format.flags      : 3;
                        mask_alu_type,                   # tcam_mask_alu_header_format.type       : 5;
                        mask_alu_size,                   # tcam_mask_alu_header_size              : 6;
                        int(mask_hardwired_advance_data),  # tcam_mask_hw_logic_advance_data      : 1;
                        int(mask_hardwired_last_macro),  # tcam_mask_hw_logic_last_macro          : 1;
                        mask_hardwired_flags,            # tcam_mask_hw_logic_header_format.flags : 3;
                        mask_hardwired_type,             # tcam_mask_hw_logic_header_format.type  : 5;
                        mask_hardwired_size,             # tcam_mask_hw_logic_header_size         : 6;
                        header_flags,                    # header_format.flags                    : 3;
                        header_type,                     # header_format.type                     : 5;
                        size                             # header_size                            : 6; # in_bytes
                    ],
                })
        return self

    def prepare_tcam_field_selects(self):
        if not len(self._keys) > 0:
            return
        # group consecutive condition keys
        keys = sorted([i for i in self._keys.items()], key=lambda s: s[1].offset)
        field_groups = []
        field_groups.append([])
        group = 0
        field_groups[group].append(keys[0][0])
        if len(self._keys) > 1:
            prev = keys[0]
            for k in keys[1:]:
                if prev[1].end == k[1].start:
                    field_groups[group].append(k[0])
                else:
                    field_groups.append([k[0]])
                    group = group + 1
                prev = k
        num_groups = len(field_groups)
        assert (num_groups <= 2)
        if num_groups < 2:
            num_groups = 2

        # calculate group widths
        field_groups_width = [None] * num_groups
        sum = 0
        for i, g in enumerate(field_groups):
            field_groups_width[i] = Field(self._keys[g[0]].offset, self._keys[g[-1]].end - self._keys[g[0]].start)
            sum += field_groups_width[i].width
        assert(sum <= TCAM_FS1_WIDTH)

        # for correct key gen
        for group in field_groups:
            group.reverse()

        # Configure Fieled Selects
        field_groups.append([])
        try:
            if field_groups_width[0].width <= TCAM_FS0_WIDTH:
                kfs0 = self._fs0.configure(field_groups_width[0])
                kfs1 = self._fs1.configure(field_groups_width[1])
                order = [0, 1]
                offsets = [kfs0.shift, kfs1.shift]
            else:
                kfs0 = self._fs0.configure(field_groups_width[1])
                kfs1 = self._fs1.configure(field_groups_width[0])
                order = [1, 0]
                offsets = [kfs1.shift, kfs0.shift]
        except BaseException:
            if field_groups_width[0].width > TCAM_FS0_WIDTH:
                kfs0 = self._fs0.configure(field_groups_width[0])
                kfs1 = self._fs1.configure(field_groups_width[1])
                order = [0, 1]
                offsets = [kfs0.shift, kfs1.shift]
            else:
                kfs0 = self._fs0.configure(field_groups_width[1])
                kfs1 = self._fs1.configure(field_groups_width[0])
                order = [1, 0]
                offsets = [kfs1.shift, kfs0.shift]

        # stack fields in the key, in the correct order and offset within key
        self._fields_in_key = []
        if offsets[0] > 0:
            self._fields_in_key.append(("padding", Field(0, offsets[0])))
        offset = offsets[0]
        for f in field_groups[order[0]]:
            self._fields_in_key.append((f, Field(offset, self._keys[f].width)))
            offset += self._keys[f].width

        if offsets[1] > 0:
            self._fields_in_key.append(("padding", Field(offset, offsets[1])))
        offset += offsets[1]
        for f in field_groups[order[1]]:
            self._fields_in_key.append((f, Field(offset, self._keys[f].width)))
            offset += self._keys[f].width
        if offset < 34:
            self._fields_in_key.append(("padding", Field(offset, 34 - offset)))

        self._tcam_fs0 = kfs0
        self._tcam_fs1 = kfs1

    def AddMacro(self, macro_config):  # macro config
        self.prepare_tcam_field_selects()
        for CONTEXT in self._contexts:
            try:
                macro_config[CONTEXT].append(
                    {
                        "key": self._macro_id,
                        "value": [
                            self._tcam_fs1.offset,      # tcam_key_inst1_offset   : 5;
                            self._tcam_fs1.width,       # tcam_key_inst1_width    : 6;
                            self._tcam_fs0.offset,      # tcam_key_inst0_offset   : 6;
                            self._tcam_fs0.width,       # tcam_key_inst0_width    : 5;
                            self._alu_shift_2,          # alu_shift2              : 5;
                            self._alu_shift_1,          # alu_shift1              : 4;
                            self._hardwired,            # hw_logic_select         : fi_hardwired_logic_e (3);
                            self._alu_fs2_type,         # alu_mux2_select         : 1;
                            self._alu_fs1_type,         # alu_mux1_select         : 1;
                            self._alu_fs2_const,        # fs2_const               : 8;
                            self._alu_fs1_const,        # fs1_const               : 8;
                            self._alu_fs2.width,        # alu_fs2_valid_bits      : 4;
                            self._alu_fs2.offset,       # alu_fs2_offset          : 6;
                            self._alu_fs1.width,        # alu_fs1_valid_bits      : 4;
                            self._alu_fs1.offset        # alu_fs1_offset          : 6;
                        ]
                    })
            except BaseException:
                self._fields_in_key = []
                macro_config[CONTEXT].append(
                    {
                        "key": self._macro_id,
                        "value": [
                            0,                          # tcam_key_inst1_offset   : 5;
                            0,                          # tcam_key_inst1_width    : 6;
                            0,                          # tcam_key_inst0_offset   : 6;
                            0,                          # tcam_key_inst0_width    : 5;
                            self._alu_shift_2,          # alu_shift2              : 5;
                            self._alu_shift_1,          # alu_shift1              : 4;
                            self._hardwired,            # hw_logic_select         : fi_hardwired_logic_e (3);
                            self._alu_fs2_type,         # alu_mux2_select         : 1;
                            self._alu_fs1_type,         # alu_mux1_select         : 1;
                            self._alu_fs2_const,        # fs2_const               : 8;
                            self._alu_fs1_const,        # fs1_const               : 8;
                            self._alu_fs2.width,        # alu_fs2_valid_bits      : 4;
                            self._alu_fs2.offset,       # alu_fs2_offset          : 6;
                            self._alu_fs1.width,        # alu_fs1_valid_bits      : 4;
                            self._alu_fs1.offset        # alu_fs1_offset          : 6;
                        ]
                    })
        return self

    @staticmethod
    def populate_macro_config(macro_config):
        for CONTEXT in macro_config:
            table = fi_macro_config_table
            table_data =  [{"key": ["fi_macro"], "value": ["fi_macro_config_data"]}]
            table_config = DirectTableConfig("fi_macro_config_table")

            ENTRIES = 64
            assert(len(macro_config[CONTEXT]) <= ENTRIES)

            for line in macro_config[CONTEXT]:
                key = fi_macro_config_table_key_t(fi_macro=line["key"])
                val = line["value"]
                conf_data = fi_macro_config_data_t(tcam_key_inst1_offset=val[0],
                                                   tcam_key_inst1_width=val[1],
                                                   tcam_key_inst0_offset=val[2],
                                                   tcam_key_inst0_width=val[3],
                                                   alu_shift2=val[4],
                                                   alu_shift1=val[5],
                                                   hw_logic_select=val[6],
                                                   alu_mux2_select=val[7],
                                                   alu_mux1_select=val[8],
                                                   fs2_const=val[9],
                                                   fs1_const=val[10],
                                                   alu_fs2_valid_bits=val[11],
                                                   alu_fs2_offset=val[12],
                                                   alu_fs1_valid_bits=val[13],
                                                   alu_fs1_offset=val[14])
                value = fi_macro_config_table_value_t(fi_macro_config_data=conf_data)
                table_data.append({"key": key, "value": value})
            table_config.create_table(table_data, CONTEXT, key_func=lambda x: x['fi_macro'], value_func=lambda x: x['fi_macro_config_data'])

    @staticmethod
    def populate_macro(macro):
        for CONTEXT in macro:
            table = fi_core_tcam_table
            table_config = TcamTableConfig("fi_core_tcam_table")
            table_data = [{"key": ["header_data", "fi_macro"], "value": ["fi_core_tcam_assoc_data"]}]
            location = 0

            ENTRIES = 128
            assert(len(macro[CONTEXT]) <= ENTRIES)

            for line in macro[CONTEXT]:
                # we can have entries commented out as string
                if not isinstance(line, dict):
                    continue
                val = line["value"]
                mask_alu_header_format = header_format_t(flags=val[5], type=val[6])
                hw_logic_header_format = header_format_t(flags=val[10], type=val[11])
                header_format = header_format_t(flags=val[13], type=val[14])
                tcam_assoc_data = fi_core_tcam_assoc_data_t(next_macro=val[0],
                                                            last_macro=val[1],
                                                            start_new_header=val[2],
                                                            start_new_layer=val[3],
                                                            advance_data=val[4],
                                                            tcam_mask_alu_header_format=mask_alu_header_format,
                                                            tcam_mask_alu_header_size=val[7],
                                                            tcam_mask_hw_logic_advance_data=val[8],
                                                            tcam_mask_hw_logic_last_macro=val[9],
                                                            tcam_mask_hw_logic_header_format=hw_logic_header_format,
                                                            tcam_mask_hw_logic_header_size=val[12],
                                                            header_format=header_format,
                                                            header_size=val[15]
                                                            )

                def fi_core_tcam_table_value_func(value_args):
                    value = fi_core_tcam_table_value_t(**value_args)
                    return value
                key_header_data = 0
                # key[0] is the macro id
                for ent in line["key"][1:]:
                    key_header_data <<= ent[0]
                    key_header_data += ent[1]
                mask_header_data = 0
                # mask[0] is the macro id mask
                for ent in line["mask"][1:]:
                    mask_header_data <<= ent[0]
                    mask_header_data += ent[1]

                def fi_core_tcam_table_key_func(key_args, mask_args):
                    key  = fi_core_tcam_table_key_t(**key_args)
                    mask = fi_core_tcam_table_key_t(**mask_args)
                    return key, mask
                table_data.append({"key": [Key(key_header_data, mask_header_data), Key(line["key"][0], line["mask"][0][1])], "value": [tcam_assoc_data]})
                location += 1
            table_config.create_table(table_data, CONTEXT, key_func=fi_core_tcam_table_key_func, value_func=fi_core_tcam_table_value_func)
