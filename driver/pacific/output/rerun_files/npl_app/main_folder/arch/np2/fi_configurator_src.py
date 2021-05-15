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
            start_new_header,
            start_new_layer,
            stage=None, # default is rtc
            last_macro=False,
            header_format_type=0, # PROTOCOL_TYPE_UNKNOWN  = 5'b00000;
            offset_from_header_start=0):
        self._contexts = contexts
        self._stage = stage
        self._macro_id = macro_id
        self._header_format_type = header_format_type
        self._start_new_header = start_new_header
        self._start_new_layer = start_new_layer
        self._last_macro = last_macro
        self._offset = 8 * offset_from_header_start
        self._buffer_size = 8 * WINDOW_SIZE
        self._fs0 = FieldSelect(TCAM_FS0_RESOLUTION, TCAM_FS0_WIDTH, self._buffer_size)
        self._fs1 = FieldSelect(TCAM_FS1_RESOLUTION, TCAM_FS1_WIDTH, self._buffer_size)
        self._mask_hw_logic_header_size_in = False # use shifter to calculate size
        self.Hardwired(hw_logic_select=4) # FI_HARDWIRED_LOGIC_NONE = 3'd4;
        self.Shifter(None)
        self._keys = {}

    def Shifter(self, field, shift=0, size_mask=7):
        if field is None:
            self._mask_hw_logic_header_size_in = False
            self._size_mask = 0
            self._size_shift = 0
            self._size_offset = 0
            self._size_width = 0
            return
        # (field << shift) & ((size_mask)| 11111)
        # field must be Field
        # shift must be const
        self._mask_hw_logic_header_size_in = True
        SHIFTER_RESOLUTION = 4 # shifter resolution
        SHIFTER_WIDTH = 8      # shifter width
        SIZE_SHIFT_WIDTH = 4
        SIZE_MASK_WIDTH = 3
        assert ((isinstance(field, Field) and isinstance(shift, int)))
        assert(self._offset <= field.offset)
        field = Field(field.offset - self._offset, field.width)
        assert(size_mask < (1 << SIZE_MASK_WIDTH))
        assert(shift < (1 << SIZE_SHIFT_WIDTH))
        assert(field.width <= SHIFTER_WIDTH)
        assert((field.offset + field.width) % SHIFTER_RESOLUTION == 0)
        # can'f fetch from first nibble
        assert(field.offset + field.width >= 4)
        # shifter can fetch from concatenation of bytes 19:16 and 11:8
        assert((field.offset < 32 and field.offset + field.width < 32) or (field.offset > 63 and field.offset + field.width < 96))
        self._size_mask = size_mask
        self._size_shift = shift
        self._size_offset = ((field.offset + field.width - SHIFTER_WIDTH) // SHIFTER_RESOLUTION)
        self._size_width = field.width - 1 # hw calculates self._size_width + 1 (no 0 width)

        return self

    def Hardwired(self, hw_logic_select, mask_hw_logic_advance_data=False, mask_hw_logic_last_macro=False, mask_hw_logic_header_format_flags=0, mask_hw_logic_calc_header_size=False):
        HARDWIRED_LOGIC_SELECT_WIDTH = 3
        assert(isinstance(hw_logic_select, int))
        assert(hw_logic_select >= 0 and hw_logic_select < (1 << HARDWIRED_LOGIC_SELECT_WIDTH))
        self._hw_logic_select = hw_logic_select

        MASK_HW_LOGIC_ADVANCE_DATA_WIDTH = 1
        assert(isinstance(mask_hw_logic_advance_data, int))
        assert(mask_hw_logic_advance_data >= 0 and mask_hw_logic_advance_data < (1 << MASK_HW_LOGIC_ADVANCE_DATA_WIDTH))
        self._mask_hw_logic_advance_data = mask_hw_logic_advance_data

        MASK_HW_LOGIC_LAST_MACRO_WIDTH = 1
        assert(isinstance(mask_hw_logic_last_macro, int))
        assert(mask_hw_logic_last_macro >= 0 and mask_hw_logic_last_macro < (1 << MASK_HW_LOGIC_LAST_MACRO_WIDTH))
        self._mask_hw_logic_last_macro = mask_hw_logic_last_macro

        MASK_HW_LOGIC_HEADER_FORMAT_FLAGS_WIDTH = 3
        assert(isinstance(mask_hw_logic_header_format_flags, int))
        assert(mask_hw_logic_header_format_flags >= 0 and mask_hw_logic_header_format_flags < (1 << MASK_HW_LOGIC_HEADER_FORMAT_FLAGS_WIDTH))
        self._mask_hw_logic_header_format_flags = mask_hw_logic_header_format_flags

        MASK_HW_LOGIC_CALC_HEADER_SIZE_WIDTH = 1
        assert(isinstance(mask_hw_logic_calc_header_size, int))
        assert(mask_hw_logic_calc_header_size >= 0 and mask_hw_logic_calc_header_size < (1 << MASK_HW_LOGIC_CALC_HEADER_SIZE_WIDTH))
        self._mask_hw_logic_calc_header_size = mask_hw_logic_calc_header_size

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
               advance_data=True,
               last_macro=None,
               header_format_flags=0,
               update_header_format_type=True, # update current header type
               header_format_type=None,
               start_new_header=None,
               header_size=0,
               start_new_layer=None,
               next_header_format_type=None,
               mask_hw_logic_header_size_in=None,
               mask_hw_logic_header_format_flags=None,
               mask_hw_logic_calc_header_size=None,
               mask_hw_logic_advance_data=None,
               mask_hw_logic_last_macro=None):

        if last_macro is None:
            last_macro = next_macro._last_macro
        if start_new_header is None:
            start_new_header = next_macro._start_new_header
        if start_new_layer is None:
            start_new_layer = next_macro._start_new_layer
        if header_format_type is None:
            header_format_type = self._header_format_type
        if next_header_format_type is None:
            next_header_format_type = 0 # next_macro._header_format_type (0 -> don't update next header type)
        if mask_hw_logic_header_size_in is None:
            mask_hw_logic_header_size_in = self._mask_hw_logic_header_size_in
        if mask_hw_logic_header_format_flags is None:
            mask_hw_logic_header_format_flags = self._mask_hw_logic_header_format_flags
        if mask_hw_logic_calc_header_size is None:
            mask_hw_logic_calc_header_size = self._mask_hw_logic_calc_header_size
        if mask_hw_logic_advance_data is None:
            mask_hw_logic_advance_data = self._mask_hw_logic_advance_data
        if mask_hw_logic_last_macro is None:
            mask_hw_logic_last_macro = self._mask_hw_logic_last_macro

        if self._stage is None: # rtc
            next_macro_id = next_macro._macro_id
        else:
            next_macro_id = {"next_stage": next_macro._stage, "macro_type": next_macro._macro_id}
        for CONTEXT in self._contexts:
            macro[CONTEXT].append(
                {
                    "key": self._entry_key,
                    "mask": self._entry_mask,
                    "value": [
                        next_macro_id,                          # 8b
                        int(advance_data),                      # 1b
                        int(mask_hw_logic_advance_data),        # 1b
                        int(mask_hw_logic_last_macro),          # 1b
                        int(last_macro),                        # 1b
                        mask_hw_logic_header_format_flags,      # 3b
                        int(mask_hw_logic_header_size_in),      # 6b
                        header_format_flags,                    # 3b
                        int(mask_hw_logic_calc_header_size),    # 1b
                        update_header_format_type,              # 1b
                        header_format_type,                     # 5b
                        start_new_header,                       # 5b
                        header_size,                            # 6b
                        start_new_layer,                        # 1b
                        next_header_format_type                 # 5b
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
                            self._size_mask,             # 3b
                            self._size_shift,            # 4b
                            self._size_offset,           # 4b
                            self._size_width,            # 3b
                            self._tcam_fs1.offset,       # 5b
                            self._tcam_fs1.width,        # 6b
                            self._tcam_fs0.offset,       # 6b
                            self._tcam_fs0.width,        # 5b
                            self._hw_logic_select        # 3b
                        ]
                    })
            except BaseException:
                self._fields_in_key = []
                macro_config[CONTEXT].append(
                    {
                        "key": self._macro_id,
                        "value": [
                            self._size_mask,             # 3b
                            self._size_shift,            # 4b
                            self._size_offset,           # 4b
                            self._size_width,            # 3b
                            0,                           # 5b
                            0,                           # 6b
                            0,                           # 6b
                            0,                           # 5b
                            self._hw_logic_select        # 3b
                        ]
                    })
        return self

    @staticmethod
    def populate_macro_config(macro_config, stage, is_rxpp): #PFI_STAGE_6 - rtc
        for CONTEXT in macro_config:
            if stage == PFI_STAGE_6 and is_rxpp:
                MACRO_CONFIG_ENTRIES = 64
            else:
                MACRO_CONFIG_ENTRIES = 16
            assert(len(macro_config[CONTEXT]) <= MACRO_CONFIG_ENTRIES)
            table_data =  [{"key": ["fi_macro"], "value": ["fi_macro_config_data"]}]
            if is_rxpp:
                if stage == PFI_STAGE_0:
                    table_config = DirectTableConfig("rxpp_fi_stage0_macro_config_table")
                elif stage == PFI_STAGE_1:
                    table_config = DirectTableConfig("rxpp_fi_stage1_macro_config_table")
                elif stage == PFI_STAGE_2:
                    table_config = DirectTableConfig("rxpp_fi_stage2_macro_config_table")
                elif stage == PFI_STAGE_3:
                    table_config = DirectTableConfig("rxpp_fi_stage3_macro_config_table")
                elif stage == PFI_STAGE_4:
                    table_config = DirectTableConfig("rxpp_fi_stage4_macro_config_table")
                elif stage == PFI_STAGE_5:
                    table_config = DirectTableConfig("rxpp_fi_stage5_macro_config_table")
                else: # stage == PFI_STAGE_6, RTC for RxPP:
                    assert(stage == PFI_STAGE_6)
                    table_config = DirectTableConfig("rxpp_fi_rtc_stage_macro_config_table")
            else: # txpp
                if stage == PFI_STAGE_3:
                    table_config = DirectTableConfig("txpp_fi_stage3_macro_config_table")
                elif stage == PFI_STAGE_4:
                    table_config = DirectTableConfig("txpp_fi_stage4_macro_config_table")
                elif stage == PFI_STAGE_5:
                    table_config = DirectTableConfig("txpp_fi_stage5_macro_config_table")
                else: # stage == PFI_STAGE_6:
                    assert(stage == PFI_STAGE_6)
                    table_config = DirectTableConfig("txpp_fi_stage6_macro_config_table")
            for line in macro_config[CONTEXT]:
                val = line["value"]
                conf_data = fi_macro_config_data_t(size_mask=val[0],
                                                   size_shift=val[1],
                                                   size_offset=val[2],
                                                   size_width=val[3],
                                                   tcam_key_inst1_offset=val[4],
                                                   tcam_key_inst1_width=val[5],
                                                   tcam_key_inst0_offset=val[6],
                                                   tcam_key_inst0_width=val[7],
                                                   hw_logic_select=val[8])
                if is_rxpp:
                    if stage == PFI_STAGE_0:
                        key = rxpp_fi_stage0_macro_config_table_key_t(fi_macro=line["key"])
                        value = rxpp_fi_stage0_macro_config_table_value_t(fi_macro_config_data=conf_data)
                    elif stage == PFI_STAGE_1:
                        key = rxpp_fi_stage1_macro_config_table_key_t(fi_macro=line["key"])
                        value = rxpp_fi_stage1_macro_config_table_value_t(fi_macro_config_data=conf_data)
                    elif stage == PFI_STAGE_2:
                        key = rxpp_fi_stage2_macro_config_table_key_t(fi_macro=line["key"])
                        value = rxpp_fi_stage2_macro_config_table_value_t(fi_macro_config_data=conf_data)
                    elif stage == PFI_STAGE_3:
                        key = rxpp_fi_stage3_macro_config_table_key_t(fi_macro=line["key"])
                        value = rxpp_fi_stage3_macro_config_table_value_t(fi_macro_config_data=conf_data)
                    elif stage == PFI_STAGE_4:
                        key = rxpp_fi_stage4_macro_config_table_key_t(fi_macro=line["key"])
                        value = rxpp_fi_stage4_macro_config_table_value_t(fi_macro_config_data=conf_data)
                    elif stage == PFI_STAGE_5:
                        key = rxpp_fi_stage5_macro_config_table_key_t(fi_macro=line["key"])
                        value = rxpp_fi_stage5_macro_config_table_value_t(fi_macro_config_data=conf_data)
                    else: # stage == PFI_STAGE_6, RTC for RxPP:
                        assert(stage == PFI_STAGE_6)
                        key = rxpp_fi_rtc_stage_macro_config_table_key_t(fi_macro=line["key"])
                        value = rxpp_fi_rtc_stage_macro_config_table_value_t(fi_macro_config_data=conf_data)
                else: # txpp
                    if stage == PFI_STAGE_3:
                        key = txpp_fi_stage3_macro_config_table_key_t(fi_macro=line["key"])
                        value = txpp_fi_stage3_macro_config_table_value_t(fi_macro_config_data=conf_data)
                    elif stage == PFI_STAGE_4:
                        key = txpp_fi_stage4_macro_config_table_key_t(fi_macro=line["key"])
                        value = txpp_fi_stage4_macro_config_table_value_t(fi_macro_config_data=conf_data)
                    elif stage == PFI_STAGE_5:
                        key = txpp_fi_stage5_macro_config_table_key_t(fi_macro=line["key"])
                        value = txpp_fi_stage5_macro_config_table_value_t(fi_macro_config_data=conf_data)
                    else: # stage == PFI_STAGE_6:
                        assert(stage == PFI_STAGE_6)
                        key = txpp_fi_stage6_macro_config_table_key_t(fi_macro=line["key"])
                        value = txpp_fi_stage6_macro_config_table_value_t(fi_macro_config_data=conf_data)

                table_data.append({"key": key, "value": value})
            table_config.create_table(table_data, CONTEXT, key_func=lambda x: x['fi_macro'], value_func=lambda x: x['fi_macro_config_data'])

    @staticmethod
    def populate_macro(macro, stage, is_rxpp):
        for CONTEXT in macro:
            if stage == PFI_STAGE_6 and is_rxpp:
                TCAM_ENTRIES = 128
            else:
                TCAM_ENTRIES = 32
            assert(len(macro[CONTEXT]) <= TCAM_ENTRIES)
            if is_rxpp:
                if stage == PFI_STAGE_0:
                    table_config = TcamTableConfig("rxpp_fi_stage0_tcam_table")
                elif stage == PFI_STAGE_1:
                    table_config = TcamTableConfig("rxpp_fi_stage1_tcam_table")
                elif stage == PFI_STAGE_2:
                    table_config = TcamTableConfig("rxpp_fi_stage2_tcam_table")
                elif stage == PFI_STAGE_3:
                    table_config = TcamTableConfig("rxpp_fi_stage3_tcam_table")
                elif stage == PFI_STAGE_4:
                    table_config = TcamTableConfig("rxpp_fi_stage4_tcam_table")
                elif stage == PFI_STAGE_5:
                    table_config = TcamTableConfig("rxpp_fi_stage5_tcam_table")
                else: # stage == PFI_STAGE_6, RTC for RxPP:
                    assert(stage == PFI_STAGE_6)
                    table_config = TcamTableConfig("rxpp_fi_rtc_stage_tcam_table")
            else: # txpp
                if stage == PFI_STAGE_3:
                    table_config = TcamTableConfig("txpp_fi_stage3_tcam_table")
                elif stage == PFI_STAGE_4:
                    table_config = TcamTableConfig("txpp_fi_stage4_tcam_table")
                elif stage == PFI_STAGE_5:
                    table_config = TcamTableConfig("txpp_fi_stage5_tcam_table")
                else: # stage == PFI_STAGE_6:
                    assert(stage == PFI_STAGE_6)
                    table_config = TcamTableConfig("txpp_fi_stage6_tcam_table")

            if is_rxpp and stage == PFI_STAGE_6:
                table_data = [{"key": ["header_data", "fi_macro"],
                               "value": ["rtc_mid", "common_data"]}]
            else:
                table_data = [{"key": ["header_data", "fi_macro"],
                               "value": ["pl_mid", "common_data"]}]

            location = 0
            for line in macro[CONTEXT]:
                # we can have entries commented out as string
                if not isinstance(line, dict):
                    continue
                val = line["value"]

                if is_rxpp and stage == PFI_STAGE_6:
                    tcam_assoc_mid = pfi_rtc_mid_t(macro_type=val[0])
                else:
                    tcam_assoc_mid = pfi_pl_mid_t(stage_id=val[0]["next_stage"], macro_type=val[0]["macro_type"])

                tcam_assoc_common_data = fi_core_table_assoc_common_data_t(
                    advance_data=val[1],
                    mask_hw_logic_advance_data=val[2],
                    mask_hw_logic_last_macro=val[3],
                    last_macro=val[4],
                    mask_hw_logic_header_format_flags=val[5],
                    mask_hw_logic_header_size_in=val[6],
                    header_format_flags=val[7],
                    mask_hw_logic_calc_header_size=val[8],
                    update_header_format_type=val[9],
                    header_format_type=val[10],
                    start_new_header=val[11],
                    header_size=val[12],
                    start_new_layer=val[13],
                    next_header_format_type=val[14])

                def fi_tcam_table_value_func(value_args):
                    if is_rxpp:
                        if stage == PFI_STAGE_0:
                            value = rxpp_fi_stage0_tcam_table_value_t(**value_args)
                        elif stage == PFI_STAGE_1:
                            value = rxpp_fi_stage1_tcam_table_value_t(**value_args)
                        elif stage == PFI_STAGE_2:
                            value = rxpp_fi_stage2_tcam_table_value_t(**value_args)
                        elif stage == PFI_STAGE_3:
                            value = rxpp_fi_stage3_tcam_table_value_t(**value_args)
                        elif stage == PFI_STAGE_4:
                            value = rxpp_fi_stage4_tcam_table_value_t(**value_args)
                        elif stage == PFI_STAGE_5:
                            value = rxpp_fi_stage5_tcam_table_value_t(**value_args)
                        else: # stage == PFI_STAGE_6, RTC for RxPP:
                            assert(stage == PFI_STAGE_6)
                            value = rxpp_fi_rtc_stage_tcam_table_value_t(**value_args)
                    else: # txpp
                        if stage == PFI_STAGE_3:
                            value = txpp_fi_stage3_tcam_table_value_t(**value_args)
                        elif stage == PFI_STAGE_4:
                            value = txpp_fi_stage4_tcam_table_value_t(**value_args)
                        elif stage == PFI_STAGE_5:
                            value = txpp_fi_stage5_tcam_table_value_t(**value_args)
                        else: # stage == PFI_STAGE_6:
                            assert(stage == PFI_STAGE_6)
                            value = txpp_fi_stage6_tcam_table_value_t(**value_args)
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

                def fi_tcam_table_key_func(key_args, mask_args):
                    if is_rxpp:
                        if stage == PFI_STAGE_0:
                            key  = rxpp_fi_stage0_tcam_table_key_t(**key_args)
                            mask = rxpp_fi_stage0_tcam_table_key_t(**mask_args)
                        elif stage == PFI_STAGE_1:
                            key  = rxpp_fi_stage1_tcam_table_key_t(**key_args)
                            mask = rxpp_fi_stage1_tcam_table_key_t(**mask_args)
                        elif stage == PFI_STAGE_2:
                            key  = rxpp_fi_stage2_tcam_table_key_t(**key_args)
                            mask = rxpp_fi_stage2_tcam_table_key_t(**mask_args)
                        elif stage == PFI_STAGE_3:
                            key  = rxpp_fi_stage3_tcam_table_key_t(**key_args)
                            mask = rxpp_fi_stage3_tcam_table_key_t(**mask_args)
                        elif stage == PFI_STAGE_4:
                            key  = rxpp_fi_stage4_tcam_table_key_t(**key_args)
                            mask = rxpp_fi_stage4_tcam_table_key_t(**mask_args)
                        elif stage == PFI_STAGE_5:
                            key  = rxpp_fi_stage5_tcam_table_key_t(**key_args)
                            mask = rxpp_fi_stage5_tcam_table_key_t(**mask_args)
                        else: # stage == PFI_STAGE_6, RTC for RxPP:
                            assert(stage == PFI_STAGE_6)
                            key  = rxpp_fi_rtc_stage_tcam_table_key_t(**key_args)
                            mask = rxpp_fi_rtc_stage_tcam_table_key_t(**mask_args)
                    else: # txpp
                        if stage == PFI_STAGE_3:
                            key  = txpp_fi_stage3_tcam_table_key_t(**key_args)
                            mask = txpp_fi_stage3_tcam_table_key_t(**mask_args)
                        elif stage == PFI_STAGE_4:
                            key  = txpp_fi_stage4_tcam_table_key_t(**key_args)
                            mask = txpp_fi_stage4_tcam_table_key_t(**mask_args)
                        elif stage == PFI_STAGE_5:
                            key  = txpp_fi_stage5_tcam_table_key_t(**key_args)
                            mask = txpp_fi_stage5_tcam_table_key_t(**mask_args)
                        else: # stage == PFI_STAGE_6:
                            assert(stage == PFI_STAGE_6)
                            key  = txpp_fi_stage6_tcam_table_key_t(**key_args)
                            mask = txpp_fi_stage6_tcam_table_key_t(**mask_args)
                    return key, mask

                #print(key_header_data, mask_header_data, line["key"][0],line["mask"][0][1] )
                table_data.append({"key": [Key(key_header_data, mask_header_data),
                                           Key(line["key"][0], line["mask"][0][1])],
                                   "value": [tcam_assoc_mid.get_value(),
                                             tcam_assoc_common_data]})
                location += 1
            table_config.create_table(table_data, CONTEXT, key_func=fi_tcam_table_key_func, value_func=fi_tcam_table_value_func)

#########################################################################
# packet header - 20B # PreviousHeaderFormat - 1B # packet header - 20B #
#########################################################################

# headers


class PreviousHeaderFormat():
    prev_flags = Field(WINDOW_SIZE * 8 - 8, 3)
    prev_type = Field(WINDOW_SIZE * 8 - 5, 5)


class InjectHeader():
    inject_header_type = Field(0, 8)
    inject_header_specific_data = Field(8, 88)
    time_and_cntr_stamp_cmd = Field(96, 24)
    npl_internal_info = Field(120, 8)
    inject_header_trailer_type = Field(128, 8)


class PuntHeader():
    punt_next_header = Field(0, 5)
    punt_fwd_header_type = Field(5, 4)
    reserved = Field(9, 3)
    pl_header_offset = Field(12, 8)
    punt_source = Field(20, 4)
    punt_code = Field(24, 8)
    punt_sub_code = Field(32, 8)
    ssp = Field(40, 16)
    dsp = Field(56, 16)
    slp = Field(72, 20)
    dlp = Field(92, 20)
    padding = Field(112, 2)
    punt_relay_id = Field(114, 14)
    time_stamp_val = Field(128, 64)
    receive_time = Field(192, 32)


class FabricHeader():
    fabric_header_type = Field(0, 4)
    ctrl = Field(4, 4)


class TMHeader():
    hdr_type = Field(0, 2)
    vce = Field(2, 1)
    tc = Field(3, 3)
    dp = Field(6, 2)


class OAMPPuntHeader():
    first_fi_macro_id = Field(0, 8)
    first_npe_macro_id = Field(8, 8)
    ether_type = Field(16, 16)
    punt_next_header = Field(32, 5)
    punt_fwd_header_type = Field(37, 4)
    reserved = Field(41, 3)
    pl_header_offset = Field(44, 8)


class EthernetHeader():
    da = Field(offset=0, width=48)
    sa = Field(offset=48, width=48)
    ether_type_or_tpid = Field(offset=96, width=16)


class VlanHeader():
    pcp = Field(0, 3)
    dei = Field(3, 1)
    vid = Field(4, 12)
    tpid = Field(16, 16)


class IPv4Header():
    version = Field(0, 4)
    hln = Field(4, 4)
    dscp = Field(8, 6)
    ecn = Field(14, 2)
    total_length = Field(16, 16)
    identification = Field(32, 16)
    reserved = Field(48, 1)
    dont_fragment = Field(49, 1)
    more_fragments = Field(50, 1)
    fragment_offset = Field(51, 13)
    ttl = Field(64, 8)
    protocol = Field(72, 8)
    header_checksum = Field(80, 16)
    sip = Field(96, 32)
    dip = Field(128, 32)


class IPv6Header():
    version = Field(0, 4)
    dscp = Field(4, 6)
    ecn = Field(10, 2)
    flow_label = Field(12, 20)
    payload_length = Field(32, 16)
    next_header = Field(48, 8)
    hop_limit = Field(56, 8)
    sip = Field(64, 128)
    dip = Field(192, 128)


class IPv6EHHeader():
    next_header = Field(0, 8)
    hdr_len = Field(8, 8)
    HOP_hdr_fields = Field(16, 112)
    routing_hdr_fields = Field(128, 112)
    dest_hdr_fields = Field(240, 112)
    frag_hdr_fields = Field(352, 48)
    Auth_hdr_fields = Field(400, 112)


class UDPHeader():
    src_port = Field(0, 16)
    dst_port = Field(16, 16)
    length = Field(32, 16)
    checksum = Field(48, 16)
    ip_version = Field(64, 4)


class TCPHeader():
    src_port = Field(0, 16)
    dst_port = Field(16, 16)
    sequence_number = Field(32, 32)
    acknowledgement_number = Field(64, 32)
    header_length = Field(96, 4)
    flags = Field(100, 12)
    window = Field(112, 16)
    checksum = Field(128, 16)
    urgent = Field(144, 16)


class GREHeader():
    C = Field(0, 1)
    na = Field(1, 1)
    k = Field(2, 1)
    s = Field(3, 1)
    reserved0 = Field(4, 9)
    version = Field(13, 3)
    protocol = Field(16, 16)
    vsid = Field(32, 24)
    flowid = Field(56, 8)


class MPLSHeader():
    speculative_first_nibble = Field(0, 4)
    label = Field(0, 20)
    exp = Field(20, 3)
    bos = Field(23, 1)
    ttl = Field(24, 8)
    speculative_next_nibble = Field(32, 4)


# flags
flag_da_is_bc = 0b100
flag_sa_is_mc = 0b010
flag_sa_eq_da = 0b001
flag_is_priority = 0b001
flag_header_error = 0b100
flag_is_fragmented = 0b010
flag_checksum_error = 0b001
flag_sip_multicast = 0b100
flag_sip_msbs_eq_0 = 0b001
flag_illegal_ipv4 = 0b100
flag_is_null = 0b010
flag_is_bos = 0b001
