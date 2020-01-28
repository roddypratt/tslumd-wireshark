
--[[
    TSM UMD 3.1 Protocol Dissector for WireShark 
    Copyright (C) 2020 Roddy Pratt

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
]]


local brightness_codes = {
    [0x00] = "Off",
    [0x1] = "Dim",
    [0x2] = "Half",
    [0x3] = "Full"
}

local p_tsl = Proto("TSL-UMD", "TSL UMD 3.1 Protocol");
local f_address = ProtoField.uint8("tsl.address", "Display address", base.HEX, nil, 0x7f);
local f_tally1 = ProtoField.bool("tsl.tally1", "Tally 1", 8, nil, 0x1);
local f_tally2 = ProtoField.bool("tsl.tally2", "Tally 2", 8, nil, 0x2);
local f_tally3 = ProtoField.bool("tsl.tally3", "Tally 3", 8, nil, 0x4);
local f_tally4 = ProtoField.bool("tsl.tally4", "Tally 4", 8, nil, 0x8);
local f_brightness = ProtoField.uint8("tsl.brightness", "Brightness", base.HEX,
                                      brightness_codes, 0x30);

local f_text = ProtoField.string("tsl.text", "Text", base.ASCII);

local f_checksum = ProtoField.uint8("tsl.checksum", "V4 Checksum", base.HEX);
local f_vbc = ProtoField.uint8("tsl.vbc", "V4 VBC", base.HEX);
local f_xdata_l = ProtoField.uint8("tsl.xdata.l", "V4 XDATA L", base.HEX);
local f_xdata_r = ProtoField.uint8("tsl.xdata.r", "V4 XDATA R", base.HEX);

-- some error expert info's
local ef_highbit = ProtoExpert.new("tsl.startbit.expert",
                                   "TSL UMD message start bit missing",
                                   expert.group.MALFORMED, expert.severity.ERROR);

local ef_bad_length = ProtoExpert.new("tsl.length.expert",
                                      "TSL UMD message is wrong length",
                                      expert.group.MALFORMED,
                                      expert.severity.ERROR);
local ef_bad_vbc = ProtoExpert.new("tsl.vbc.expert",
                                   "TSL UMD V4 VBC code is invalid",
                                   expert.group.MALFORMED, expert.severity.WARN);

p_tsl.fields = {
    f_tsl, f_address, f_tally1, f_tally2, f_tally3, f_tally4, f_brightness,
    f_text, f_checksum, f_vbc, f_xdata_l, f_xdata_r
};

p_tsl.experts = {ef_highbit, ef_bad_length, ef_bad_vbc}

function p_tsl.dissector(buffer, packet_info, root_tree)
    packet_info.cols.protocol = "TSL UMD";

    tsl_tree = root_tree:add(p_tsl, "TSL UMD Message");
    if (buffer:len() ~= 18) and (buffer:len() ~= 22) then
        tsl_tree:add_proto_expert_info(ef_bad_length);
    end

    local header = buffer(0, 1):uint();
    if bit32.band(header, 0x80) == 0 then
      tsl_tree:add_proto_expert_info(ef_highbit);
    end;

    tsl_tree:add(f_address, buffer(0,1));
    tsl_tree:add(f_tally1, buffer(1, 1));
    tsl_tree:add(f_tally2, buffer(1, 1));
    tsl_tree:add(f_tally3, buffer(1, 1));
    tsl_tree:add(f_tally4, buffer(1, 1));
    tsl_tree:add(f_brightness, buffer(1, 1));
    tsl_tree:add(f_text, buffer(2, 16));

    if buffer:len() == 22 then
        tsl_tree:add(f_checksum, buffer(18, 1));
        local vbc = buffer(19,1):uint();
        if vbc ~= 2 then
          tsl_tree:add_proto_expert_info(ef_bad_vbc);
        end  
        tsl_tree:add(f_vbc, vbc);
        tsl_tree:add(f_xdata_l, buffer(20, 1));
        tsl_tree:add(f_xdata_r, buffer(21, 1));
    end
end

local udp_encap_table = DissectorTable.get("udp.port")
udp_encap_table:add(5001, p_tsl)

