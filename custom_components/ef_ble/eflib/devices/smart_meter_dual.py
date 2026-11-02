"""EcoFlow Smart Meter Dual CT (SN ES81...) for ha-ef-ble (rabits/ha-ef-ble, written against v1.3.0).

Decoded 2 Nov 2026 from our own meter (ES81Z11B7J8Q0075, BLE name EF-ES8Q0075) with the integration's
unsupported-device packet capture. It sends the same message as the single-CT Smart Meter (BK21):
src 0x02, cmd fe/15, bk622_common.DisplayPropertyUpload, xor'd payload. Channel 1 is the fields that
message already defines (pow_get_sys_grid, grid_connection_*_L1..L3). Channel 2 is fields 984-998, which
the .proto does not know, so they are read from the raw payload here:
    985-987 volts L1-L3, 988-990 amps L1-L3, 991-993 watts L1-L3, 994-996 phase flags,
    997 energy record (GridConnectionDataRecord layout: 1-3 today L1-L3, 4 today), 998 channel total W.
Checked against a 400 W step from a Stream 5000 on channel 1's circuit: channel 1 moved -388 W, channel 2 0.
Sign: positive = drawing from the grid side of the clamp, negative = sending back.

Only L1 has a real voltage on a single-phase supply (L2/L3 float at ~half); a clamp in the L2/L3 position
of its lead reads half power. Use the L1 clamp of each set.

Sensor names reuse keys the integration already defines, so no other file changes:
    grid_power / l1_*   channel 1 (CT1) total / its L1 clamp
    pv_power_sum / l2_* channel 2 (CT2) total / its L1 clamp (the app calls channel 2 "solar")
Shipped in the CFLLDS/ha-ef-ble fork (HACS custom repository): upstream takes no new devices after v1.3.0
under its agreement with EcoFlow (rabits/ha-ef-ble discussion #521; PR #551 kept open for reference).
Installed from rabits/ha-ef-ble instead, an update deletes this file.
"""

import struct

from ..devicebase import DeviceBase
from ..packet import Packet
from ..pb import bk622_common_pb2
from ..props import Field, ProtobufProps, pb_field, proto_attr_mapper
from ..props.transforms import pround

pb = proto_attr_mapper(bk622_common_pb2.DisplayPropertyUpload)

CH2_VOLT_L1, CH2_AMP_L1, CH2_POWER_L1, CH2_ENERGY, CH2_TOTAL = 985, 988, 991, 997, 998


def _varint(buf: bytes, i: int) -> tuple[int, int]:
    shift = value = 0
    while True:
        b = buf[i]
        i += 1
        value |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return value, i


def _raw_fields(buf: bytes) -> dict[int, float | int | bytes]:
    """Top-level protobuf fields by number (last value wins); stops at an unknown wire type."""
    out: dict[int, float | int | bytes] = {}
    i = 0
    try:
        while i < len(buf):
            key, i = _varint(buf, i)
            num, wire = key >> 3, key & 7
            if wire == 0:
                out[num], i = _varint(buf, i)
            elif wire == 5:
                out[num] = struct.unpack_from("<f", buf, i)[0]
                i += 4
            elif wire == 1:
                out[num] = struct.unpack_from("<d", buf, i)[0]
                i += 8
            elif wire == 2:
                n, i = _varint(buf, i)
                out[num] = buf[i : i + n]
                i += n
            else:
                break
    except (IndexError, struct.error):
        pass
    return out


class Device(DeviceBase, ProtobufProps):
    SN_PREFIX = (b"ES81",)
    NAME_PREFIX = "EF-ES8"

    @classmethod
    def check(cls, sn: bytes):
        return sn[:4] in cls.SN_PREFIX

    @property
    def device(self):
        return "Smart Meter Dual CT"

    # Channel 1
    grid_power = pb_field(pb.pow_get_sys_grid, pround(1))
    grid_energy = pb_field(pb.grid_connection_data_record.today_active)
    l1_power = pb_field(pb.grid_connection_power_L1, pround(2))
    l1_current = pb_field(pb.grid_connection_amp_L1, pround(2))
    l1_voltage = pb_field(pb.grid_connection_vol_L1, pround(1))
    l1_energy = pb_field(pb.grid_connection_data_record.today_active_L1)
    wifi_rssi = pb_field(pb.module_wifi_rssi)

    # Channel 2 (not in the .proto)
    pv_power_sum = Field[float]()
    l2_power = Field[float]()
    l2_current = Field[float]()
    l2_voltage = Field[float]()
    l2_energy = Field[float]()

    async def packet_parse(self, data: bytes):
        return Packet.from_bytes(data, xor_payload=True)

    def _update_channel2(self, payload: bytes):
        f = _raw_fields(payload)

        def num(n: int, digits: int):
            v = f.get(n)
            return round(float(v), digits) if isinstance(v, (int, float)) else None

        for name, n, digits in (
            ("pv_power_sum", CH2_TOTAL, 1),
            ("l2_power", CH2_POWER_L1, 2),
            ("l2_current", CH2_AMP_L1, 2),
            ("l2_voltage", CH2_VOLT_L1, 1),
        ):
            if (v := num(n, digits)) is not None:
                setattr(self, name, v)
        rec = f.get(CH2_ENERGY)
        if isinstance(rec, bytes):
            today = _raw_fields(rec).get(1)  # today_active_L1 of channel 2
            if isinstance(today, float):
                self.l2_energy = today

    async def data_parse(self, packet: Packet):
        processed = False
        self.reset_updated()

        match packet.src, packet.cmd_set, packet.cmd_id:
            case (0x02, 0xFE, 0x15):
                self.update_from_bytes(
                    bk622_common_pb2.DisplayPropertyUpload, packet.payload
                )
                self._update_channel2(packet.payload)
                processed = True

        for field_name in self.updated_fields:
            self.update_callback(field_name)
            self.update_state(field_name, getattr(self, field_name))

        return processed
