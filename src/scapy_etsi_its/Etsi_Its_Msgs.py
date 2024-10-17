from pycrate_asn1dir import ITS_CAM_2, ITS_DENM_3
from pycrate_asn1dir.ITS import SPATEM_PDU_Descriptions, MAPEM_PDU_Descriptions, IVIM_PDU_Descriptions, \
    SREM_PDU_Descriptions, SSEM_PDU_Descriptions, EVCSN_PDU_Descriptions
from pycrate_asn1dir.ITS_IEEE1609_2 import Ieee1609Dot2
from scapy.all import *
from scapy.layers.l2 import SNAP, Ether


class PycratePacket(Packet):
    def _show_or_dump(self, dump=False, indent=3, lvl="", label_lvl="", first_call=True):
        if dump:
            from scapy.themes import AnsiColorTheme
            ct = AnsiColorTheme()  # No color for dump output
        else:
            ct = conf.color_theme
        s = "%s%s %s %s \n" % (label_lvl,
                               ct.punct("###["),
                               ct.layer_name(self.name),
                               ct.punct("]###"))

        if self.asn1 is not None:
            s += self.asn1.to_json() + "\n"

        if self.payload:
            s += self.payload._show_or_dump(  # type: ignore
                dump=dump,
                indent=indent,
                lvl=lvl + (" " * indent * self.show_indent),
                label_lvl=label_lvl,
                first_call=False
            )

        if first_call and not dump:
            print(s)
            return None
        else:
            return s

    def do_build(self):
        if self.asn1 is None:
            return bytes()
        else:
            return self.asn1.to_uper()


class GeoBasicHeader(Packet):
    name = "GeoBasicHeader"
    fields_desc = [
        BitField("Version", 1, 4),
        BitEnumField("NH", 1, 4, {
            0: "ANY",
            1: "Common Header",
            2: "Secured Packet"
        }),
        ByteField("Reserved", 0),
        ByteField("LT", 5),
        ByteField("RHL", 1)
    ]


bind_layers(SNAP, GeoBasicHeader, code=0x8947)
bind_layers(Ether, GeoBasicHeader, type=0x8947)


class GeoSecuredPacket(PycratePacket):
    name = "GeoSecuredPacket"
    payload_path = ["content", "signedData", "tbsData", "payload", "data", "content", "unsecuredData"]
    # r_sig_path = ["content", "signature", "rSig"]
    # s_sig_path = ["content", "signature", "sSig"]

    def do_dissect(self, s):
        if s.startswith(b'\x02'):
            # We don't parse legacy v2 packets, only extract the payload
            s = s[20:]
            s = s[:-68]
            return s

        secure_header = Ieee1609Dot2.Ieee1609Dot2Data
        secure_header.from_coer(s)
        self.asn1 = copy.copy(secure_header)
        value = secure_header.get_val_at(self.payload_path)
        # r_sig = secure_header.get_val(self.r_sig_path)
        # s_sig = secure_header.get_val(self.s_sig_path)
        # TODO: Encryption
        return value

    def do_build(self):
        pay = self.do_build_payload()
        self.asn1.set_val_at(self.payload_path, pay)
        return self.asn1.to_coer()


bind_layers(GeoBasicHeader, GeoSecuredPacket, NH=2)


class GeoCommonHeader(Packet):
    name = "GeoCommonHeader"
    fields_desc = [
        BitEnumField("NH", 0, 4, {
            0: "Unspecified",
            1: "BTP-A (Interactive)",
            2: "BTP-B (Non-Interactive)",
            3: "IPv6"
        }),
        BitField("Reserved1", 0, 4),
        BitEnumField("HT", 0, 4, {
            0: "Any",
            1: "Beacon",
            2: "GeoUnicast",
            3: "GeoAnycast",
            4: "GeoBroadcast",
            5: "TopologicallyScopedBroadcast",
            6: "LocationService"
        }),
        BitField("HST", 0, 4),  # Sub-Type
        ByteField("TC", 0),  # Traffic Class
        ByteField("Flags", 0),  # Flags
        ShortField("PL", 0),  # Payload Length
        ByteField("MHL", 0),  # Maximum Hop Limit
        ByteField("Reserved2", 0)
    ]


bind_layers(GeoBasicHeader, GeoCommonHeader, NH=1)
bind_layers(GeoSecuredPacket, GeoCommonHeader)


class SingleHopBroadcast(Packet):
    name = "SingleHopBroadcast"
    fields_desc = [
        BitField("manual", 0, 1),
        BitEnumField("HT", 0, 5, {
            0: "Unknown",
            1: "Pedestrian",
            2: "Cyclist",
            3: "Moped",
            4: "Motorcycle",
            5: "PassengerCar",
            6: "Bus",
            7: "LightTruck",
            8: "HeavyTruck",
            9: "Trailer",
            10: "SpecialVehicle",
            11: "Tram",
            15: "RoadSideUnit"
        }),
        BitField("reserved1", 0, 10),
        BitField("address", 0, 48),

        IntField("timestamp", 0),
        IntField("latitude", 0),
        IntField("longitude", 0),
        BitField("position_accuracy", 0, 1),
        BitField("speed", 0, 15),
        ShortField("heading", 0),
        IntField("reserved2", 0)
    ]


bind_layers(GeoCommonHeader, SingleHopBroadcast, HT=5)


class GeoBroadcast(Packet):
    name = "GeoBroadcast"
    fields_desc = [
        ShortField("sequence_number", 0),
        ShortField("reserved1", 0),
        # LongPositionVector
        # Adress
        BitField("manual", 0, 1),
        BitEnumField("HT", 0, 5, {
            0: "Unknown",
            1: "Pedestrian",
            2: "Cyclist",
            3: "Moped",
            4: "Motorcycle",
            5: "PassengerCar",
            6: "Bus",
            7: "LightTruck",
            8: "HeavyTruck",
            9: "Trailer",
            10: "SpecialVehicle",
            11: "Tram",
            15: "RoadSideUnit"
        }),
        BitField("reserved2", 0, 10),
        BitField("address", 0, 48),

        IntField("timestamp", 0),
        IntField("latitude", 0),
        IntField("longitude", 0),
        BitField("position_accuracy", 0, 1),
        BitField("speed", 0, 15),
        ShortField("heading", 0),

        # GeoBroadcast
        IntField("geo_area_position_latitude", 0),
        IntField("geo_area_position_longitude", 0),
        ShortField("distance_a", 0),
        ShortField("distance_b", 0),
        ShortField("angle", 0),
        ShortField("reserved3", 0)
    ]


bind_layers(GeoCommonHeader, GeoBroadcast, HT=4)


class BTPB(Packet):
    name = "BTP-B header"
    fields_desc = [
        ShortField("dport", 0),
        ShortField("dport_info", 0),
    ]


bind_layers(SingleHopBroadcast, BTPB)
bind_layers(GeoBroadcast, BTPB)


class ITS_CAM(PycratePacket):
    def do_dissect(self, s):
        cam = ITS_CAM_2.CAM_PDU_Descriptions.CAM
        cam.from_uper(s)
        self.asn1 = copy.copy(cam)
        return bytes()


bind_layers(BTPB, ITS_CAM, dport=2001)


class ITS_DENM(PycratePacket):
    def do_dissect(self, s):
        denm = ITS_DENM_3.DENM_PDU_Descriptions.DENM
        denm.from_uper(s)
        self.asn1 = denm
        return bytes()


bind_layers(BTPB, ITS_DENM, dport=2002)


class ITS_MAPEM(PycratePacket):
    def do_dissect(self, s):
        mapem = MAPEM_PDU_Descriptions.MAPEM
        mapem.from_uper(s)
        self.asn1 = copy.copy(mapem)
        return bytes()


bind_layers(BTPB, ITS_MAPEM, dport=2003)


class ITS_SPATEM(PycratePacket):
    def do_dissect(self, s):
        spatem = SPATEM_PDU_Descriptions.SPATEM
        spatem.from_uper(s)
        self.asn1 = copy.copy(spatem)
        return bytes()


bind_layers(BTPB, ITS_SPATEM, dport=2004)


class ITS_IVIM(PycratePacket):
    def do_dissect(self, s):
        ivim = IVIM_PDU_Descriptions.IVIM
        ivim.from_uper(s)
        self.asn1 = copy.copy(ivim)
        return bytes()


bind_layers(BTPB, ITS_IVIM, dport=2006)


class ITS_SREM(PycratePacket):
    def do_dissect(self, s):
        srem = SREM_PDU_Descriptions.SREM
        srem.from_uper(s)
        self.asn1 = copy.copy(srem)
        return bytes()


bind_layers(BTPB, ITS_IVIM, dport=2007)


class ITS_SSEM(PycratePacket):
    def do_dissect(self, s):
        ssem = SSEM_PDU_Descriptions.SSEM
        ssem.from_uper(s)
        self.asn1 = copy.copy(ssem)
        return bytes()


bind_layers(BTPB, ITS_IVIM, dport=2008)


class ITS_EVCSN(PycratePacket):
    def do_dissect(self, s):
        evcsn = EVCSN_PDU_Descriptions.EvcsnPdu
        evcsn.from_uper(s)
        self.asn1 = copy.copy(evcsn)
        return bytes()


bind_layers(BTPB, ITS_IVIM, dport=2010)
