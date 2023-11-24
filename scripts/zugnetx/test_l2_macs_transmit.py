# vim: et sw=4 ts=4 ai
from trex_stl_lib.api import *
import argparse


# 1 clients MAC override the LSB of destination
# overide the src mac  00:bb:12:34:56:01 - 00:bb:12:34:56:0a
class STLS1(object):


    def __init__ (self):
        self.fsize  = 64
        self.mac_count = 8
        self.port_count = 500
        self.mac_ab = "00:bb:12:00:00:00"
        self.mac_ba = "00:bb:13:00:00:00"


    def create_stream (self, direction, port_id):
        if direction == 0:
            base_pkt =  Ether(src=self.mac_ab, dst=self.mac_ba) / IP(src="13.0.0.1", dst="23.0.0.1") / UDP(dport=direction, sport=port_id)/"fill"
        else:
            base_pkt =  Ether(src=self.mac_ba, dst=self.mac_ab) / IP(src="14.0.0.1", dst="24.0.0.1") / UDP(dport=direction, sport=port_id)/"fill"

        # Create base packet and pad it to size
        size = self.fsize - 4; # HW will add 4 bytes ethernet FCS
        pad = max(0, size - len(base_pkt)) * 'x'

        min_ip = "16.0.0.0"
        max_ip = "16.15.255.255"
        min_port = 60001
        max_port = min_port + self.port_count
        generator_code = [
                           STLVmFlowVar(name="dyn_mac", min_value=0, max_value=self.mac_count-1, size=2, op="inc"), # 2 byte varible, range 1-1 ( workaround)
                           STLVmTupleGen(name="tuple", ip_min=min_ip, ip_max=max_ip, port_min=min_port, port_max=max_port),
                           STLVmWrFlowVar(fv_name="tuple.ip", pkt_offset= "IP.src" ),
                           STLVmWrFlowVar(fv_name="tuple.port", pkt_offset= "UDP.sport"),
                           STLVmFixChecksumHw(l3_offset="IP",l4_offset="UDP",l4_type=CTRexVmInsFixHwCs.L4_TYPE_UDP),
                           STLVmWrFlowVar(fv_name="dyn_mac", pkt_offset=4), #ofs=4: MAC dest, ofs=10: MAC source
                           STLVmWrFlowVar(fv_name="dyn_mac", pkt_offset=10),#ofs=4: MAC dest, ofs=10: MAC source
                          ]
        vm = STLScVmRaw(generator_code, cache_size=4*1024)

        return STLStream(name = "DUT",
                         packet = STLPktBuilder(pkt = base_pkt/pad,vm = vm),
                         mode = STLTXCont( pps=10),
                        )


    def get_streams (self, direction, tunables, **kwargs):
        parser = argparse.ArgumentParser(description='Argparser for {}'.format(os.path.basename(__file__)), 
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument('--fsize',
                            type=int,
                            default=1024,
                            help="The packets size in the data stream")
        parser.add_argument('--ports',
                            type=int,
                            default=50,
                            help="The number of UDP src ports")
        parser.add_argument('--macs',
                            type=int,
                            default=10,
                            help="The number of MAC addresses")
        args = parser.parse_args(tunables)
        self.fsize = args.fsize
        self.mac_count = args.macs
        self.port_count = args.ports
        return [
                self.create_stream(direction, kwargs['port_id']),
               ]


# dynamic load - used for trex console or simulator
def register():
    return STLS1()



