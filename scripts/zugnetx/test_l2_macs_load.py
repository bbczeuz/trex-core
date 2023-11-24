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

    def fill_l2_self(self, direction):
        """
        Send packets with physical interface MACs
        """
        base_pkt =  Ether()/IP(src="10.0.0.1",dst="20.0.0.1")/UDP(dport=direction,sport=1025)/"self"
        size = self.fsize - 4 # HW will add 4 bytes ethernet FCS
        pad = max(0, size - len(base_pkt)) * 'x'
        vm = STLScVmRaw(cache_size=2)
        return STLStream(name = "Self",
                         next = "MacTable",
                         #next = "DUT",
                         packet = STLPktBuilder(pkt = base_pkt/pad, vm = vm),
                         mode = STLTXSingleBurst( pps = 10, total_pkts = 1)
                        )


    def fill_l2_forwarding_table(self, direction, port_id):
        """
        Send packets with src=random MAC, dst=physical interface MACs -> preload L2 forwarding table
        """
        if direction == 0:
            base_pkt =  Ether(src=self.mac_ab) / IP(src="13.0.0.1", dst="23.0.0.1") / UDP(dport=direction, sport=port_id)/"load"
        else:
            base_pkt =  Ether(src=self.mac_ba) / IP(src="14.0.0.1", dst="24.0.0.1") / UDP(dport=direction, sport=port_id)/"load"

        # Create base packet and pad it to size
        size = self.fsize - 4; # HW will add 4 bytes ethernet FCS
        pad = max(0, size - len(base_pkt)) * 'x'

        generator_code = [
                           STLVmFlowVar(name="dyn_mac", min_value=0, max_value=self.mac_count-1, size=2, op="inc"), # 2 byte varible, range 1-1 ( workaround)
                           STLVmWrFlowVar(fv_name="dyn_mac", pkt_offset=10),#ofs=4: MAC dest, ofs=10: MAC source
                          ]
        vm = STLScVmRaw(generator_code, cache_size=4*1024)

        return STLStream(name = "MacTable",
                         #next = "DUT",
                         packet = STLPktBuilder(pkt = base_pkt/pad,vm = vm),
                         mode = STLTXSingleBurst( pps=10, total_pkts = self.mac_count)
                        )


    def get_streams (self, direction, tunables, **kwargs):
        parser = argparse.ArgumentParser(description='Argparser for {}'.format(os.path.basename(__file__)), 
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument('--fsize',
                            type=int,
                            default=64,
                            help="The packets size in the data stream")
        parser.add_argument('--ports',
                            type=int,
                            default=500,
                            help="The number of UDP src ports")
        parser.add_argument('--macs',
                            type=int,
                            default=8,
                            help="The number of MAC addresses")
        args = parser.parse_args(tunables)
        self.fsize = args.fsize
        self.mac_count = args.macs
        self.port_count = args.ports
        return [
                self.fill_l2_self(direction),
                self.fill_l2_forwarding_table(direction, kwargs['port_id']),
               ]


# dynamic load - used for trex console or simulator
def register():
    return STLS1()



