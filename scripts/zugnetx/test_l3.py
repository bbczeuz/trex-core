# vim: et sw=4 ts=4
from trex_stl_lib.api import *
import argparse


# 1 clients MAC override the LSB of destination
# overide the src mac  00:bb:12:34:56:01 - 00:bb:12:34:56:0a
class STLS1(object):

    def __init__ (self):
        self.fsize  = 128; # the size of the packet 

    def create_stream (self, direction):
        # Create base packet and pad it to size
        size = self.fsize - 4; # HW will add 4 bytes ethernet FCS

        base_pkt =  Ether()/IP(src="16.0.0.1",dst="48.0.0.1")/UDP(dport=12,sport=1025)  
        pad = max(0, size - len(base_pkt)) * 'x'

        min_ip="16.0.0.0"
        max_ip="16.0.0.7"
        min_port=60001
        max_port=60500
        generator_code = [
                           STLVmTupleGen(name="tuple", ip_min=min_ip, ip_max=max_ip, port_min=min_port, port_max=max_port),
                           STLVmWrFlowVar(fv_name="tuple.ip",   pkt_offset= "IP.src" ),
                           STLVmWrFlowVar(fv_name="tuple.port", pkt_offset= "UDP.sport"),
                           STLVmFixChecksumHw(l3_offset="IP",l4_offset="UDP",l4_type=CTRexVmInsFixHwCs.L4_TYPE_UDP),
                          ]
        vm = STLScVmRaw(generator_code, cache_size =4*1024)

        return STLStream(packet = STLPktBuilder(pkt = base_pkt/pad,vm = vm),
                         mode = STLTXCont( pps=100)
                         #mode = STLTXSingleBurst( pps = 10, total_pkts = 10)
        )

    def get_streams (self, direction, tunables, **kwargs):
        parser = argparse.ArgumentParser(description='Argparser for {}'.format(os.path.basename(__file__)), 
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)

        args = parser.parse_args(tunables)
        # create 1 stream 
        return [ self.create_stream(direction) ]


# dynamic load - used for trex console or simulator
def register():
    return STLS1()



