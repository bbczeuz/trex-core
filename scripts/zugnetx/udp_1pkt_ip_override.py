from trex_stl_lib.api import *
import argparse


# 1 clients MAC override the LSB of destination
# overide the src mac  00:bb:12:34:56:01 - 00:bb:12:34:56:0a
class STLS1(object):


    def __init__ (self):
        self.fsize  = 1024; # the size of the packet 

    def create_stream (self, direction):

        # Create base packet and pad it to size
        size = self.fsize - 4; # HW will add 4 bytes ethernet FCS

        # Ether(src="00:bb:12:34:56:01") this will tell TRex to take the src-mac from packet and not from config file
        base_pkt =  Ether(src="00:bb:12:34:56:01")/IP(src="16.0.0.1",dst="48.0.0.1")/UDP(dport=12,sport=1025)  
        pad = max(0, size - len(base_pkt)) * 'x'

        #vm = STLScVmRaw( [ STLVmFlowVar(name="dyn_mac_src", min_value=0, max_value=255, size=1, op="inc"), # 1 byte varible, range 1-1 ( workaround)
        #                   STLVmWrFlowVar(fv_name="dyn_mac_src", pkt_offset= 11)                           
        #                  ]
        #               )
    
        vm = STLScVmRaw( [ 
                           #STLVmFlowVar(name="dyn_mac_src", min_value=min_mac, max_value=max_mac, size=2, op="inc"), # 2 byte varible, range 1-1 ( workaround)
                           STLVmFlowVar(name="dyn_mac_src", min_value=0 if direction==0 else 1, max_value=2 if direction==0 else 3, size=1, op="inc"), # 2 byte varible, range 1-1 ( workaround)
               #STLVmFlowVar(name="dyn_mac_src", min_value=0 if direction==0 else mac_count//2, max_value=mac_count//2+1 if direction==0 else mac_count, size=2, op="inc"), # 2 byte varible, range 1-1 ( workaround)
               #STLVmFlowVar(name="dyn_mac_src", min_value=0 if direction==0 else mac_count/2, max_value=mac_count/2-1 if direction==0 else mac_count, size=2, op="inc"), # 2 byte varible, range 1-1 ( workaround)
                           STLVmFlowVar(name="ip_src",
                                              min_value="16.0.0.0",
                                              max_value="16.0.0.255",
                                              size=4, op="random"),

                           STLVmFlowVar(name="src_port",
                                              min_value=60000,
                                              max_value=60500,
                                              size=2, op="random"),

                           STLVmWrFlowVar(fv_name="ip_src", pkt_offset= "IP.src" ),
                           STLVmFixIpv4(offset = "IP"), # fix checksum
                           STLVmWrFlowVar(fv_name="src_port", pkt_offset= "UDP.sport"),
                           #STLVmWrFlowVar(fv_name="dyn_mac_src", pkt_offset= 10)                           
                          ]
                       )

        return STLStream(packet = STLPktBuilder(pkt = base_pkt/pad,vm = vm),
                         random_seed = 314159,
                         mode = STLTXCont( pps=100))

    def get_streams (self, direction, tunables, **kwargs):
        parser = argparse.ArgumentParser(description='Argparser for {}'.format(os.path.basename(__file__)), 
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)

        args = parser.parse_args(tunables)
        # create 1 stream 
        return [ self.create_stream(direction) ]


# dynamic load - used for trex console or simulator
def register():
    return STLS1()



