from trex_stl_lib.api import *
import argparse


# 1 clients MAC override the LSB of destination
# overide the src mac  00:bb:12:34:56:01 - 00:bb:12:34:56:0a
class STLS1(object):


    def __init__ (self):
        self.fsize  = 64; # the size of the packet 

    def create_stream (self, direction):

        # Create base packet and pad it to size
        size = self.fsize - 4; # HW will add 4 bytes ethernet FCS

        # Ether(src="00:bb:12:34:56:01") this will tell TRex to take the src-mac from packet and not from config file
        base_pkt =  Ether()/IP(src="16.0.0.1",dst="48.0.0.1")/UDP(dport=12,sport=1025)  
        """
        if direction == 0:
            #base_pkt =  Ether(src="00:bb:12:34:56:01")/IP(src="16.0.0.1",dst="48.0.0.1")/UDP(dport=12,sport=1025)  
            base_pkt =  Ether(src="00:bb:12:00:00:00", dst="00:bb:13:00:00:00")/IP(src="16.0.0.1",dst="48.0.0.1")/UDP(dport=12,sport=1025)  
        else:
            base_pkt =  Ether(src="00:bb:13:00:00:00", dst="00:bb:12:00:00:00")/IP(src="16.0.0.1",dst="48.0.0.1")/UDP(dport=12,sport=1025)  
        """
        pad = max(0, size - len(base_pkt)) * 'x'

        #vm = STLScVmRaw( [ STLVmFlowVar(name="dyn_mac_src", min_value=0, max_value=255, size=1, op="inc"), # 1 byte varible, range 1-1 ( workaround)
        #                   STLVmWrFlowVar(fv_name="dyn_mac_src", pkt_offset= 11)                           
        #                  ]
        #               )
    
        mac_count = 16
        mac_offset = 0
        min_mac = 0
        max_mac = 0
        min_mac = (           0 if direction == 0 else mac_count//2 + 1) + mac_offset
        max_mac = (mac_count//2 if direction == 0 else mac_count       ) + mac_offset
        min_ip="16.0.0.0"
        max_ip="16.0.0.20"
        min_port=60000
        max_port=60500
        generator_code = [
                           STLVmFlowVar(name="dyn_mac_low", min_value=0, max_value=mac_count//2, size=2, op="inc"), # 2 byte varible, range 1-1 ( workaround)
                           STLVmFlowVar(name="dyn_mac_high", min_value=mac_count//2+1, max_value=mac_count, size=2, op="inc"), # 2 byte varible, range 1-1 ( workaround)
                           STLVmTupleGen(name="tuple", ip_min=min_ip, ip_max=max_ip, port_min=min_port, port_max=max_port),
                           STLVmWrFlowVar(fv_name="tuple.ip", pkt_offset= "IP.src" ),
                           STLVmWrFlowVar(fv_name="tuple.port", pkt_offset= "UDP.sport"),
                           STLVmFixChecksumHw(l3_offset="IP",l4_offset="UDP",l4_type=CTRexVmInsFixHwCs.L4_TYPE_UDP),
                          ]
        """
        if direction == 0:
            generator_code.append(STLVmWrFlowVar(fv_name="dyn_mac_high", pkt_offset=4)) #MAC source
            generator_code.append(STLVmWrFlowVar(fv_name="dyn_mac_low", pkt_offset=10)) #MAC destination
        else:
            generator_code.append(STLVmWrFlowVar(fv_name="dyn_mac_low", pkt_offset= 4)) #MAC source
            generator_code.append(STLVmWrFlowVar(fv_name="dyn_mac_high", pkt_offset= 10)) #MAC destination
        """
        vm = STLScVmRaw(generator_code, cache_size =4*1024)

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



