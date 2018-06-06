
import sys, os
from scapy.all import *
import simpy
from utils.hwsim_tools import *

class STFQPipe(HW_sim_object):
    def __init__(self, env, period, r_in_pipe, r_out_pipe, w_in_pipe, w_out_pipe, vt_tracker):
        """
        r_in_pipe  : used to receive read result ACK
        r_out_pipe : used to return read result
        w_in_pipe  : used to receive write data
        w_out_pipe : used to indicate write completion
        """
        super(StrictPipe, self).__init__(env, period)

        # Top level interface
        self.r_in_pipe = r_in_pipe
        self.r_out_pipe = r_out_pipe
        self.w_in_pipe = w_in_pipe
        self.w_out_pipe = w_out_pipe

        self.vt_tracker = vt_tracker
        self.last_finish = {}

        # register processes for simulation
        self.run()

    def run(self):
        self.env.process(self.compute_rank())

    def compute_rank(self):
        """
        Pipeline to compute rank for pkt
        """
        while not self.sim_done:
            # wait to receive incoming pkt
            (q_id, pkt) = yield self.w_in_pipe.get()
            self.w_out_pipe.put(1)

            flowTuple = pkt[IP].src + pkt[IP].dst + pkt[IP].proto + pkt[TCP].sport + pkt[TCP].dport
            rank = 0
            virtual_time = self.vt_tracker.virtual_time

            if flowTuple in last_finish: 
                rank = max(virtual_time, last_finish[flowTuple])
            else:
                rank = virtual_time
            last_finish[flowTuple] = rank + len(pkt)

            self.r_out_pipe.put((rank, q_id, pkt))
            yield self.r_in_pipe.get()
