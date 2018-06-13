
import sys, os
from scapy.all import *
import simpy
import crcmod
from utils.hwsim_tools import *

# HASH_POLYS = [0x104c11db7, 0x11edc6f41, 0x1814141AB, 0x1741B8CD7, 0x142F0E1EBA9EA3693]
HASH_POLYS = [0x104c11db7, 0x11edc6f41, 0x1814141AB]

class STFQCMSPipe(HW_sim_object):
    def __init__(self, env, period, r_in_pipe, r_out_pipe, w_in_pipe, w_out_pipe, cmswidth, vt_tracker):
        """
        r_in_pipe  : used to receive read result ACK
        r_out_pipe : used to return read result
        w_in_pipe  : used to receive write data
        w_out_pipe : used to indicate write completion
        """
        super(STFQCMSPipe, self).__init__(env, period)

        # Top level interface
        self.r_in_pipe = r_in_pipe
        self.r_out_pipe = r_out_pipe
        self.w_in_pipe = w_in_pipe
        self.w_out_pipe = w_out_pipe

        self.cms_width = cmswidth

        self.hash_arrays = [[0 for i in range(self.cms_width)] for j in range(len(HASH_POLYS))]

        self.vt_tracker = vt_tracker

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

            hash_indices = self.get_hash_idxs(pkt)
            penalty = self.get_penalty(hash_indices)
            virtual_time = self.vt_tracker.virtual_time
            rank = max(virtual_time, penalty)
            self.set_penalty(rank, pkt, hash_indices)

            self.r_out_pipe.put((rank, q_id, pkt))
            yield self.r_in_pipe.get()

    def get_hash_idxs(self, pkt):
            hash_fns = [crcmod.Crc(poly, initCrc = 0) for poly in HASH_POLYS]
            hashTuple = pkt[IP].src + pkt[IP].dst + str(pkt[IP].proto) + str(pkt.sport) + str(pkt.dport)

            for fn in hash_fns:
                fn.update(hashTuple)

            return [int(fn.hexdigest(), 16) % self.cms_width for fn in hash_fns]

    def get_penalty(self, hash_indices):
        penalties = [cms[hash_indices[i]] for i, cms in enumerate(self.hash_arrays)]

        return min(penalties)

    def set_penalty(self, rank, pkt, hash_indices):
        for i, cms in enumerate(self.hash_arrays):
            cms[hash_indices[i]] = max(rank + len(pkt), cms[hash_indices[i]])
