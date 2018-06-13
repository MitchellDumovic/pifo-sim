import sys, os
from scapy.all import *
from collections import OrderedDict
import matplotlib
import matplotlib.pyplot as plt
import numpy as np


class avg_rate_stats(object):
    def __init__(self, flowID_tuple, pkt_list, avg_interval=1000):
        """
        flowID_tuple: tuple of tuples used to identify a flow in the pkt_list (e.g. ((IP, 'src'), (IP, 'dst')) )
        pkt_list: a list of nanosecond timestamps and scapy pkts with the format: [(t0, pkt0), (t1, pk1), ...]
        avg_interval: # of ns to avg rates over
        """

        self.avg_interval = avg_interval
        self.flowID_tuple = flowID_tuple
        self.flow_pkts = self.parse_pkt_list(pkt_list)
        self.rate_stats = self.calc_flow_rates(self.flow_pkts)

    def extract_flowID(self, pkt):
        flowID = []
        for (layer, field) in self.flowID_tuple:
            try:
                val = pkt[layer].getfieldval(field)
            except IndexError as e1:
                print >> sys.stderr, 'WARNING: layer {} not in pkt: {}'.format(layer.name, pkt.summary())
                return None
            except AttributeError as e2:
                print >> sys.stderr, 'WARNING: field {} not in pkt[{}]: {}'.format(field, layer.name, pkt[layer].summary())
                return None
            flowID.append(val)
        return tuple(flowID)

    def parse_pkt_list(self, pkt_list):
        """
        Read a pkt_list and parse into per-flow pkts
        """
        flow_pkts = {}
        for (t, pkt) in pkt_list:
            flowID = self.extract_flowID(pkt)
            if flowID not in flow_pkts.keys():
                flow_pkts[flowID] = [(t, pkt)]
            else:
                flow_pkts[flowID].append((t,pkt))
        return flow_pkts

    def calc_flow_rates(self, flow_pkts):
        """
        Given dictionary mapping flowIDs to the flow's pkts with nanosecond timestamps, calculate a new
        dictionary mapping flowIDs to the flow's measured rate
        """
        flow_rates = {}
        max_time = max(flow_pkts.items(), key=lambda x: x[1][-1][0])[1][-1][0] + 1
        for flowID, pkts in flow_pkts.items():
            min_range = 0
            max_range = self.avg_interval
            byte_cnt = 0
            flow_rates[flowID] = []
            for (timestamp, pkt) in pkts:
                if timestamp >= min_range and timestamp < max_range:
                    byte_cnt += len(pkt)
                else:
                    avg_time = min_range + self.avg_interval / 2
                    rate = (byte_cnt*8.0)/float(self.avg_interval)
                    flow_rates[flowID].append((avg_time, rate))

                    min_range += self.avg_interval
                    max_range += self.avg_interval
                    while not (timestamp >= min_range and timestamp < max_range):
                        flow_rates[flowID].append((min_range + self.avg_interval / 2, 0))
                        
                        min_range += self.avg_interval
                        max_range += self.avg_interval
                    byte_cnt = len(pkt)

        rate_stats = OrderedDict()
        flowIdx = 0
        for avg_time in range(self.avg_interval / 2, max_time, self.avg_interval):
            rates = []
            for flowId in flow_rates:
                if flowIdx >= len(flow_rates[flowId]):
                    continue
                rate = flow_rates[flowId][flowIdx][1]
                if rate > 0:
                    rates.append(rate) 

            flowIdx += 1
            if len(rates) == 0:
                rate_stats[avg_time] = (0, 0, 0, 0, 0)
            else: 
                rate_stats[avg_time] = (np.amax(rates), np.amin(rates), np.mean(rates), np.var(rates), len(rates))


        return rate_stats


    def line_gen(self):
        lines = ['-', '--', ':', '-.']
        i = 0
        while True:
            yield lines[i]
            i += 1
            i = i % len(lines)

    def plot_avg(self, ymax=None, linewidth=1):
        """
        Plots the flow rates
        """

        times = self.rate_stats.keys()
        averages = [val[2] for val in self.rate_stats.values()]
        plt.plot(times, averages, 'k-', label='Flow avg rates', linewidth=linewidth)

        plt.legend(loc='upper left')


    # Gets the average variance over all timesteps where all 50 flows are still active
    def get_var_avg(self):
        filtered = filter(lambda val: val[4] == 50, self.rate_stats.values())
        arr = np.array([val[3] for val in filtered])
        return np.mean(arr)


