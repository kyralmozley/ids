import csv
import datetime
import glob
import traceback
from datetime import time

import pandas as pd
from scapy.sendrecv import sniff
import numpy as np

from flow.Flow import Flow
from flow.PacketInfo import PacketInfo

import warnings

warnings.filterwarnings("ignore")

f = open("output.csv", 'w')
w = csv.writer(f)

current_flows = {}
terminated = []
FlowTimeout = 600

victim_ips = [
    '192.168.10.3',
    '192.168.10.50',
    '205.174.165.68',
    '192.168.10.51',
    '205.174.165.66',
    '192.168.10.19',
    '192.168.10.17',
    '192.168.10.16',
    '192.168.10.12',
    '192.168.10.9',
    '192.168.10.5',
    '192.168.10.8',
    '192.168.10.14',
    '192.168.10.15',
    '192.168.10.25'
]

attacker_ips = [
    '205.174.165.73',
    '205.174.165.69',
    '205.174.165.70',
    '205.174.165.71',
    '205.174.165.80',
    '172.16.0.10',
    '172.16.0.1',
    '172.16.0.11',
]

timezone = 4 * 3600

def monday_labels(flow):
    return 'Benign'


def tuesday_labels(flow):

    ftp_start_time = datetime.datetime(2017,7,4,9,10).timestamp()
    ftp_end_time = datetime.datetime(2017,7,4,10,30).timestamp()
    ssh_start_time = datetime.datetime(2017,7,4,13,50).timestamp()
    sh_end_time = datetime.datetime(2017,7,4,15,10).timestamp()

    p = flow.packetInfos[0]
    startTime = flow.getFlowStartTime()
    endTime = flow.flowLastSeen

    if p.getSrc() in attacker_ips or p.getDest() in attacker_ips:
        if p.getSrc() in victim_ips or p.getDest() in victim_ips:

            if (startTime - timezone) >= ftp_start_time and (endTime - timezone) < ftp_end_time:
                return 'FTP-Patator'

            if (startTime - timezone) >= ssh_start_time and (endTime - timezone) < sh_end_time:
                return 'SSH-Patator'

    return 'Benign'



def wednesday_labels(flow):

    dos_start_time = datetime.datetime(2017, 7,5,9,40).timestamp()
    dos_end_time = datetime.datetime(2017,7,5,11,30).timestamp()

    p = flow.packetInfos[0]
    startTime = flow.getFlowStartTime()
    endTime = flow.flowLastSeen

    if p.getSrc() in attacker_ips or p.getDest() in attacker_ips:
        if p.getSrc() in victim_ips or p.getDest() in victim_ips:
            if (startTime - timezone) >= dos_start_time and (endTime - timezone) < dos_end_time:
                return 'DoS'
    return 'Benign'


def thursday_labels(flow):
    web_start_time = datetime.datetime(2017, 7, 6, 9, 10).timestamp()
    web_end_time = datetime.datetime(2017, 7, 6, 10, 45).timestamp()

    p = flow.packetInfos[0]
    startTime = flow.getFlowStartTime()
    endTime = flow.flowLastSeen

    if p.getSrc() in attacker_ips or p.getDest() in attacker_ips:
        if p.getSrc() in victim_ips or p.getDest() in victim_ips:
            if (startTime - timezone) >= web_start_time and (endTime - timezone) < web_end_time:
                return 'Web Attack'
    return 'Benign'


def friday_morning_labels(flow):
    bot_start_time = datetime.datetime(2017, 7, 7, 9, 55).timestamp()
    bot_end_time = datetime.datetime(2017, 7, 7, 11, 10).timestamp()

    p = flow.packetInfos[0]
    startTime = flow.getFlowStartTime()
    endTime = flow.flowLastSeen

    if p.getSrc() in attacker_ips or p.getDest() in attacker_ips:
        if p.getSrc() in victim_ips or p.getDest() in victim_ips:
            if (startTime - timezone) >= bot_start_time and (endTime - timezone) < bot_end_time:
                    return 'Botnet'
    return 'Benign'

def friday_afternoon_labels(flow):
    portscan_start = datetime.datetime(2017,7,7,13,45).timestamp()
    portscan_end = datetime.datetime(2017,7,7,15,40).timestamp()

    ddos_start = datetime.datetime(2017,7,7,15,45,0).timestamp()
    ddos_end = datetime.datetime(2017,7,7,16,25).timestamp()

    p = flow.packetInfos[0]
    startTime = flow.getFlowStartTime()
    endTime = flow.flowLastSeen

    if p.getSrc() in attacker_ips or p.getDest() in attacker_ips:
        if p.getSrc() in victim_ips or p.getDest() in victim_ips:
            if (startTime - timezone) >= portscan_start and (endTime - timezone) < portscan_end:
                return 'Probe'
            if (startTime - timezone) >= ddos_start and (endTime - timezone) < ddos_end:
                return 'DDoS'
    return 'Benign'



def output(features, flow):
    f = features

    feature_string = [str(i) for i in f]
    classification = friday_morning_labels(flow)
    if classification != 'Benign':
        print(feature_string + [classification])
    w.writerow(feature_string + [classification])

    return feature_string + [classification]

def check_time(day, time):
    if day == 'mon':
        return True
    if day == 'tue-mon':
        if time < (datetime.datetime(2017,7,4,12,0).timestamp() + timezone):
            return True
    if day == 'tue-aft':
        if (datetime.datetime(2017, 7, 4, 16, 0).timestamp() + timezone) > time > (datetime.datetime(2017, 7, 4, 12, 0).timestamp() + timezone):
            return True

    if day == 'wed':
        if time < (datetime.datetime(2017,7,5,12,0).timestamp() + timezone):
            return True

    if day == 'thur':
        if time < (datetime.datetime(2017,7,6,12,0).timestamp() + timezone):
            return True

    if day == 'fri-mon':
        if time < (datetime.datetime(2017,7,7,12,0).timestamp() + timezone):
            return True
    if day == 'fri-aft':
        if time > (datetime.datetime(2017, 7, 4, 13, 0).timestamp() + timezone):
            return True

    return False


def newPacket(p):
    # for friday morn
    if not check_time('fri-mon',  p.time):
        print('time done')
        return
    try:
        packet = PacketInfo()
        packet.setDest(p)
        packet.setSrc(p)
        packet.setSrcPort(p)
        packet.setDestPort(p)
        packet.setProtocol(p)
        packet.setTimestamp(p)
        packet.setPSHFlag(p)
        packet.setFINFlag(p)
        packet.setSYNFlag(p)
        packet.setACKFlag(p)
        packet.setURGFlag(p)
        packet.setRSTFlag(p)
        packet.setPayloadBytes(p)
        packet.setHeaderBytes(p)
        packet.setWinBytes(p)
        packet.setFwdID()
        packet.setBwdID()

        if packet.getFwdID() in current_flows.keys():
            flow = current_flows[packet.getFwdID()]

            # check for timeout
            # for some reason they only do it if packet count > 1
            if (packet.getTimestamp() - flow.getFlowStartTime()) > FlowTimeout:
                output(flow.terminated(), flow)
                del current_flows[packet.getFwdID()]
                flow = Flow(packet)
                current_flows[packet.getFwdID()] = flow

            # check for fin flag
            elif packet.getFINFlag() or packet.getRSTFlag():
                flow.new(packet, 'fwd')
                output(flow.terminated(), flow)
                del current_flows[packet.getFwdID()]
                del flow

            else:
                flow.new(packet, 'fwd')
                current_flows[packet.getFwdID()] = flow

        elif packet.getBwdID() in current_flows.keys():
            flow = current_flows[packet.getBwdID()]

            # check for timeout
            if (packet.getTimestamp() - flow.getFlowStartTime()) > FlowTimeout:
                output(flow.terminated(), flow)
                del current_flows[packet.getBwdID()]
                del flow
                flow = Flow(packet)
                current_flows[packet.getFwdID()] = flow

            elif packet.getFINFlag() or packet.getRSTFlag():
                flow.new(packet, 'bwd')
                output(flow.terminated(), flow)
                del current_flows[packet.getBwdID()]
                del flow
            else:
                flow.new(packet, 'bwd')
                current_flows[packet.getBwdID()] = flow
        else:

            flow = Flow(packet)
            current_flows[packet.getFwdID()] = flow
            # current flows put id, (new) flow

    except AttributeError as none:
        # not IP or TCP
        return

    except Exception:
        traceback.print_exc()


def main(pcap_file):
    sniff(offline=pcap_file, prn=newPacket)
    for flow in current_flows.values():
        output(flow.terminated(), flow)


if __name__ == '__main__':
    main()
    f.close()
