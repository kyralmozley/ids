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

def monday_labels(flow):
    return 'Benign'


def tuesday_labels(flow):
    victim_ip = '192.168.10.50'
    attacker_ip = '172.16.0.1'

    timezone = 4 * 3600
    ftp_start_time = datetime.datetime(2017,7,4,9,10).timestamp()
    # ftp_end_time = datetime.datetime(2017,7,4,10,20).timestamp()
    ssh_start_time = datetime.datetime(2017,7,4,14,0).timestamp()
    # sh_end_time = datetime.datetime(2017,7,4,15,0).timestamp()

    p = flow.packetInfos[0]
    startTime = flow.getFlowStartTime()
    endTime = flow.flowLastSeen

    #print(p.getSrc(), p.getDest(), startTime - timezone, ftp_start_time)
    if p.getSrc() == victim_ip or p.getDest() == victim_ip:
        if p.getSrc() == attacker_ip or p.getDest() == attacker_ip:

            if (startTime - timezone) >= ftp_start_time and (endTime - timezone) < ssh_start_time:
                return 'FTP-Patator'

            if (startTime - timezone) >= ssh_start_time:
                return 'SSH-Patator'

    return 'Benign'

def wednesday_labels(flow):
    victim_ip = '192.168.10.50'
    attacker_ip = '172.16.0.1'

    timezone = 4 * 3600

    dos_loris_start_time = datetime.datetime(2017, 7, 5, 9, 47).timestamp()
    dos_loris_end_time = datetime.datetime(2017, 7, 5, 10, 10).timestamp()

    dos_http_start_time = datetime.datetime(2017, 7, 5, 10, 14).timestamp()
    dos_http_end_time = datetime.datetime(2017, 7, 5, 10, 35).timestamp()

    dos_hulk_start_time = datetime.datetime(2017, 7, 5, 10, 43).timestamp()
    dos_hulk_end_time = datetime.datetime(2017, 7, 5, 11, 0).timestamp()

    dos_golden_start_time = datetime.datetime(2017, 7, 5, 11, 10).timestamp()
    dos_golden_end_time = datetime.datetime(2017, 7, 5, 11, 23).timestamp()

    p = flow.packetInfos[0]
    startTime = flow.getFlowStartTime()
    endTime = flow.flowLastSeen

    # print(p.getSrc(), p.getDest(), startTime - timezone, dos_loris_start_time)
    if p.getSrc() == victim_ip or p.getDest() == victim_ip:
        if p.getSrc() == attacker_ip or p.getDest() == attacker_ip:

            if (startTime - timezone) >= dos_loris_start_time and (endTime - timezone) < dos_http_start_time:
                return 'DoS slowloris'

            if (startTime - timezone) >= dos_http_start_time and (endTime - timezone) < dos_hulk_start_time:
                return 'DoS Slowhttptest'

            if (startTime - timezone) >= dos_hulk_start_time and (endTime - timezone) < dos_golden_start_time:
                return 'DoS Hulk'

            if (startTime - timezone) >= dos_golden_start_time:
                return 'DoS GoldenEye'

    return 'Benign'

def thursday_labels(flow):
    victim_ip = '192.168.10.50'
    attacker_ip = '172.16.0.1'

    timezone = 4 * 3600
    brute_force_start_time = datetime.datetime(2017,7,6,9,20).timestamp()
    brute_force_end_time = datetime.datetime(2017,7,6,10,0).timestamp()
    xss_start_time = datetime.datetime(2017,7,6,10,15).timestamp()
    xss_end_time = datetime.datetime(2017,7,6,10,35).timestamp()

    p = flow.packetInfos[0]
    startTime = flow.getFlowStartTime()
    endTime = flow.flowLastSeen

    print(p.getSrc(), p.getDest(), startTime - timezone, brute_force_start_time)
    if p.getSrc() == victim_ip or p.getDest() == victim_ip:
        if p.getSrc() == attacker_ip or p.getDest() == attacker_ip:
            print("attack", startTime - timezone, brute_force_start_time, brute_force_end_time)

            if (startTime - timezone) > brute_force_start_time and (endTime - timezone) < brute_force_end_time:
                print('brute force')
                return 'Brute Force'

            if (startTime - timezone) > xss_start_time and (endTime - timezone) < xss_end_time:
                print('xss')
                return 'XSS'

    return 'Benign'

def friday_morning_labels(flow):
    victim_1 = '192.168.10.15'
    victim_2 = '192.168.10.9'
    victim_3 = '192.168.10.14'
    victim_4 = '192.168.10.8'
    victim_5 = '192.168.10.50'
    victim = [victim_1, victim_2, victim_3, victim_4, victim_5]

    attacker_1 = '172.16.0.1'
    attacker_2 = '205.174.165.80'
    attacker_3 = '205.174.165.73'
    attacker = [attacker_1, attacker_2, attacker_3]

    timezone = 4 * 3600
    botnet_start_time = datetime.datetime(2017,7,7,10,2).timestamp()
    botnet_end_time = datetime.datetime(2017,7,7,11,2).timestamp()


    p = flow.packetInfos[0]
    startTime = flow.getFlowStartTime()
    endTime = flow.flowLastSeen

    if p.getSrc() in victim or p.getDest in victim:
        if p.getSrc() in attacker or p.getDest() in attacker:
            if (startTime - timezone) >= botnet_start_time and (endTime - timezone) < botnet_end_time:
                return 'Bot'
    return 'Benign'

def friday_afternoon_port_labels(flow):
    victim = '192.168.10.50'

    attacker_1 = '172.16.0.1'
    attacker_2 = '205.174.165.80'
    attacker_3 = '205.174.165.73'
    attacker = [attacker_1, attacker_2, attacker_3]

    timezone = 4 * 3600
    port_scan_start_time = datetime.datetime(2017,7,7,13,50).timestamp()
    port_scan_end_time = datetime.datetime(2017,7,7,14,50).timestamp()


    p = flow.packetInfos[0]
    startTime = flow.getFlowStartTime()
    endTime = flow.flowLastSeen

    if p.getSrc() == victim or p.getDest == victim:
        if p.getSrc() in attacker or p.getDest() in attacker:
            if (startTime - timezone) >= port_scan_start_time and (endTime - timezone) < port_scan_end_time:
                return 'PortScan'
    return 'Benign'

def friday_afternoon_ddos(flow):
    victim_ip = '192.168.10.50'

    attacker_1 = '172.16.0.1'
    attacker_2 = '205.174.165.80'
    attacker_3 = '205.174.165.69'
    attacker_4 = '205.174.165.70'
    attacker_5 = '205.174.165.71'
    attackers = [attacker_1, attacker_2, attacker_3, attacker_4, attacker_5]

    timezone = 4 * 3600
    ddos_start_time = datetime.datetime(2017,7,7,15,50).timestamp()
    ddos_end_time = datetime.datetime(2017,7,7,14,20).timestamp()


    p = flow.packetInfos[0]
    startTime = flow.getFlowStartTime()
    endTime = flow.flowLastSeen

    if p.getSrc() == victim_ip or p.getDest == victim_ip:
        if p.getSrc() in attackers or p.getDest() in attackers:
            if (startTime - timezone) >= ddos_start_time and (endTime - timezone) < ddos_end_time:
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


def newPacket(p):
    # for friday morn
    if p.time > (datetime.datetime(2017,7,7,12,2).timestamp() + 4 * 3600):
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
            elif packet.getFINFlag():
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
                flow = Flow(packet)
                current_flows[packet.getFwdID()] = flow

            elif packet.getFINFlag():
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


    except Exception:
        traceback.print_exc()


def main(pcap_file):
    sniff(offline=pcap_file, prn=newPacket)
    print('done')
    for flow in current_flows.values():
        output(flow.terminated(), flow)


if __name__ == '__main__':
    main()
    f.close()
