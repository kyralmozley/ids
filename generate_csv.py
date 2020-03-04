import csv
import glob
import traceback

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

global labels
global count

def get_labels(csv_file):
    global labels
    path = 'MachineLearningCVE/'
    all_files = glob.glob(path + csv_file + ".csv")
    dataset = pd.concat((pd.read_csv(f, low_memory=False) for f in all_files))

    col_names = ["Destination_Port",
                 "Flow_Duration",
                 "Total_Fwd_Packets",
                 "Total_Backward_Packets",
                 "Total_Length_of_Fwd_Packets",
                 "Total_Length_of_Bwd_Packets",
                 "Fwd_Packet_Length_Max",
                 "Fwd_Packet_Length_Min",
                 "Fwd_Packet_Length_Mean",
                 "Fwd_Packet_Length_Std",
                 "Bwd_Packet_Length_Max",
                 "Bwd_Packet_Length_Min",
                 "Bwd_Packet_Length_Mean",
                 "Bwd_Packet_Length_Std",
                 "Flow_Bytes_s",
                 "Flow_Packets_s",
                 "Flow_IAT_Mean",
                 "Flow_IAT_Std",
                 "Flow_IAT_Max",
                 "Flow_IAT_Min",
                 "Fwd_IAT_Total",
                 "Fwd_IAT_Mean",
                 "Fwd_IAT_Std",
                 "Fwd_IAT_Max",
                 "Fwd_IAT_Min",
                 "Bwd_IAT_Total",
                 "Bwd_IAT_Mean",
                 "Bwd_IAT_Std",
                 "Bwd_IAT_Max",
                 "Bwd_IAT_Min",
                 "Fwd_PSH_Flags",
                 "Bwd_PSH_Flags",
                 "Fwd_URG_Flags",
                 "Bwd_URG_Flags",
                 "Fwd_Header_Length",
                 "Bwd_Header_Length",
                 "Fwd_Packets_s",
                 "Bwd_Packets_s",
                 "Min_Packet_Length",
                 "Max_Packet_Length",
                 "Packet_Length_Mean",
                 "Packet_Length_Std",
                 "Packet_Length_Variance",
                 "FIN_Flag_Count",
                 "SYN_Flag_Count",
                 "RST_Flag_Count",
                 "PSH_Flag_Count",
                 "ACK_Flag_Count",
                 "URG_Flag_Count",
                 "CWE_Flag_Count",
                 "ECE_Flag_Count",
                 "Down_Up_Ratio",
                 "Average_Packet_Size",
                 "Avg_Fwd_Segment_Size",
                 "Avg_Bwd_Segment_Size",
                 "Fwd_Header_Length",
                 "Fwd_Avg_Bytes_Bulk",
                 "Fwd_Avg_Packets_Bulk",
                 "Fwd_Avg_Bulk_Rate",
                 "Bwd_Avg_Bytes_Bulk",
                 "Bwd_Avg_Packets_Bulk",
                 "Bwd_Avg_Bulk_Rate",
                 "Subflow_Fwd_Packets",
                 "Subflow_Fwd_Bytes",
                 "Subflow_Bwd_Packets",
                 "Subflow_Bwd_Bytes",
                 "Init_Win_bytes_forward",
                 "Init_Win_bytes_backward",
                 "act_data_pkt_fwd",
                 "min_seg_size_forward",
                 "Active_Mean",
                 "Active_Std",
                 "Active_Max",
                 "Active_Min",
                 "Idle_Mean",
                 "Idle_Std",
                 "Idle_Max",
                 "Idle_Min",
                 "Label"
                 ]
    dataset.columns = col_names
    labels = dataset['Label']


def output(features):
    global count
    f = features

    feature_string = [str(i) for i in f]
    classification = [str(labels[count])]
    count = count + 1
    print(feature_string + classification)
    w.writerow(feature_string + classification)

    return feature_string + classification


def newPacket(p):
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

        #print(p[TCP].flags, packet.getFINFlag(), packet.getSYNFlag(), packet.getPSHFlag(), packet.getACKFlag(),packet.getURGFlag() )

        if packet.getFwdID() in current_flows.keys():
            flow = current_flows[packet.getFwdID()]

            # check for timeout
            # for some reason they only do it if packet count > 1
            if (packet.getTimestamp() - flow.getFlowStartTime()) > FlowTimeout:
                if flow.packet_count > 1:
                    output(flow.terminated())
                del current_flows[packet.getFwdID()]
                flow = Flow(packet)
                current_flows[packet.getFwdID()] = flow

            # check for fin flag
            elif packet.getFINFlag():
                flow.new(packet, 'fwd')
                output(flow.terminated())
                del current_flows[packet.getFwdID()]
                del flow

            else:
                flow.new(packet, 'fwd')
                current_flows[packet.getFwdID()] = flow

        elif packet.getBwdID() in current_flows.keys():
            flow = current_flows[packet.getBwdID()]

            # check for timeout
            if (packet.getTimestamp() - flow.getFlowStartTime()) > FlowTimeout:
                output(flow.terminated())
                del current_flows[packet.getBwdID()]
                flow = Flow(packet)
                current_flows[packet.getFwdID()] = flow

            elif packet.getFINFlag():
                flow.new(packet, 'bwd')
                output(flow.terminated())
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


def main(pcap_file, csv_file):
    global count
    count = 0
    get_labels(csv_file)
    sniff(offline=pcap_file, prn=newPacket)

    for flow in current_flows:
        output(flow.terminated())
        del current_flows[flow.packetInfos[0].getFwdID()]

if __name__ == '__main__':
    main()
    f.close()



