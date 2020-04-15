import csv
import time
import traceback

from scapy.layers.inet import TCP
from scapy.sendrecv import sniff
from sklearn.ensemble import RandomForestClassifier
import numpy as np

import train
from flow.Flow import Flow
from flow.PacketInfo import PacketInfo

import warnings
warnings.filterwarnings("ignore")

f = open("output_logs.csv", 'w')
w = csv.writer(f)

current_flows = {}
FlowTimeout = 600

global X 
global Y
global normalisation
global classifier

def classify(features):
    # preprocess
    f = features
    features = [np.nan if x in [np.inf, -np.inf] else float(x) for x in features]

    if np.nan in features:
        return

    features = normalisation.transform([features])
    result = classifier.predict(features)

    feature_string = [str(i) for i in f]
    classification = [str(result[0])]
    if result != 'Benign':
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
        packet.setPacketSize(p)
        packet.setWinBytes(p)
        packet.setFwdID()
        packet.setBwdID()

        #print(p[TCP].flags, packet.getFINFlag(), packet.getSYNFlag(), packet.getPSHFlag(), packet.getACKFlag(),packet.getURGFlag() )

        if packet.getFwdID() in current_flows.keys():
            flow = current_flows[packet.getFwdID()]

            # check for timeout
            # for some reason they only do it if packet count > 1
            if (packet.getTimestamp() - flow.getFlowStartTime()) > FlowTimeout:
                classify(flow.terminated())
                del current_flows[packet.getFwdID()]
                flow = Flow(packet)
                current_flows[packet.getFwdID()] = flow

            # check for fin flag
            elif packet.getFINFlag() or packet.getRSTFlag():
                flow.new(packet, 'fwd')
                classify(flow.terminated())
                del current_flows[packet.getFwdID()]
                del flow

            else:
                flow.new(packet, 'fwd')
                current_flows[packet.getFwdID()] = flow

        elif packet.getBwdID() in current_flows.keys():
            flow = current_flows[packet.getBwdID()]

            # check for timeout
            if (packet.getTimestamp() - flow.getFlowStartTime()) > FlowTimeout:
                classify(flow.terminated())
                del current_flows[packet.getBwdID()]
                del flow
                flow = Flow(packet)
                current_flows[packet.getFwdID()] = flow

            elif packet.getFINFlag() or packet.getRSTFlag():
                flow.new(packet, 'bwd')
                classify(flow.terminated())
                del current_flows[packet.getBwdID()]
                del flow
            else:
                flow.new(packet, 'bwd')
                current_flows[packet.getBwdID()] = flow
        else:

            flow = Flow(packet)
            current_flows[packet.getFwdID()] = flow
            # current flows put id, (new) flow

    except AttributeError:
        # not IP or TCP
        return

    except:
        traceback.print_exc()


def live():
    print("Begin Sniffing".center(20, ' '))
    sniff(iface="en0", prn=newPacket)
    for f in current_flows.values():
        classify(f.terminated())


def pcap(f):
    sniff(offline=f, prn=newPacket)
    for flow in current_flows.values():
        classify(flow.terminated())


def main(mode, pcap_file):
    print(" Training ".center(20, '~'))
    global X, Y, normalisation, classifier
    x_train, y_train, min_max_scaler = train.dataset()
    X = x_train
    Y = y_train
    normalisation = min_max_scaler

    classifier = RandomForestClassifier()
    classifier = classifier.fit(X, Y)
    print(" Sniffing ".center(20, '*'))
    if mode == 0:
        live()
    else:
        pcap(pcap_file)


if __name__ == '__main__':
    main()
    f.close()
