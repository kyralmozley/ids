import glob
import numpy as np
import pandas as pd

from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split



def dataset():
    path = 'MachineLearningCVE'
    all_files = glob.glob(path + "/*.csv")
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
    attack_group = {'BENIGN': 'Benign',
                    'DoS Hulk': 'DoS',
                    'PortScan': 'Probe',
                    'DDoS': 'DDoS',
                    'DoS GoldenEye': 'DoS',
                    'FTP-Patator': 'FTP-Patator',
                    'SSH-Patator': 'SSH-Patator',
                    'DoS slowloris': 'DoS',
                    'DoS Slowhttptest': 'DoS',
                    'Bot': 'Botnet',
                    'Brute Force': 'Web Attack',
                    'XSS': 'Web Attack'}

    # drop null, inf, duplicate

    dataset['Flow_Bytes_s'] = dataset['Flow_Bytes_s'].astype('float64')
    dataset['Flow_Packets_s'] = dataset['Flow_Packets_s'].astype('float64')
    dataset = dataset.loc[:, ~dataset.columns.duplicated()]

    dataset = dataset.replace([np.inf, -np.inf], np.nan)
    dataset = dataset.dropna()

    index_to_drop = dataset[(dataset['Label'] == 'Heartbleed') | (dataset['Label'] == 'Web Attack � Sql Injection') | (
            dataset['Label'] == 'Infiltration')].index
    dataset.drop(index_to_drop, inplace=True)
    dataset.loc[dataset.Label == 'Web Attack � Brute Force', ['Label']] = 'Brute Force'
    dataset.loc[dataset.Label == 'Web Attack � XSS', ['Label']] = 'XSS'

    dataset['Label_Category'] = dataset['Label'].map(lambda x: attack_group[x])


    features = ['Destination_Port',
                'Flow_Duration',
                'Fwd_Packet_Length_Min',
                'Bwd_Packet_Length_Max',
                'Bwd_Packet_Length_Min',
                'Bwd_Packet_Length_Mean',
                'Bwd_Packet_Length_Std',
                'Flow_IAT_Mean',
                'Flow_IAT_Std',
                'Flow_IAT_Max',
                'Flow_IAT_Min',
                'Fwd_IAT_Total',
                'Fwd_IAT_Mean',
                'Fwd_IAT_Std',
                'Fwd_IAT_Max',
                'Fwd_IAT_Min',
                'Bwd_IAT_Total',
                'Bwd_IAT_Mean',
                'Bwd_IAT_Std',
                'Bwd_IAT_Max',
                'Bwd_IAT_Min',
                'Fwd_PSH_Flags',
                'Fwd_Packets_s',
                'Bwd_Packets_s',
                'Min_Packet_Length',
                'Max_Packet_Length',
                'Packet_Length_Mean',
                'Packet_Length_Std',
                'Packet_Length_Variance',
                'FIN_Flag_Count',
                'SYN_Flag_Count',
                'RST_Flag_Count',
                'PSH_Flag_Count',
                'ACK_Flag_Count',
                'Average_Packet_Size',
                'Avg_Bwd_Segment_Size',
                'Init_Win_bytes_forward',
                'Init_Win_bytes_backward',
                'Active_Mean',
                'Active_Std',
                'Active_Max',
                'Active_Min',
                'Idle_Mean',
                'Idle_Std',
                'Idle_Max']
    xs = dataset[features]
    ys = dataset['Label_Category']

    #normalise
    min_max_scaler = MinMaxScaler().fit(xs)
    xs = min_max_scaler.transform(xs)

    return xs, ys, min_max_scaler

'''
    x_train, x_test, y_train, y_test = train_test_split(xs, ys, test_size=0.8, random_state=0,
                                                        stratify=ys)

    # normalise
    min_max_scaler = MinMaxScaler().fit(x_train)
    x_train = min_max_scaler.transform(x_train)
    x_test = min_max_scaler.transform(x_test)

    # learn

    return x_train, x_test, y_train, y_test, min_max_scaler
    
    
'''
