'''
Main class, initalize everything, and then hand over to sniffer & machine learning model
'''
import generate_csv
from flow import snif

def create_csv():
    pcap_file = 'PCAP/Tuesday-WorkingHours.pcap'
    csv_file = 'Tuesday-WorkingHours.pcap_ISCX'
    generate_csv.main(pcap_file, csv_file)

def main():
    mode = input("Enter s to sniff, or p for pcap analysis. Default will be to sniff traffic.")
    if mode == 'p':
        #f = input("Enter path to file")
        f = 'PCAP/Tuesday-WorkingHours.pcap'
        snif.main(1, f)
    else:
        snif.main(0, '')


if __name__ == '__main__':
    create_csv()