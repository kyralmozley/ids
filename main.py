'''
Main class, initalize everything, and then hand over to sniffer & machine learning model
'''
import generate_csv
import snif


def create_csv():
    pcap_file = 'PCAP/Friday-WorkingHours.pcap'
    generate_csv.main(pcap_file)

def main():
    mode = input("Enter s to sniff, or p for pcap analysis. Default will be to sniff traffic.")
    if mode == 'p':
        #f = input("Enter path to file")
        f = 'PCAP/my_dos_hulk.pcap'
        snif.main(1, f)
    else:
        snif.main(0, '')


if __name__ == '__main__':
    main()
