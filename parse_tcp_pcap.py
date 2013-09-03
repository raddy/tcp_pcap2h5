import sys,os
from tcp_pcap2h5 import open_pcap

def main(file_name):
    print 'Parsing %s ....' %file_name
    open_pcap(file_name)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit('Usage: %s tcp pcap-path' % sys.argv[0])

    if not os.path.exists(sys.argv[1]):
        sys.exit('ERROR: Raw Pcap file %s was not found!' % sys.argv[1])
    sys.exit(main(sys.argv[1]))