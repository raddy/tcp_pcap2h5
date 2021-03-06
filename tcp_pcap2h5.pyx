import numpy as np
import pandas as pd
import sys
cimport cython
cimport numpy as np
from libc.stdlib cimport malloc, free
from libc.string cimport strlen

ctypedef np.double_t DTYPE_t

cdef extern from "stdint.h" nogil:
    ctypedef   signed long  int64_t #pytables doesn't like unsigned ints apparently
    ctypedef unsigned short uint16_t
    ctypedef unsigned int uint8_t
    ctypedef unsigned int uint32_t
    
cdef extern from * nogil:
    ctypedef char const_char "const char"
    ctypedef void const_void "const void"
    
cdef extern from "string.h" nogil:
    void *memcpy  (void *TO, const_void *FROM, size_t SIZE)
    void *memset  (void *BLOCK, int C, size_t SIZE)

cdef extern from "time.h" nogil:
    ctypedef long time_t
    ctypedef long suseconds_t
    struct timeval:
        time_t tv_sec
        suseconds_t  tv_usec
    
cdef extern from "pcap.h" nogil:
    struct pcap_pkthdr:
        timeval ts
    ctypedef struct pcap_t:
        int __xxx
    pcap_t *pcap_open_offline(const char *, char *)
    unsigned char *pcap_next(pcap_t *p, pcap_pkthdr *hdr)
    void pcap_close(pcap_t *)

cdef extern from "netinet/in.h" nogil:
    ctypedef unsigned int in_addr_t    
    ctypedef struct in_addr:
        in_addr_t s_addr
    
cdef extern from "netinet/ip.h" nogil:
    struct ip:
        unsigned short ip_len
        unsigned char ip_p
        unsigned int ip_hl #not sure how to use this...
        in_addr ip_src,ip_dst
        
cdef extern from "arpa/inet.h" nogil:
    int ntohs (int)
    int ntohl (int)
    char* inet_ntoa(in_addr)

cdef extern from "netinet/tcp.h" nogil:
    ctypedef unsigned int tcp_seq
    struct tcphdr:
        unsigned short th_sport
        unsigned short th_dport
        tcp_seq th_seq
        tcp_seq th_ack
        unsigned int th_off

cdef packed struct tcp_packed:
        int64_t packet_time
        char source_ip[16]
        int64_t dest_port
        char dest_ip[16]
        int64_t source_port
        char pkt_data[1500]
        int64_t frame_len
        int64_t header_len
        int64_t seq
        int64_t ack 
        int64_t sack1_le 
        int64_t sack1_re 

ctypedef struct tcp_option_t:
    uint8_t kind
    uint8_t size       


    
#let's just ignore non-udp for now
@cython.cdivision(True)
@cython.boundscheck(False)
def open_pcap(some_pcap):
    cdef:
        char __ebuf[256]
        char *p = some_pcap
        pcap_t *handle = pcap_open_offline(p,__ebuf)
        pcap_pkthdr header
        const unsigned char *packet
        unsigned char* pkt_ptr
        ip *ip_hdr
        tcphdr *tcpHdr
        uint8_t* opt
        tcp_option_t* _opt 
        char *data
        char *s
        int data_len, ip_hdr_len, ether_type, ether_offset, data_offset,
        int opt_offset,pkt_counter=0,packet_length,flag,opt_counter=0
        int sack_size,sack_counter=0
        DEF MAX_SIZE  = 500000
        long KST_TZ_OFFSET = 9 * 60 * 60 * 1000 * 1000 * 1000
        
        np.ndarray packet_info = np.ndarray((MAX_SIZE,),
            dtype=[('packet_time','i8'),('source_ip','a16'), ('dest_port','i8'),
                   ('dest_ip','a16'),('source_port','i8'),('pkt_data','a1500'),
                   ('frame_len','i8'),('header_len','i8'),('seq','i8'),('ack','i8'),
                   ('sack1_le','i8'),('sack1_re','i8')])
        tcp_packed [:] packet_view = packet_info
    #set up hdfstore
    h5_filename = some_pcap.split('/')[-1]+'.h5'
    store = pd.HDFStore(h5_filename,'w') #delete old pcap if it already existed
    
    
    while 1:
        packet = pcap_next(handle,&header)
        if packet is NULL:
            break
        pkt_ptr = <unsigned char *> packet
        ether_type = (<int>(pkt_ptr[12]) << 8) | <int>(pkt_ptr[13])
        if ether_type == 0x0800: #ether type == 2048
            ether_offset = 14 #14 bytes
        pkt_ptr+=ether_offset
        ip_hdr = <ip *>pkt_ptr
        packet_length = ntohs(ip_hdr.ip_len) + ether_offset
        if ip_hdr.ip_p == 6: #TCP == 6 bro
            ip_hdr_len = ip_hdr.ip_hl*4 #is this always 20 bytes since we're v4?
            tcpHdr = (<tcphdr *> (<char *>ip_hdr + ip_hdr_len))
            
            #tcp options handling
            opt_offset = ip_hdr_len + ether_offset + sizeof(tcphdr)
            data_offset = ether_offset + ip_hdr_len + int(tcpHdr.th_off<<2)

            if opt_offset < data_offset:
                opt_counter = 0
                opt = <uint8_t*>(packet + opt_offset)
                while (opt_offset+opt_counter<data_offset) and opt[0] != 0:
                    _opt = <tcp_option_t*>opt
                    if <int>_opt.kind == 1:
                        opt+=1 #move pointer up 1 byte?
                        opt_counter+=1
                        continue
                    if <int>_opt.kind == 5:
                        sack_size = <int>_opt.size
                        sack_counter = 2
                        sacks = []
                        while sack_counter<sack_size:
                            sacks.append(ntohl(<uint32_t>opt[sack_counter]))
                            sack_counter+=4
                        if len(sacks)>=2:
                            packet_view[pkt_counter].sack1_le = sacks[0]
                            packet_view[pkt_counter].sack1_re = sacks[1]
                    opt += _opt.size
                    opt_counter+= <int>_opt.size

            
            data  = <char *>packet + data_offset
            data_len = (packet_length - data_offset)

            if data_len>1500:
                data_len = 1500
            data[data_len] = 0
            # *** General Packet Info *** 
            packet_view[pkt_counter].packet_time = header.ts.tv_sec * 1000000000 +header.ts.tv_usec*1000 + KST_TZ_OFFSET
            packet_view[pkt_counter].source_port = ntohs(tcpHdr.th_sport)
            packet_view[pkt_counter].dest_port = ntohs(tcpHdr.th_dport)
            packet_view[pkt_counter].frame_len = packet_length
            packet_view[pkt_counter].header_len = int(tcpHdr.th_off<<2) + ip_hdr_len
            packet_view[pkt_counter].seq = ntohl(tcpHdr.th_seq) 
            packet_view[pkt_counter].ack = ntohl(tcpHdr.th_ack) 
            #copy ip info in (clunky)
            s = inet_ntoa(ip_hdr.ip_src)
            memset(packet_view[pkt_counter].source_ip, '\0', 16)
            memcpy(packet_view[pkt_counter].source_ip,s,strlen(s))
            packet_view[pkt_counter].source_ip[strlen(s)] = 0
            s = inet_ntoa(ip_hdr.ip_dst)
            memset(packet_view[pkt_counter].dest_ip, '\0', 16)
            memcpy(packet_view[pkt_counter].dest_ip,s,strlen(s))
            packet_view[pkt_counter].dest_ip[strlen(s)] = 0
            #end of ip info
            # *** End of General Packet Info
            if packet_length>60:
                memcpy(packet_view[pkt_counter].pkt_data,data,data_len)
            else:
                memset(packet_view[pkt_counter].pkt_data, '\0', 1500)
            pkt_counter+=1
        if pkt_counter == MAX_SIZE:
            df = pd.DataFrame(packet_info)
            df.index = df.packet_time.values
            del df['packet_time']
            store.append('pcap_data',df)
            pkt_counter = 0
    df = pd.DataFrame(packet_info[:pkt_counter])
    df.index = df.packet_time.values
    del df['packet_time']
    store.append('pcap_data',df)
    print 'Number tcp packets saved: ',len(df)
    pcap_close(handle)
    store.close()