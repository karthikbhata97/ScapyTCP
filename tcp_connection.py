from scapy.all import *
from threading import Thread
from tcp_listener import TCP_IPv6_Listener, TCP_IPv4_Listener
from time import sleep


class TCP_IPv4:

    def __init__(self, src, dst, sport, dport, verbose=False):

        self.src = src
        self.dst = dst
        
        self.sport = sport
        self.dport = dport

        self.verbose = verbose

        self.seq_no = 0
        self.ack_no = 0

        self.tcp_flags = {
            'TCP_FIN': 0x01, 
            'TCP_SYN': 0x02, 
            'TCP_RST': 0x04, 
            'TCP_PSH': 0x08, 
            'TCP_ACK': 0x10, 
            'TCP_URG': 0x20, 
            'TCP_ECE': 0x40, 
            'TCP_CWR': 0x80
        }

        self.basic_pkt = IP(src=self.src, dst=self.dst)/\
                         TCP(sport=self.sport, dport=self.dport)

        self.listener = TCP_IPv4_Listener(self.src, self.dst, self.sport, self.dport, self.seq_no, self.ack_no, self.verbose)
        self.listener_thread = Thread(target=self.listener.listen)
        self.listener_thread.start()

    
    def send_pkt(self, pkt, flags):
        seqno = self.listener.next_seq

        pkt[TCP].flags = flags
        pkt[TCP].seq = self.listener.next_seq
        pkt[TCP].ack = self.listener.next_ack

        while self.listener.next_seq == seqno:
            sr1(pkt, timeout=1, verbose=self.verbose)
            sleep(0.5) # Not required, insted use timeout in sr1


    def handshake(self):
        self.listener.connection_open = True
        self.send_pkt(self.basic_pkt, 'S')

    def send_data(self, data_layer):
        pkt = self.listener.basic_pkt
        self.send_pkt(pkt/data_layer, 'PA')

    def close(self):
        self.listener.src_closed = True
        self.finish_pkt()
        self.listener_thread.join()

    def finish_pkt(self):
        pkt = self.listener.basic_pkt
        pkt[TCP].flags = 'FA'

        pkt[TCP].seq = self.listener.next_seq
        pkt[TCP].ack = self.listener.next_ack

        send(pkt, verbose=self.verbose)


class TCP_IPv6:

    def __init__(self, src, dst, sport, dport, verbose=False):

        self.src = src
        self.dst = dst
        
        self.sport = sport
        self.dport = dport

        self.verbose = verbose

        self.seq_no = 0
        self.ack_no = 0

        self.tcp_flags = {
            'TCP_FIN': 0x01, 
            'TCP_SYN': 0x02, 
            'TCP_RST': 0x04, 
            'TCP_PSH': 0x08, 
            'TCP_ACK': 0x10, 
            'TCP_URG': 0x20, 
            'TCP_ECE': 0x40, 
            'TCP_CWR': 0x80
        }

        self.basic_pkt = IPv6(src=self.src, dst=self.dst)/\
                         TCP(sport=self.sport, dport=self.dport)

        self.listener = TCP_IPv6_Listener(self.src, self.dst, self.sport, self.dport, self.seq_no, self.ack_no, self.verbose)
        self.listener_thread = Thread(target=self.listener.listen)
        self.listener_thread.start()

    
    def send_pkt(self, pkt, flags):
        seqno = self.listener.next_seq

        pkt[TCP].flags = flags
        pkt[TCP].seq = self.listener.next_seq
        pkt[TCP].ack = self.listener.next_ack

        while self.listener.next_seq == seqno:
            sr1(pkt, timeout=1, verbose=self.verbose)
            sleep(0.5) # Not required, insted use timeout in sr1


    def handshake(self):
        self.listener.connection_open = True
        self.send_pkt(self.basic_pkt, 'S')

    def send_data(self, data_layer):
        pkt = self.listener.basic_pkt
        self.send_pkt(pkt/data_layer, 'PA')

    def close(self):
        self.listener.src_closed = True
        self.finish_pkt()
        self.listener_thread.join()

    def finish_pkt(self):
        pkt = self.listener.basic_pkt
        pkt[TCP].flags = 'FA'

        pkt[TCP].seq = self.listener.next_seq
        pkt[TCP].ack = self.listener.next_ack

        send(pkt, verbose=self.verbose)

 