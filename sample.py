from tcp_connection import TCP_IPv4
import argparse
from scapy.all import Raw
from threading import Thread
import sys
import signal


def listen_connection(conn):

    while not (conn.listener.src_closed and conn.listener.dst_closed):
        if not conn.listener.data_share.empty():
            sys.stdout.write (conn.listener.data_share.get().decode('utf-8'))


if __name__ == '__main__':

    connection = None
    listener_th = None

    def signal_handler(sig, frame):
        print('Exiting..')
        connection.close()
        listener_th.join()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser()

    parser.add_argument('-s', '--source', help='Source IP:Port', nargs=1, required=True, type=str)
    parser.add_argument('-d', '--dest', help='Destination IP:Port', nargs=1, required=False, type=str)
    parser.add_argument('-l', '--listen', help='Accept connection', action='store_true')

    args = parser.parse_args()

    source_ip = args.source[0].split(':')[0]
    source_port = int(args.source[0].split(':')[1])

    if args.listen:
        connection = TCP_IPv4(source_ip, None, source_port, None)
        listener_th = Thread(target=listen_connection, args=(connection,))
        listener_th.start()

        print('Listening')
        while not connection.listener.dst_closed:
            data = sys.stdin.readline()
            if not data:
                break
            connection.send_data(Raw(load=data))

        connection.close() 
        listener_th.join()
        sys.exit(0)

    else:
        dest_ip = args.dest[0].split(':')[0]
        dest_port = int(args.dest[0].split(':')[1])

        connection = TCP_IPv4(source_ip, dest_ip, source_port, dest_port)
        connection.handshake()

        listener_th = Thread(target=listen_connection, args=(connection,))
        listener_th.start()

        data = ""

        while data:
            data = sys.stdin.readline()
            if not data:
                break

            connection.send_data(Raw(load=data))

        connection.close()
        listener_th.join()