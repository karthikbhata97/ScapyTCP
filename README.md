# TCP/IP Stack using Scapy
This is a utility to create TCP/IP connections. With this it is possible to write custom application layer protocols and test them. This utility has support for both IPv4 and IPv6.

It contains TCP_IPv4 (TCP_IPv6) class which can be used to connect to remote host. It supports IP spoofing as well. This can also be used to listen to the incoming TCP connections. It is capable of eshtablishing a full fledged connection.

### Requirements
* Scapy in Python3
* Update iptables to prevent kernel from sending RST for unknown ports being used by scapy.
    ```
    bash update_iptables.sh
    ```
* superuser privilages.

## Implementation and Usage:
It has TCP_IPv4 (and TCP_IPv6) class which will make use of TCP_IPv4_Listener (and TCP_IPv6_Listener). It either creates a connection with remote host using ```handshake``` method or will listen for a ```TCP_SYN```. After this, it completes the handshake and is capable of sending data to-fro as TCP/IP.

This class can be used to test custom protocols over TCP/IP too.

There is a ```sample.py``` which implements ```netcat``` like program using this utility.

```
usage: sample.py [-h] -s SOURCE [-d DEST] [-l]

optional arguments:
  -h, --help            show this help message and exit
  -s SOURCE, --source SOURCE
                        Source IP:Port
  -d DEST, --dest DEST  Destination IP:Port
  -l, --listen          Accept connection
```

