import scapy.packet
from scapy.all import *
from scapy.layers.inet6 import IPv6




def readPCAPFile():
    scapy_cap = rdpcap('pkap/trace-24.pcap')
    print(scapy_cap)
    i = 1
    for p in scapy_cap:
        packet_raw = raw(p)
        packet_hex = packet_raw.hex()
        packet_length = len(packet_hex)/2
        index = 0
        destination_adress_hex = ""
        source_adress_hex = ""
        packet_type_eth = ""
        packet_type_hex = ""
        medio_length = 0

        if(packet_length < 60):
            medio_length = 64
        else:
            medio_length = packet_length + 4


        for x in packet_hex:
            if (index >= 0 and index <= 11):
                destination_adress_hex += packet_hex[index]

            if (index >= 12 and index <= 23):
                source_adress_hex += packet_hex[index]

            if(index >=24 and index <= 27):
                packet_type_eth += packet_hex[index]

            if(index >= 28 and index <= 29):
                packet_type_hex += packet_hex[index]


            index += 1

        #destination adress conversion
        destination_adress = ':'.join(a + b for a, b in zip(destination_adress_hex[::2], destination_adress_hex[1::2]))
        source_adress = ':'.join(a + b for a, b in zip(source_adress_hex[::2], source_adress_hex[1::2]))


        #packet type + ošetriť aby sa po vykonaní ethernetu skiplo packet type hex
        packet_type = ""
        if(packet_type_eth > "05DC"):
            packet_type = "Ethernet II"

        if(packet_type_hex == "ff" or packet_type_hex == "FF"):
            packet_type = "IEEE 802.3 - Raw"
        elif(packet_type_hex == "aa" or packet_type_hex == "AA"):
            packet_type = "IEEE 802.3 s LLC a SNAP"
        else:
            packet_type = "IEEE 802.3 s LLC"





        print(packet_hex)
        print("LENGTH: " + str(packet_length))
        print("MEDIO LENGTH: " + str(medio_length))
        print("DEST ADRESS: " + str(destination_adress))
        print("SOURCE ADRESS: " + str(source_adress))
        print("PACKET TYPE: " + str(packet_type_hex))
        print("PACKET: " + packet_type)
        # x > 05DC  Ethernet II od 24 po 28
        # x > aa or x > AA == IEEE 802.3 s LCC a SNAP od 28 po 30
        # x > ff or x > FF == IEEE 802.3 - Raw
        # else IEEE 802.3 s LCC


if __name__ == '__main__':
    readPCAPFile()
