# Maram Ahmer
# Student Number: 250963151
import socket
import os
import signal
import sys
import argparse
from urllib.parse import urlparse
import selectors
import struct
import hashlib


# Define a constant for our buffer size
BUFFER_SIZE = 1024

# Define a maximum string size for the text being sent
MAX_STRING_SIZE = 256

# User name for tagging sent messages.
user = ''

# Signal handler for graceful exiting.  Let the server know when we're gone.
def signal_handler(sig, frame):
    print('Interrupt received, shutting down ...')
    message=f'DISCONNECT {user} CHAT/1.0\n'
    client_socket.send(message.encode())
    sys.exit(0)

# Creating checksum server
def checksum_server(ack, seg):
    values = (ack, seg)
    UDP_Data = struct.Struct('I I')
    packed_data = UDP_Data.pack(*values)
    checksum = bytes(hashlib.md5(packed_data).hexdigest(), encoding="UTF-8")
    return checksum

# Creating checksum of packet
def checksum_create(size, sequence, data):
    packet_tuple = (sequence, size, data)
    packet_structure = struct.Struct(f'I I {MAX_STRING_SIZE}s')
    packed_data = packet_structure.pack(*packet_tuple)
    checksum = bytes(hashlib.md5(packed_data).hexdigest(), encoding="UTF-8")
    return checksum

# Creating UDP packet
def UDP_packet(sequence_number, size, data, checksum):
    packet_tuple = (sequence_number, size, data, checksum)
    UDP_packet_structure = struct.Struct(f'I I {MAX_STRING_SIZE}s 32s')
    UDP_packet = UDP_packet_structure.pack(*packet_tuple)
    return UDP_packet

# Main method
def main():
    global user

    # Register our signal handler for shutting down.
    signal.signal(signal.SIGINT, signal_handler)

    # Get the url from the command line arguments
    parser = argparse.ArgumentParser()

    # Make the arguments from command line input
    parser.add_argument("user", help="username for chat user")
    parser.add_argument("server", help="url server in this form- chat://host:port")
    args = parser.parse_args()

    # Make sure that the url is valid and save it
    try:
        server_address = urlparse(args.server)
        # If any of the parts of the url are not compatible with the scheme, raise an error
        if(server_address.scheme != 'chat') or (server_address.hostname is None) or (server_address.port is None):
            raise ValueError
        # If there's no problem with the url, save the host and port from command line
        UDP_IP = server_address.hostname
        UDP_PORT = server_address.port
    except ValueError:
        # Print error message accordingly
        print('ERROR: Invalid server.\nEnter a url of form chat://host:port\n')
        sys.exit(1)

    # Save the username
    user = args.user

    # Binding the socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #client_socket.bind((UDP_IP, UDP_PORT))
    client_socket.settimeout(0.01)

    while True:
        print("> ", end = '', flush = True)

        # The packet will contain sequence number, data, data size and checksum
        sequence_number = 0
        data = sys.stdin.readline().encode()
        size = len(data)

        # We now compute our checksum by building up the packet and running our checksum function on it.
        # Our packet structure will contain our sequence number first, followed by the size of the data,
        # followed by the data itself.  We fix the size of the string being sent ... as we are sending
        # less data, it will be padded with NULL bytes, but we can handle that on the receiving end
        # just fine!
        checksum = checksum_create(size, sequence_number, data)

        # Now we can construct our actual packet.  We follow the same approach as above, but now include
        # the computed checksum in the packet.
        UDP_pack = UDP_packet(sequence_number, size, data, checksum)

        # Finally, we can send out our packet over UDP and hope for the best.
        client_socket.sendto(UDP_pack, (UDP_IP, UDP_PORT))

        try:
            # Get the data
            data, addr = client_socket.recvfrom(BUFFER_SIZE)
            unpacker3 = struct.Struct('I I 32s')
            unpacker4 = struct.Struct('I I 8s 32s')

            UDP_pack_server = unpacker3.unpack(data)
            print("Received from ", addr)
            print("Received message ", UDP_pack_server)

            # Checksum to compare for correctness
            checksum_comp = checksum_server(UDP_pack_server[0], UDP_pack_server[1])

            # Make the comparison, test SEQ and any data corruptions
            temp = unpacker4.unpack(UDP_pack)
            size = temp[1]

            if UDP_pack_server[2] == checksum_comp and UDP_pack_server[1] == size:
                # If all the comparisons go through well, packet is good to go
                print('Checksums match, packet is all good')

            elif UDP_pack_server[2] != checksum_comp or UDP_pack_server[1] != size:
                # Packet will be resent if either of the two comparisons fail, printing reason as well
                if UDP_pack_server[1] != size:
                    print('Resending... size incorrect')
                else:
                    print('Resending... packet is corrupted')

        except socket.timeout:
            print('Resending... packet has timed out')

if __name__ == '__main__':
    main()
