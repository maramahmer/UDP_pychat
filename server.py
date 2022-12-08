# Maram Ahmer
# Student Number: 250963151
import socket
import os
import datetime
import signal
import sys
import selectors
from string import punctuation
import struct
import hashlib

# Define a constant for our buffer size
BUFFER_SIZE = 1024

# Define a maximum string size for the text being sent
MAX_STRING_SIZE = 256

# Follow list of users and topics the client is following

follow_list = []

# Signal handler for graceful exiting.  We let clients know in the process so they can disconnect too.
def signal_handler(sig, frame):
    print('Interrupt received, shutting down ...')
    message='DISCONNECT CHAT/1.0\n'
    for reg in client_list:
        reg[1].send(message.encode())
    sys.exit(0)

# Creating MD5 checksum packet
def ack_checksum(size, sequence):
    values = (size, sequence)
    packer = struct.Struct('I I')
    packed_data = packer.pack(*values)
    checksum = bytes(hashlib.md5(packed_data).hexdigest(), encoding = "UTF-8")
    return checksum

# Creating UDP packet
def UDP_packet_maker(size, sequence, checksum):
    values = (size, sequence, checksum)
    UDP_data = struct.Struct('I I 32s')
    UDP_packet = UDP_data.pack(*values)
    return UDP_packet

# Returning client following list
def client_following():
    list = ''
    for followed_topic in follow_list:
        list += (' ' + followed_topic) #Add topic to list
        return list
    return None

# To add to the client following list
def add_client_follow(follow_topic):
    for topic in follow_list:
        if topic == follow_topic:
            return False # Already following
    follow_list.append(follow_topic) # Add new topic
    return True

# To remove from client following list
def client_unfollow(unfollow_topic):
    for topic in follow_list:
        if topic == unfollow_topic:
            follow_list.remove(topic)
            return True # Successfully removed
    return False

# Reading a line from the socket and stripping it, then returning the line
def get_line_from_socket(sock):
    done = False
    line = ''

    while not done:
        char = sock.recv(1).decode()
        if char == '\r':
            pass
        elif char == '\n':
            done = True
        else:
            line = line + char
    return line

# Reading a message from the client
def client_message(sock, received_text):
    #Empty message
    if received_text == '':
        print('Closed connection')

    # Receive message
    else:
        print(f'Message: {received_text}')
        text = received_text.replace('\n', ' ').split(' ')

        # If the client requests to disconnect, print message and close connection
        if text[0] == 'DISCONNECT':
            print('Disconnecting chat...')
            sock.close

        # If the client requests a specific single command, send along accordingly
        elif (text[0] == '!exit') or (text[0] == '!list') or (text[0] == '!follow?'):
            if text[0] == '!exit':
                print('Disconnecting...')
                sock.close
            elif text[0] == '!list':
                reply_message = 'One client connected'
                sock.sendto(reply_message.encode, sock)
            elif text[0] == '!follow?':
                reply_message = client_following() + '\n'
                sock.sendto(reply_message.encode(), sock)

            # If the client requests following or unfollowing, do as requested
        elif (len(text) == 3) and ((text[1] == '!follow') or (text[1] == '!unfollow')):
            if text[1] == '!follow':
                following_topic = text[2]
                if add_client_follow(following_topic):
                    reply_message = f'Started following {following_topic}\n'
                else:
                    reply_message = f'Already following {following_topic}\n'

            sock.sendto(reply_message.encode(), sock)

        elif text[1] == '!unfollow':
            unfollow_topic = text[2]
            if client_unfollow(unfollow_topic):
                reply_message = f'Successfully unfollowed {unfollow_topic}\n'
            else:
                reply_message = f'{unfollow_topic} not in following list\n'

            sock.sendto(reply_message.encode(), sock)

        # If the user attempts to send a file, forward as needed
        elif (len(text) >= 3) and (text[1] == '!attach'):
            sock.setblocking(True)

            filename = text[2]
            # Strip message
            text.remove(filename)
            text.remove('!attach')

            reply_message = f'Attach {filename} CHAT/1.0\n'
            sock.sendto(reply_message.encode(), sock)

            # Extract header
            header = get_line_from_socket(sock)
            header_content = header.split(' ')

            # Check header validity, throw error if invalid
            if (header_content[1] == -1):
                reply_message = f'ERROR: requested file {filename} could not be sent\n'
            elif (len(header_content != 2)) or (header_content[0] != 'Content-Length: '):
                reply_message = f'ERROR: attachment header incorrect\n'
            else:
                reply_message = f'File {filename} attached successfully\n'
            sock.sendto(reply_message.encode(), sock)


def main():
    # Register our signal handler for shutting down.
    signal.signal(signal.SIGINT, signal_handler)

    # Create the UDP socket and bind to address
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.bind(('', 0))

    print('Waiting for client connections at port ' + str(server_sock.getsockname()[1]))
    print('Waiting for incoming client connections...')

    # Wait for packets from clients
    while True:
        # Unpack data
        received_packet, addr = server_sock.recvfrom(BUFFER_SIZE)
        unpacker = struct.Struct(f'I I {MAX_STRING_SIZE}s 32s')
        UDP_packet = unpacker.unpack(received_packet)

        # Extract data
        received_sequence = UDP_packet[0]
        received_size = UDP_packet[1]
        received_data = UDP_packet[2]
        received_checksum = UDP_packet[3]

        # Print out what we received.
        print("Packet received from:", addr)
        print("Packet data:", UDP_packet)

        # We now compute the checksum on what was received to compare with the checksum
        # that arrived with the data.  So, we repack our received packet parts into a tuple
        # and compute a checksum against that, just like we did on the sending side.
        values = (received_sequence, received_size, received_data)
        packer = struct.Struct(f'I I {MAX_STRING_SIZE}s')
        packed_data = packer.pack(*values)
        computed_checksum = bytes(hashlib.md5(packed_data).hexdigest(), encoding="UTF-8")

        # We can now compare the computed and received checksums to see if any corruption of
        # data can be detected.  Note that we only need to decode the data according to the
        # size we intended to send; the padding can be ignored.
        if received_checksum == computed_checksum:
            print('Received and computed checksums match, so packet can be processed')
            received_text = received_data[:received_size].decode()
            print(f'Message text was:  {received_text}')
            client_message(addr, received_text)

            # Acknowledgement checksum
            ack_checksum(1, received_size)

            # Acknowledgement packet
            UDP_pack = UDP_packet_maker(1, received_size, computed_checksum)
            print('Sending Message: ', 1, received_size, '\n')
            server_sock.sendto(UDP_pack, addr)
            print('Message Sent\n')

        else:
            # Here the packet is corrupted, print an error
            print('Received and computed checksums do not match, so packet is corrupt and discarded')

            # Send checksum error
            if received_size == 0:
                reply_checksum = ack_checksum(1, 1)

            else:
                reply_checksum = ack_checksum(1, 0)

            # Error packet, reverse seq
            if received_size == 0:
                values = (1, 1, reply_checksum)

            else:
                values = (1, 0, reply_checksum)

            UDP_pack = UDP_packet_maker(values[0], values[1], values[2])

            # Sending Error
            print('Sending Message: ', values, '\n')
            server_sock.sendto(UDP_pack, addr)
            print('Error Message Sent\n')


if __name__ == '__main__':
    main()

