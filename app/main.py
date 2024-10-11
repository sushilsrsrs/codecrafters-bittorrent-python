import json
import sys
from bencodepy import Bencode  # - available if you need it!
import hashlib
import textwrap
import requests  # - available if you need it!
import socket
import struct
# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"
def decode_bencode(bencoded_value):
    ctrl_char_begin = bencoded_value[0]

    # If it's a string (starts with a number)
    if chr(ctrl_char_begin).isdigit():
        # Extract the length of the string before the colon
        length, rest = bencoded_value.split(b":", 1)
        length = int(length)  # Convert length to an integer
        # Return the string portion with the exact length
        return rest[:length]
    
    elif chr(ctrl_char_begin) == "i":
        # For integer
        return int(bencoded_value[1:-1])
    
    elif chr(ctrl_char_begin) in ("l", "d"):
        # Use Bencode decoder for lists and dictionaries
        return Bencode(encoding="utf-8").decode(bencoded_value)
    
    else:
        raise NotImplementedError("This data type is unsupported for now")

def metafile(file):
    content_decoded = ""
    with open(file, "rb") as metafile:
        content = metafile.read()
        content_decoded = Bencode().decode(content)
    return content_decoded
def get_peers(torrent):
    # Step 1: Extract necessary information from the torrent file
    tracker_url = torrent[b"announce"].decode()
    info_hash = hashlib.sha1(Bencode().encode(torrent[b"info"])).digest()
    peer_id = "40440440440404404040"  # Just an example, this should be unique

    # Step 2: Query the tracker for peers
    response = requests.get(
        tracker_url,
        params={
            "info_hash": info_hash,
            "peer_id": peer_id,
            "port": 6881,
            "uploaded": 0,
            "downloaded": 0,
            "left": torrent[b"info"][b"length"],
            "compact": 1,
        },
    )

    if response.status_code != 200:
        raise Exception(f"Failed to get peers from tracker: {response.status_code}")

    # Step 3: Decode the response
    tracker_response = Bencode().decode(response.content)
    peers = tracker_response[b"peers"]

    peer_list = []
    while len(peers) >= 6:
        ip = f"{peers[0]}.{peers[1]}.{peers[2]}.{peers[3]}"
        port = int.from_bytes(peers[4:6], "big")
        peer_list.append((ip, port))
        peers = peers[6:]  # Move to the next peer

    return peer_list

def download_piece(file, piece_index, output_path):
    # Step 1: Get metadata from the torrent file
    torrent = metafile(file)

    # Step 2: Get a list of peers from the tracker
    peers = get_peers(torrent)
    
    if not peers:
        raise Exception("No peers available")

    # Step 3: Try to connect to one of the peers
    for peer_ip, peer_port in peers:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                client.settimeout(5)
                print(f"Attempting to connect to peer {peer_ip}:{peer_port}")
                client.connect((peer_ip, peer_port))

                # Perform handshake and download logic here...
                # Step 4: Wait for bitfield (message ID 5)
                bitfield = client.recv(1024)  # Receive and ignore the bitfield for now

                # Step 5: Send interested message (message ID 2)
                interested_msg = struct.pack("!Ib", 1, 2)
                client.send(interested_msg)

                # Step 6: Wait for unchoke message (message ID 1)
                unchoke_msg = client.recv(1024)
                if unchoke_msg[4] != 1:
                    raise Exception("Peer did not unchoke")

                # Continue with the rest of the piece downloading steps...
                
                break  # If connected and successful, break out of the loop
        except (ConnectionRefusedError,socket.timeout) as e:
            print(f"Failed to connect to peer {peer_ip}:{peer_port}, error: {e}")
            continue
    else:
        raise Exception("Could not connect to any peers.")

def main():
    command = sys.argv[1]
    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        # json.dumps() can't handle bytes, but bencoded "strings" need to be
        # bytestrings since they might contain non utf-8 characters.
        #
        # Let's convert them to strings for printing to the console.
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()
            raise TypeError(f"Type not serializable: {type(data)}")
        # Uncomment this block to pass the first stage
        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))
    elif command == "info":
        content_decoded = metafile(sys.argv[2])
        print("Tracker URL:", content_decoded[b"announce"].decode())
        print("Length:", content_decoded[b"info"][b"length"])
        print(
            "Info Hash:",
            hashlib.sha1(Bencode().encode(content_decoded[b"info"])).hexdigest(),
        )
        print("Piece Length:", content_decoded[b"info"][b"piece length"])
        print("Piece Hashes:")
        for ph in range(0, len(content_decoded[b"info"][b"pieces"]), 20):
            print(content_decoded[b"info"][b"pieces"][ph : ph + 20].hex())
    elif command == "peers":
        content_decoded = metafile(sys.argv[2])
        reply = requests.get(
            content_decoded[b"announce"].decode(),
            params={
                "info_hash": hashlib.sha1(
                    Bencode().encode(content_decoded[b"info"])
                ).digest(),
                "peer_id": "40440440440404404040",
                "port": 6881,
                "uploaded": 0,
                "downloaded": 0,
                "left": content_decoded[b"info"][b"length"],
                "compact": 1,
            },
        )
        decoded_reply = Bencode().decode(reply.content)
        peers_list = decoded_reply[b"peers"]
        while len(peers_list) > 0:
            ip_addr = (
                str(peers_list[0])
                + "."
                + str(peers_list[1])
                + "."
                + str(peers_list[2])
                + "."
                + str(peers_list[3])
            )
            port = int.from_bytes(peers_list[4:6], "big")
            print(ip_addr + ":" + str(port))
            peers_list = peers_list[6:]
    
    elif command == "handshake":
        content_decoded = metafile(sys.argv[2])
        info_hash = hashlib.sha1(Bencode().encode(content_decoded[b"info"])).digest()
        addr = sys.argv[3].split(":")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.connect((addr[0], int(addr[1])))

            # Reserved bytes - 8 bytes of zeros
            reserved_bytes = b'\x00\x00\x00\x00\x00\x00\x00\x00'

            # Peer ID (you can adjust this as necessary, but it should be 20 bytes)
            peer_id = b'-PC0001-' + b'123456789012'  # Example of a 20-byte peer ID

            # Send handshake message
            client.send(
                chr(19).encode()                          # Protocol string length
                + b"BitTorrent protocol"                  # Protocol identifier
                + reserved_bytes                          # Reserved bytes
                + info_hash                               # Info hash
                + peer_id                                 # Peer ID
            )

            # Receive and process the reply
            reply = client.recv(68)

        # Extract and print Peer ID from the reply (20 bytes starting from byte 48)
        peer_id_received = reply[48:68].hex()  # Convert Peer ID to hex string for correct output
        print("Peer ID:", peer_id_received)
    elif command == "download_piece":
        if sys.argv[2] == "-o":
            output_path = sys.argv[3]
            torrent_file = sys.argv[4]
            piece_index = int(sys.argv[5])
        else:
            print("Usage: download_piece -o <output_path> <torrent_file> <piece_index>")
            return
        
        download_piece(torrent_file, piece_index, output_path)
    else:
        raise NotImplementedError(f"Unknown command {command}")
if __name__ == "__main__":
    main()