import hashlib
import json
import sys
import bencodepy
import requests
import struct

bc = bencodepy.Bencode(encoding="utf-8")

def decode_bencode(bencoded_value):
    return bc.decode(bencoded_value)

def main():
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        # Convert bytes to string for printing to the console.
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode(errors='ignore')  # Ignore errors for non-UTF-8 characters
            raise TypeError(f"Type not serializable: {type(data)}")

        decoded_value = decode_bencode(bencoded_value)
        print(json.dumps(decoded_value, default=bytes_to_str))

    elif command == "info":
        with open(sys.argv[2], "rb") as torrent_file:
            info = torrent_file.read()
        info_dict = bc.decode(info)

        # Extracting the info hash
        info_hash = hashlib.sha1(bencodepy.encode(info_dict[b"info"])).digest()

        # Display relevant info
        print(f'Tracker URL: {info_dict[b"announce"].decode()}')
        print(f'Length: {info_dict[b"info"].get(b"length", "Unknown")}')
        print(f"Info Hash: {info_hash.hex()}")
        print(f"Piece Length: {info_dict[b'info'][b'piece length']}")
        
        # Displaying the pieces
        pieces = info_dict[b"info"][b"pieces"]
        for i in range(0, len(pieces), 20):
            print(pieces[i:i+20].hex())

    elif command == "peers":
        with open(sys.argv[2], "rb") as f:
            bencoded_value = f.read()

        torrent_info = bc.decode(bencoded_value)
        tracker_url = torrent_info.get(b"announce", b"").decode()

        # Extracting the info dictionary
        info_dict = torrent_info[b"info"]
        info_hash = hashlib.sha1(bencodepy.encode(info_dict)).digest()

        # Tracker parameters
        params = {
            "info_hash": info_hash,
            "peer_id": "0011223344556677889900112233445566778899",  # A dummy peer_id
            "port": 6881,
            "uploaded": 0,
            "downloaded": 0,
            "left": info_dict.get(b"length", 0),
            "compact": 1,
        }

        # Send request to the tracker
        response = requests.get(tracker_url, params=params)
        response_dict = bc.decode(response.content)

        # Get the peers
        peers = response_dict.get(b"peers", b"")
        for i in range(0, len(peers), 6):
            ip = ".".join(str(b) for b in peers[i:i+4])
            port = struct.unpack("!H", peers[i+4:i+6])[0]
            print(f"Peer: {ip}:{port}")

    else:
        raise NotImplementedError(f"Unknown command {command}")

if __name__ == "__main__":
    main()
