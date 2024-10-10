import hashlib
import json
import sys
import bencodepy
import requests
import struct

# Bencode decoder setup
bc = bencodepy.Bencode(encoding="utf-8")

def decode_bencode(bencoded_value):
    """Decodes a Bencoded value, handling non-UTF-8 data gracefully."""
    try:
        return bc.decode(bencoded_value)
    except UnicodeDecodeError:
        # Return raw binary data if it cannot be decoded as UTF-8
        return bencoded_value

def main():
    command = sys.argv[1]
    
    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode(errors="replace")  # Replace invalid UTF-8 characters
            raise TypeError(f"Type not serializable: {type(data)}")
        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))
    
    elif command == "info":
        with open(sys.argv[2], "rb") as torrent_file:
            info = torrent_file.read()
        
        info_dict = decode_bencode(info)
        # Calculate info hash
        info_hash = hashlib.sha1(bencodepy.encode(info_dict[b"info"])).hexdigest()
        
        # Print required details
        print(f'Tracker URL: {info_dict[b"announce"].decode()}')
        print(f'Length: {info_dict[b"info"][b"length"]}')
        print(f"Info Hash: {info_hash}")
        print("Piece Length:", info_dict[b"info"][b"piece length"])
        
        # Print the pieces in 20-byte segments
        for i in range(0, len(info_dict[b"info"][b"pieces"]), 20):
            print(info_dict[b"info"][b"pieces"][i:i+20].hex())
    
    elif command == "peers":
        with open(sys.argv[2], "rb") as f:
            bencoded_value = f.read()
        
        # Decode the torrent info and extract relevant details
        torrent_info = decode_bencode(bencoded_value)
        tracker_url = torrent_info.get(b"announce", b"").decode()
        info_dict = torrent_info.get(b"info", {})
        bencoded_info = bencodepy.encode(info_dict)
        
        # Calculate the info hash for the tracker request
        info_hash = hashlib.sha1(bencoded_info).digest()
        
        # Tracker request parameters
        params = {
            "info_hash": info_hash,
            "peer_id": "00112233445566778899",  # Static peer ID for testing
            "port": 6881,
            "uploaded": 0,
            "downloaded": 0,
            "left": info_dict.get(b"length", 0),  # Fallback to 0 if length is missing
            "compact": 1
        }
        
        # Send GET request to tracker
        response = requests.get(tracker_url, params=params)
        response_dict = decode_bencode(response.content)
        
        # Decode peers list from compact format (binary)
        peers = response_dict.get(b"peers", b"")
        if isinstance(peers, bytes):
            for i in range(0, len(peers), 6):
                ip = ".".join(str(b) for b in peers[i:i+4])
                port = struct.unpack("!H", peers[i+4:i+6])[0]
                print(f"Peer: {ip}:{port}")
        else:
            print("No valid peers data found.")
    
    else:
        raise NotImplementedError(f"Unknown command {command}")

if __name__ == "__main__":
    main()
