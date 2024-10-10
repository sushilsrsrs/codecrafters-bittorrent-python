import json
import sys
import hashlib
import requests
import struct
import bencodepy

# Updated decode_bencode to gracefully handle non-UTF-8 sequences
def decode_bencode(bencoded_value):
    if chr(bencoded_value[0]).isdigit():
        first_colon_index = bencoded_value.find(b":")
        if first_colon_index == -1:
            raise ValueError("Invalid encoded value")
        length = int(bencoded_value[:first_colon_index])
        return (
            bencoded_value[first_colon_index + 1 : first_colon_index + 1 + length],
            bencoded_value[first_colon_index + 1 + length :],
        )
    elif chr(bencoded_value[0]) == "i":
        end_index = bencoded_value.find(b"e")
        if end_index == -1:
            raise ValueError("Invalid encoded value")
        return int(bencoded_value[1:end_index]), bencoded_value[end_index + 1 :]
    elif chr(bencoded_value[0]) == "l":
        list_values = []
        remaining = bencoded_value[1:]
        while remaining[0] != ord("e"):
            decoded, remaining = decode_bencode(remaining)
            list_values.append(decoded)
        return list_values, remaining[1:]
    elif chr(bencoded_value[0]) == "d":
        dict_values = {}
        remaining = bencoded_value[1:]
        while remaining[0] != ord("e"):
            key, remaining = decode_bencode(remaining)
            if isinstance(key, bytes):
                try:
                    key = key.decode()
                except UnicodeDecodeError:
                    key = key.decode('latin-1')  # Fallback to avoid decoding errors
            value, remaining = decode_bencode(remaining)
            dict_values[key] = value
        return dict_values, remaining[1:]
    else:
        raise NotImplementedError(
            "Only strings, integers, lists, and dictionaries are supported at the moment"
        )

def bencode(data):
    if isinstance(data, str):
        return f"{len(data)}:{data}".encode()
    elif isinstance(data, bytes):
        return f"{len(data)}:".encode() + data
    elif isinstance(data, int):
        return f"i{data}e".encode()
    elif isinstance(data, list):
        return b"l" + b"".join(bencode(item) for item in data) + b"e"
    elif isinstance(data, dict):
        encoded_dict = b"".join(
            bencode(key) + bencode(value) for key, value in sorted(data.items())
        )
        return b"d" + encoded_dict + b"e"
    else:
        raise TypeError(f"Type not serializable: {type(data)}")

def main():
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        # Convert bytes to string for printing to the console.
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode(errors='ignore')  # Ignore errors for non-UTF-8 characters

        decoded_value, _ = decode_bencode(bencoded_value)
        print(json.dumps(decoded_value, default=bytes_to_str))

    elif command == "info":
        with open(sys.argv[2], "rb") as f:
            bencoded_value = f.read()

        torrent_info, _ = decode_bencode(bencoded_value)
        tracker_url = torrent_info.get("announce", b"").decode()
        file_length = torrent_info.get("info", {}).get("length", 0)
        piece_length = torrent_info.get("info", {}).get("piece length", 0)
        pieces = torrent_info.get("info", {}).get("pieces", b"")
        piece_hashes = [pieces[i : i + 20].hex() for i in range(0, len(pieces), 20)]

        print(f"Tracker URL: {tracker_url}")
        print(f"Length: {file_length}")
        info_dict = torrent_info.get("info", {})
        bencoded_info = bencode(info_dict)
        info_hash = hashlib.sha1(bencoded_info).hexdigest()

        print(f"Info Hash: {info_hash}")
        print(f"Piece Length: {piece_length}")
        print(f"Piece Hashes: {piece_hashes}")

    elif command == "peers":
        with open(sys.argv[2], "rb") as f:
            bencoded_value = f.read()

        torrent_info, _ = decode_bencode(bencoded_value)
        tracker_url = torrent_info.get("announce", b"").decode()

        info_dict = torrent_info.get("info", {})
        bencoded_info = bencode(info_dict)
        info_hash = hashlib.sha1(bencoded_info).digest()

        params = {
            "info_hash": info_hash,
            "peer_id": "00112233445566778899",
            "port": 6881,
            "uploaded": 0,
            "downloaded": 0,
            "left": torrent_info.get("info", {}).get("length", 0),
            "compact": 1,
        }

        response = requests.get(tracker_url, params=params)
        response_dict, _ = decode_bencode(response.content)

        peers = response_dict.get("peers", b"")
        for i in range(0, len(peers), 6):
            ip = ".".join(str(b) for b in peers[i : i + 4])
            port = struct.unpack("!H", peers[i + 4 : i + 6])[0]
            print(f"Peer: {ip}:{port}")

    else:
        raise NotImplementedError(f"Unknown command {command}")

if __name__ == "__main__":
    main()






















# import hashlib
# import json
# import sys
# import bencodepy
# import requests
# import struct

# bc = bencodepy.Bencode(encoding="utf-8")

# def decode_bencode(bencoded_value):
#     return bc.decode(bencoded_value)

# def main():
#     command = sys.argv[1]

#     if command == "decode":
#         bencoded_value = sys.argv[2].encode()

#         # Convert bytes to string for printing to the console.
#         def bytes_to_str(data):
#             if isinstance(data, bytes):
#                 return data.decode(errors='ignore')  # Ignore errors for non-UTF-8 characters
#             raise TypeError(f"Type not serializable: {type(data)}")

#         decoded_value = decode_bencode(bencoded_value)
#         print(json.dumps(decoded_value, default=bytes_to_str))

#     elif command == "info":
#         with open(sys.argv[2], "rb") as torrent_file:
#             info = torrent_file.read()
#         info_dict = bc.decode(info)

#         # Extracting the info hash
#         info_hash = hashlib.sha1(bencodepy.encode(info_dict[b"info"])).digest()

#         # Display relevant info
#         print(f'Tracker URL: {info_dict[b"announce"].decode()}')
#         print(f'Length: {info_dict[b"info"].get(b"length", "Unknown")}')
#         print(f"Info Hash: {info_hash.hex()}")
#         print(f"Piece Length: {info_dict[b'info'][b'piece length']}")
        
#         # Displaying the pieces
#         pieces = info_dict[b"info"][b"pieces"]
#         for i in range(0, len(pieces), 20):
#             print(pieces[i:i+20].hex())

#     elif command == "peers":
#         with open(sys.argv[2], "rb") as f:
#             bencoded_value = f.read()

#         torrent_info = bc.decode(bencoded_value)
#         tracker_url = torrent_info.get(b"announce", b"").decode()

#         # Extracting the info dictionary
#         info_dict = torrent_info[b"info"]
#         info_hash = hashlib.sha1(bencodepy.encode(info_dict)).digest()

#         # Tracker parameters
#         params = {
#             "info_hash": info_hash,
#             "peer_id": "0011223344556677889900112233445566778899",  # A dummy peer_id
#             "port": 6881,
#             "uploaded": 0,
#             "downloaded": 0,
#             "left": info_dict.get(b"length", 0),
#             "compact": 1,
#         }

#         # Send request to the tracker
#         response = requests.get(tracker_url, params=params)
#         response_dict = bc.decode(response.content)

#         # Get the peers
#         peers = response_dict.get(b"peers", b"")
#         for i in range(0, len(peers), 6):
#             ip = ".".join(str(b) for b in peers[i:i+4])
#             port = struct.unpack("!H", peers[i+4:i+6])[0]
#             print(f"Peer: {ip}:{port}")

#     else:
#         raise NotImplementedError(f"Unknown command {command}")

# if __name__ == "__main__":
#     main()
