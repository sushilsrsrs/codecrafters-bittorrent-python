import json
import sys
from bencodepy import Bencode  # - available if you need it!
import hashlib
import textwrap
import requests  # - available if you need it!
import socket
# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"
def decode_bencode(bencoded_value):
    ctrl_char_begin = bencoded_value[0]
    ctrl_char_end = bencoded_value[:-1]
    if chr(ctrl_char_begin).isdigit():
        length = int(bencoded_value.split(b":")[0])
        return bencoded_value.split(b":")[1][:length]
    elif chr(ctrl_char_begin) == "i":
        return int(bencoded_value[1:-1])
    elif chr(ctrl_char_begin) in ("l", "d"):
        # Lazy solution
        return Bencode(encoding="utf-8").decode(bencoded_value)
    else:
        raise NotImplementedError("This data type is unsupported for now")
def metafile(file):
    content_decoded = ""
    with open(file, "rb") as metafile:
        content = metafile.read()
        content_decoded = Bencode().decode(content)
    return content_decoded
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
            client.send(
                chr(19).encode()
                + b"BitTorrent protocol00000000"
                + info_hash
                + "40440440440404404040".encode()
            )
            reply = client.recv(70)
        print("Peer ID:", reply[48:].hex())
    else:
        raise NotImplementedError(f"Unknown command {command}")
if __name__ == "__main__":
    main()