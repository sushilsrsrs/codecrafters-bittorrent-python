import hashlib
import json
import sys
import bencodepy
import requests 
import struct 
# import requests - available if you need it!
bc = bencodepy.Bencode(encoding="utf-8")
# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"
def decode_bencode(bencoded_value):
    return bc.decode(bencoded_value)
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
        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))
    elif command == "info":
        with open(sys.argv[2], "rb") as torrent_file:
            info = torrent_file.read()
        info_dict = bencodepy.Bencode().decode(info)
        info_hash = hashlib.sha1(bencodepy.encode(info_dict[b"info"]))
        print(f'Tracker URL: {info_dict[b"announce"].decode()}')
        print(f'Length: {info_dict[b"info"][b"length"]}')
        print(f"Info Hash: {info_hash.hexdigest()}")
        print("Piece Length:",info_dict[b"info"][b"piece length"])
        for i in range(0, len(info_dict[b"info"][b"pieces"]),20):
            print(info_dict[b"info"][b"pieces"][i:i+20].hex())
    elif command=="peers":
        with open(sys.argv[2],"rb") as f:
            bencoded_value=f.read()
        torrent_info=bencodepy.Bencode().decode(bencoded_value)
        tracker_url=torrent_info.get("announce","").decode()
        info_dict=torrent_info.get("info",{})
        bencoded_info=bencodepy.Bencode().decode(info_dict)
        info_hash=hashlib.sha1(bencoded_info).digest()
        params ={
            "info_hash":info_hash,
            "peer_id":"00112233445566778899",
            "port":6881,
            "uploaded":0,
            "downloaded":0,
            "left":torrent_info("info",{}).get("length",0),
            "compact":1,
        }
        response=requests.get(tracker_url,params=params)
        response_dict=bencodepy.Bencode().decode(response.content)
        peers=response_dict.get("peers","b")
        for i in range(0,len(peers),6):
            ip =".".join(str(b) for b in peers[i:i+4])
            port=struct.unpack("!H",peers[i+4:i+6])[0]
            print(f"Peer: {ip}:{port}")

    else:
        raise NotImplementedError(f"Unknown command {command}")
if __name__ == "__main__":
    main()