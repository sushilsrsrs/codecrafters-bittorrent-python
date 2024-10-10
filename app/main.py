import json
import sys
# import bencodepy - available if you need it!
# import requests - available if you need it!
def decode_part(value, start_index):
    if chr(value[start_index]).isdigit():
        return decode_string(value, start_index)
    elif chr(value[start_index]) == "i":
        return decode_integer(value, start_index)
    elif chr(value[start_index]) == "l":
        return decode_list(value, start_index)
    elif chr(value[start_index]) == "d":
        return decode_dict(value, start_index)
    else:
        raise NotImplementedError(
            "Only strings and integers are supported at the moment"
        )
def decode_string(bencoded_value, start_index):
    if not chr(bencoded_value[start_index]).isdigit():
        raise ValueError("Invalid encoded string", bencoded_value, start_index)
    bencoded_value = bencoded_value[start_index:]
    first_colon_index = bencoded_value.find(b":")
    if first_colon_index == -1:
        raise ValueError("Invalid encoded value")
    length = int(bencoded_value[:first_colon_index])
    word_start = first_colon_index + 1
    word_end = first_colon_index + length + 1
    return bencoded_value[word_start:word_end], start_index + word_end
def decode_integer(bencoded_value, start_index):
    if chr(bencoded_value[start_index]) != "i":
        raise ValueError("Invalid encoded integer", bencoded_value, start_index)
    bencoded_value = bencoded_value[start_index:]
    end_marker = bencoded_value.find(b"e")
    if end_marker == -1:
        raise ValueError("Invalid encoded integer", bencoded_value)
    return int(bencoded_value[1:end_marker]), start_index + end_marker + 1
def decode_list(bencoded_value, start_index):
    if chr(bencoded_value[start_index]) != "l":
        raise ValueError("Invalid encoded list", bencoded_value, start_index)
    current_index = start_index + 1
    values = []
    while chr(bencoded_value[current_index]) != "e":
        value, current_index = decode_part(bencoded_value, current_index)
        values.append(value)
    return values, current_index + 1
def decode_dict(bencoded_value, start_index):
    if chr(bencoded_value[start_index]) != "d":
        raise ValueError("Invalid encoded dict", bencoded_value, start_index)
    current_index = start_index + 1
    values = {}
    while chr(bencoded_value[current_index]) != "e":
        key, current_index = decode_string(bencoded_value, current_index)
        value, current_index = decode_part(bencoded_value, current_index)
        values[key.decode()] = value
    return values, current_index
# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"
def decode_bencode(bencoded_value):
    return decode_part(bencoded_value, 0)[0]
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
        file_name = sys.argv[2]
        with open(file_name, "rb") as torrent_file:
            bencoded_content = torrent_file.read()
        torrent = decode_bencode(bencoded_content)
        print("Tracker URL:", torrent["announce"].decode())
        print("Length:", torrent["info"]["length"])
    else:
        raise NotImplementedError(f"Unknown command {command}")
if __name__ == "__main__":
    main()











# import json
# import sys

# import bencodepy 
# # import requests - available if you need it!
# bc = bencodepy.Bencode(encoding="utf-8")
# # Examples:
# #
# # - decode_bencode(b"5:hello") -> b"hello"
# # - decode_bencode(b"10:hello12345") -> b"hello12345"
# def decode_bencode(bencoded_value):
#     # return bencodepy.decode(bencoded_value)
#     return bc.decode(bencoded_value)
#     if chr(bencoded_value[0]).isdigit():
#         first_colon_index = bencoded_value.find(b":")
#         if first_colon_index == -1:
#             raise ValueError("Invalid encoded value")
#         return bencoded_value[first_colon_index+1:]
#     elif chr(bencoded_value[0])=="i" and chr(bencoded_value[-1]=="e"):
#        return int(bencoded_value[1:-1]) 
#     else:
#         raise NotImplementedError("Only strings are supported at the moment")


# def main():
#     command = sys.argv[1]

#     # You can use print statements as follows for debugging, they'll be visible when running tests.
#     # print("Logs from your program will appear here!")

#     if command == "decode":
#         bencoded_value = sys.argv[2].encode()

#         # json.dumps() can't handle bytes, but bencoded "strings" need to be
#         # bytestrings since they might contain non utf-8 characters.
#         #
#         # Let's convert them to strings for printing to the console.
#         def bytes_to_str(data):
#             if isinstance(data, bytes):
#                 return data.decode()

#             raise TypeError(f"Type not serializable: {type(data)}")

#         # Uncomment this block to pass the first stage
#         print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))
#     elif command == "info":
#         file_name = sys.argv[2]
#         with open(file_name, "rb") as torrent_file:
#             bencoded_content = torrent_file.read()
#         torrent = decode_bencode(bencoded_content)
#         print("Tracker URL:", torrent["announce"].decode())
#         print("Length:", torrent["info"]["length"])
#     else:
#         raise NotImplementedError(f"Unknown command {command}")


# if __name__ == "__main__":
#     main()
