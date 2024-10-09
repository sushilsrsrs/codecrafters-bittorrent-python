import json
import sys

# import bencodepy - available if you need it!
# import requests - available if you need it!

# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"
def decode_bencode(bencoded_value):
    if isinstance(bencoded_value, bytes):
        bencoded_value = bencoded_value.decode('utf-8')
    
    if bencoded_value[0].isdigit():
        # String case: find the colon to determine string length
        first_colon_index = bencoded_value.find(":")
        if first_colon_index == -1:
            raise ValueError("Invalid encoded value")
        length = int(bencoded_value[:first_colon_index])  # Length of the string
        start_index = first_colon_index + 1
        end_index = start_index + length
        return bencoded_value[start_index:end_index], bencoded_value[end_index:]
    
    elif bencoded_value[0] == "i" and bencoded_value[-1] == "e":
        # Integer case
        return int(bencoded_value[1:-1]), ""
    
    elif bencoded_value[0] == "l":
        # List case
        result = []
        bencoded_value = bencoded_value[1:]  # Skip the initial 'l'
        while bencoded_value[0] != "e":
            decoded_element, bencoded_value = decode_bencode(bencoded_value)
            result.append(decoded_element)
        return result, bencoded_value[1:]  # Skip the closing 'e'
    
    else:
        raise NotImplementedError("Unsupported bencoded type")

def main():
    command = sys.argv[1]

    # You can use print statements as follows for debugging, they'll be visible when running tests.
    # print("Logs from your program will appear here!")

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
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
