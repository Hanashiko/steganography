import cv2
import numpy as np
import os

def to_bin(data):
    if isinstance(data, str):
        return ''.join([ format(ord(i), "08b") for i in data ])
    elif isinstance(data, bytes):
        return ''.join([ format(i, "08b") for i in data ])
    elif isinstance(data, np.ndarray):
        return [ format(i, "08b") for i in data ]
    elif isinstance(data, int) or isinstance(data, np.uint8):
        return format(data, "08b")
    else:
        raise TypeError("Type not supported.")
    
def encode(image_name, secret_data, n_bits=2):
    image = cv2.imread(image_name)
    n_bytes = image.shape[0] * image.shape[1] * 3 * n_bits // 8
    print("[*] Maximum bytes to encode:", n_bytes)
    print("[*] Data size:", len(secret_data))
    if len(secret_data) > n_bytes:
        raise ValueError(f"[!] Insufficient bytes ({len(secret_data)}), need bigger image or less data.")
    print("[*] Encoding data...")
    if isinstance(secret_data, str):
        secret_data += "====="
    elif isinstance(secret_data, bytes):
        secret_data += b"====="
    data_index = 0
    binary_secret_data = to_bin(secret_data)
    data_len = len(binary_secret_data)
    for bit in range(1, n_bits+1):
        for row in image:
            for pixel in row:
                r, g, b = to_bin(pixel)
                if data_index < data_len:
                    if bit == 1:
                        pixel[0] = int(r[:-bit] + binary_secret_data[data_index], 2)
                    elif bit > 1:
                        pixel[0] = int(r[:-bit] + binary_secret_data[data_index] + r[-bit+1:], 2)
                    data_index += 1
                if data_index < data_len:
                    if bit == 1:
                        pixel[1] = int(g[:-bit] + binary_secret_data[data_index], 2)
                    elif bit > 1:
                        pixel[1] = int(g[:-bit] + binary_secret_data[data_index] + g[-bit+1:], 2)
                    data_index += 1
                if data_index < data_len:
                    if bit == 1:
                        pixel[2] = int(b[:-bit] + binary_secret_data[data_index], 2)
                    elif bit > 1:
                        pixel[2] = int(b[:-bit] + binary_secret_data[data_index] + b[-bit+1:], 2)
                    data_index += 1
                if data_index >= data_len:
                    break
    return image

def decode(image_name, n_bits=1, in_bytes=False):
    print("[+] Decoding...")
    image = cv2.imread(image_name)
    binary_data = ""
    for bit in range(1, n_bits+1):
        for row in image:
            for pixel in row:
                r, g, b = to_bin(pixel)
                binary_data += r[-bit]
                binary_data += g[-bit]
                binary_data += b[-bit]
    all_bytes = [ binary_data[i: i+8] for i in range(0, len(binary_data), 8) ]
    if in_bytes:
        decoded_data = bytearray()
        for byte in all_bytes:
            decoded_data.append(int(byte, 2))
            if decoded_data[-5:] == b"=====":
                break
    else:
        decoded_data = ""
        for byte in all_bytes:
            decoded_data += chr(int(byte, 2))
            if decoded_data[-5:] == "=====":
                break
    return decoded_data[:-5]

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Steganography encoder/decoder, this Python scripts encode data within images.")
    parser.add_argument("-t", "--text", help="The text data to encode into the image, this only should be specified for encoding")
    parser.add_argument("-f", "--file", help="The file to hide into the image, this only should be specified while encoding")
    parser.add_argument("-e", "--encode", help="Encode the following image")
    parser.add_argument("-d", "--decode", help="Decode the following image")
    parser.add_argument("-b", "--n-bits", help="The number of least significant bits of the image to encode", type=int, default=2)
    args = parser.parse_args()
    if args.encode:
        if args.text:
            secret_data = args.text
        elif args.file:
            with open(args.file, "rb") as f:
                secret_data = f.read()
        input_image = args.encode
        path, file = os.path.split(input_image)
        filename, ext = file.split(".")
        output_image = os.path.join(path, f"{filename}_encoded.{ext}")
        encoded_image = encode(image_name=input_image, secret_data=secret_data, n_bits=args.n_bits)
        cv2.imwrite(output_image, encoded_image)
        print("[+] Saved encoded image.")
    if args.decode:
        input_image = args.decode
        if args.file:
            decoded_data = decode(input_image, n_bits=args.n_bits, in_bytes=True)
            with open(args.file, "wb") as f:
                f.write(decoded_data)
            print(f"[+] File decoded, {args.file} is saved successfully.")
        else:
            decoded_data = decode(input_image, n_bits=args.n_bits)
            print("[+] Decoded data:", decoded_data)