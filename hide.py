import argparse
import base64
import os
import struct

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image

class Header:
    MAX_FORMAT_LENGTH = 8
    MAGIC_NUM = b"hide"  # Updated to byte literal for consistency
    def __init__(self, size=0, fformat="txt"):
        self.size = size
        self.fformat = fformat

def encode_in_pixel(byte, pixel):
    """Encodes a byte in the two least significant bits of each channel."""
    r = byte & 0b11
    g = (byte >> 2) & 0b11
    b = (byte >> 4) & 0b11
    a = (byte >> 6) & 0b11

    return (
        (pixel[0] & 0b11111100) | r,
        (pixel[1] & 0b11111100) | g,
        (pixel[2] & 0b11111100) | b,
        (pixel[3] & 0b11111100) | a
    )

def decode_from_pixel(pixel):
    """Retrieves an encoded byte from the pixel."""
    r = pixel[0] & 0b11
    g = pixel[1] & 0b11
    b = pixel[2] & 0b11
    a = pixel[3] & 0b11
    return struct.pack("B", r | (g << 2) | (b << 4) | (a << 6))

def encrypt_data(data, password, padding=0):
    """Encrypts data using the provided password."""
    if padding < 0:
        raise ValueError("Image too small to encode the file. Add more padding.")

    password = password.encode()  # Ensure password is bytes
    salt = password

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)

    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()

    encrypted_data += os.urandom(padding - 16)
    return nonce + encrypted_data

def decrypt_data(data, password):
    """Decrypts data using the provided password."""
    password = password.encode()
    salt = password

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)

    nonce = data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data[16:]) + decryptor.finalize()

def encode(image_path, data, filename, encrypt=False, password=""):
    image = Image.open(image_path)
    px = image.load()

    header = Header(size=len(data), fformat=os.path.splitext(filename)[1][1:])
    header_data = struct.pack(
        "4sI{}s".format(Header.MAX_FORMAT_LENGTH),
        header.MAGIC_NUM, header.size, header.fformat.encode().ljust(Header.MAX_FORMAT_LENGTH, b"\x00")
    )

    file_bytes = header_data + data

    if encrypt:
        if password:
            file_bytes = encrypt_data(file_bytes, password, padding=image.width * image.height - len(file_bytes))
        else:
            print("Password is empty, encryption skipped")

    if len(file_bytes) > image.width * image.height:
        raise ValueError("Image too small to encode the file.")

    for i in range(len(file_bytes)):
        x, y = i % image.width, i // image.width
        byte = file_bytes[i]
        px[x, y] = encode_in_pixel(byte, px[x, y])

    image.save("output.png", "PNG")
    print("Data encoded into output.png")

def decode(image_path, password=""):
    image = Image.open(image_path)
    px = image.load()

    data = bytearray()
    for y in range(image.height):
        for x in range(image.width):
            data += decode_from_pixel(px[x, y])

    if password:
        data = decrypt_data(data, password)

    header = Header()
    header_size = struct.calcsize("4sI{}s".format(Header.MAX_FORMAT_LENGTH))
    header_data = struct.unpack("4sI{}s".format(Header.MAX_FORMAT_LENGTH), data[:header_size])

    header.MAGIC_NUM, header.size, header.fformat = header_data
    header.fformat = header.fformat.decode().strip("\x00")

    if header.MAGIC_NUM != b"hide":
        raise ValueError("No valid data to recover.")

    extracted_data = data[header_size:header_size + header.size]
    output_filename = "output.{}".format(header.fformat)
    
    with open(output_filename, 'wb') as output_file:
        output_file.write(extracted_data)

    print(f"Decoded data saved to {output_filename}")

def main():
    parser = argparse.ArgumentParser(description="Encode or decode data in an image.")
    parser.add_argument("-i", "--image", required=True, help="Image file to encode or decode.")
    parser.add_argument("-f", "--file", help="File to encode into the image.")
    parser.add_argument("-a", "--action", choices=["encode", "decode"], required=True, help="Action to perform.")
    parser.add_argument("-p", "--password", help="Password for encryption/decryption.")
    args = parser.parse_args()

    if args.action == "encode":
        if not args.file:
            raise ValueError("You need to specify a file to encode.")
        with open(args.file, 'rb') as file_data:
            data = file_data.read()
            encode(args.image, data, args.file, encrypt=bool(args.password), password=args.password or "")
    elif args.action == "decode":
        decode(args.image, password=args.password or "")
    else:
        raise ValueError("Invalid action. Use 'encode' or 'decode'.")

if __name__ == '__main__':
    main()
