# PixelCrypt: 

#### Hide your files invisibly within images using advanced steganography. With optional AES encryption, PixelCrypt secures your data, making it both undetectable and protected. Seamlessly conceal sensitive information inside PNG images with just a few commands—perfect for safeguarding your privacy.

# hide.py

A program, encode and hide files within images.

# Installing Dependencies

To install the required Python libraries, run the following command in the folder containing the requirements.txt file:

` pip install -r requirements.txt `

# Usage

To run the program, use the following command:

` hide.py [-h] -i IMAGE [-f FILE] -a ACTION [-p PASSWORD] `

## Arguments:

" -i, --image: " Required. Specifies the image file for encoding or decoding. Only PNG files with an alpha channel are supported.

" -f, --file: " Required for encoding. Specifies the file to hide in the image.

" -a, --action: " Required. Action to perform, either encode or decode.

" -p, --password: " Optional. Password to activate AES encryption for encoding/decoding. If not provided, no encryption will be used.


# Example Usage:

## Encoding a file into an image:

` python hide.py -i image.png -f secret.txt -a encode -p mypassword `

## Decoding a file from an image:

` python hide.py -i image.png -a decode -p mypassword `

---

# How It Works

The program uses steganography to hide any file inside a PNG image by altering the pixel values in an imperceptible way. Each byte of the file is split into 2-bit sequences, which are embedded into the RGBA channels of the image pixels. Since each pixel channel (Red, Green, Blue, Alpha) uses 8 bits (ranging from 0-255), only the two least significant bits of each channel are modified, ensuring minimal visible impact.

## Header:

The program adds a small header to the image, storing the file's metadata:

## Magic number: 

To validate the presence of encoded data.

## File size: 

The size of the hidden file.

## File format: 

The extension of the hidden file (e.g., txt, zip).


## Encryption:

If a password is provided, the file is encrypted with AES symmetric encryption before being encoded into the image. The password is hashed into a secure key using PBKDF2, and a random nonce is added to ensure encryption security. Random noise is also added to the end of the data to obscure the file size.

## Compression:

For best results, it is recommended to compress or bundle multiple files (e.g., in a .zip archive) before hiding them to minimize size and maximize efficiency.

## Limitations:

Only PNG images with an alpha (transparency) channel are supported.

The image must be large enough to store the file data (approximately 1 byte per pixel).

Decoding any random image may result in meaningless output if no hidden data is present.


## Output:

### Encode: 

The program saves the encoded image as output.png.

### Decode:

The program saves the hidden file as output.xxx (with the appropriate file extension).
