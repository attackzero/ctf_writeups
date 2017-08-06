# Runs in Python 2.7 and requires pycrypto (pip install pycrypto)
# We have to use Python 2.7 because Python 3+ generates random numbers
# differently even with the same seed.  I tried to use a version 1 seed
# (see Python docs for random in Python 3), but it did not seem to matter
# The original encryption script was written in Python 2.7.

from Crypto.Cipher import AES
import base64
import os
import string
import random
import sys
import logging

def determine_file_iv(file_path):
    # The IV was seeded using the time when the file was encrpyted
    # If we use the same seed, we should get the same IV
    iv = ''
    
    # Find modified time of the encrypted file
    # The modified time of the file should be around the time it was
    # written.
    file_stats = os.stat(file_path)
    modified_time = int(file_stats.st_mtime)
    random.seed(modified_time)
    logger.debug('Seeded random generator with mtime from {}: {}'.format(file_path, modified_time))
    
    # The IV is 16 bytes
    for i in range(16):
        iv += random.choice(string.ascii_letters + string.digits)
    
    return iv

def get_encrypted_image_data(file_path):
    # Each image file was overwritten with a blurred version of the
    # image with the message on it plus a new line (hex 0A) plus 
    # the encrypted image that has been base64 encoded
    
    # First, we need to find the end of the blurred image
    # PNG files end with the tag IEND then 4 bytes for the CRC
    # of the IEND chunk (there is no data in the IEND chunk)
    with open(file_path, 'rb') as encrypted_file:
        encrypted_bytes = encrypted_file.read()
    
    iend_position = encrypted_bytes.find(b'IEND')
    logger.debug('Found IEND for {} at {}'.format(file_path, iend_position))
    
    # Grab the bytes at iend_position + 9 until the end of
    # the file
    # 9 bytes because IEND is 4 bytes, the CRC is another 4, then the newline
    # inserted by the encryption function - we want to start after that new line
    
    # Second, we need to Base64 Decode the bytes
    logger.debug('Slicing file at IEND + 9: {}'.format(iend_position + 9))
    decoded_size = len(encrypted_bytes) - (iend_position + 9)
    logger.debug('Will decode {:,} bytes of total {:,}.'.format(decoded_size, len(encrypted_bytes)))
    base64_decoded_file = base64.b64decode(encrypted_bytes[iend_position+9:])
    logger.debug('Found {:,} decoded bytes'.format(len(base64_decoded_file)))
    
    return base64_decoded_file

def decrypt_file(encrypted_file_path, key, decrypted_file_path):
    encrypted_data = get_encrypted_image_data(encrypted_file_path)

    file_iv = determine_file_iv(encrypted_file_path)
    logger.info('File IV for {}: {}'.format(encrypted_file_path, file_iv))
    aes_for_file = AES.new(key, AES.MODE_CFB, file_iv)
    
    decrypted_bytes = aes_for_file.decrypt(encrypted_data)
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_bytes)
    logger.info('Decrypted image written to: {}'.format(decrypted_file_path))
    
    return

if __name__ == '__main__':
    encrypted_images_dir = sys.argv[1]
    decrypted_images_dir = sys.argv[2]
    key = sys.argv[3]
    
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger_stream = logging.StreamHandler()
    logger_stream.setLevel(logging.DEBUG)
    log_format = logging.Formatter('%(asctime)s [%(levelname)s] - %(message)s')
    logger_stream.setFormatter(log_format)
    logger.addHandler(logger_stream)
    
    if not encrypted_images_dir.endswith('/'):
        encrypted_images_dir += '/'
    
    if not decrypted_images_dir.endswith('/'):
        decrypted_images_dir += '/'
    
    for image_path in os.listdir(encrypted_images_dir):
        full_encrypted_path = encrypted_images_dir + image_path
        output_file_path = '{}DECRYPTED_{}'.format(decrypted_images_dir, image_path)
        logger.info('Encrypted image {} will be decrypted to {}'
                    .format(encrypted_images_dir + image_path, output_file_path))
        decrypt_file(full_encrypted_path, key, output_file_path)
    
