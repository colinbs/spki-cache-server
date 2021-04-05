#!/usr/bin/python3

import socket
import enum
import argparse
import os
import sys
import copy
import random
from math import floor

log_level = 0

key_vault = []
asn = bytearray(b"\x00\x00\x00\x00")

SPKI_OFFSET = 170
SPKI_LEN = 91

SKI_OFFSET = 299
SKI_LEN = 20

SPKI_TO_SKI_OFFSET = 39

ASN_LEN = 4

serial_notify = b"\x01\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x00"

serial_query = b"\x01\x01\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x00"

reset_query = b"\x01\x02\x00\x00\x00\x00\x00\x08"

cache_response = b"\x01\x03\x00\x00\x00\x00\x00\x08"

end_of_data = b"\x01\x07\x00\x00\x00\x00\x00\x18\x00\x00\x00\x00\x00\x01\x51\x80\x00\x00\x1C\x20\x00\x02\xA3\x00"

cache_reset = b"\x01\x08\x00\x00\x00\x00\x00\x08"

router_key_header = b"\x01\x09\x01\x00\x00\x00\x00\x00"

dummy_spki = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

dummy_ski = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

class States(enum.Enum):
    RECV = 1
    SEND = 2
    DONE = 3

def mod_dummy_router_key():
    global dummy_router_key

    r_bytes = bytearray(dummy_router_key)
    r_len = len(r_bytes) - 1
    
    while True:
        if r_bytes[r_len] >= 255:
            r_len -= 1
            continue
        r_bytes[r_len] += 1
        dummy_router_key = bytes(r_bytes)
        break

def gen_dummy_keys(amount):
    global key_vault
    global router_key_header
    global dummy_spki
    global asn
    global dummy_ski
    global log_level

    header = bytearray(router_key_header)

    for i in range(0, amount):
        key = bytearray()

        gen_dummy_spki()
        gen_dummy_asn()
        gen_dummy_ski()

        header[7] = 8 + len(dummy_spki) + len(asn) + len(dummy_ski)

        key += header
        key += dummy_ski
        key += asn
        key += dummy_spki

        key_vault.append(key)

    if log_level: print(f"Generated {amount} router keys")

def gen_dummy_ski():
    global dummy_ski

    r_bytes = bytearray(dummy_ski)
    r_len = len(r_bytes) - 1
    
    while True:
        if r_bytes[r_len] >= 255:
            r_len -= 1
            continue
        r_bytes[r_len] += 1
        dummy_ski = bytes(r_bytes)
        break

def gen_dummy_spki():
    global dummy_spki

    r_bytes = bytearray(dummy_spki)
    r_len = len(r_bytes) - 1
    
    while True:
        if r_bytes[r_len] >= 255:
            r_len -= 1
            continue
        r_bytes[r_len] += 1
        dummy_spki = bytes(r_bytes)
        break

def gen_dummy_asn():
    global asn

    pos = ASN_LEN - 1
    for x in range(0, 4):
        asn[x] = random.randint(0, 255);
    
    # while True:
        # if asn[pos] >= 255:
            # pos -= 1
            # continue
        # asn[pos] += 1
        # break

def process_data(data, addr):
    r_bytes = bytearray(data)
    
    if r_bytes[1] == 0:
        print(f"Received Serial Notify from {addr}")
    elif r_bytes[1] == 1:
        print(f"Received Serial Query from {addr}")
    elif r_bytes[1] == 2:
        print(f"Received Reset Query from {addr}")
    elif r_bytes[1] == 3:
        print(f"Received Cache Response from {addr}")
    elif r_bytes[1] == 10:
        print(f"Received Error Report from {addr}")
        handle_error_pdu(r_bytes)
    else:
        print(f"Received Unknown PDU from {addr}: {data}")

def handle_error_pdu(data):
    err_len = data[19]
    print(data[20:err_len])

def send_data(conn, addr, data):
    global log_level

    if log_level:
        if data[1] == 0:
            print(f"Send Serial Notify to {addr}")
        elif data[1] == 1:
            print(f"Send Serial Query to {addr}")
        elif data[1] == 2:
            print(f"Send Reset Query to {addr}")
        elif data[1] == 3:
            print(f"Send Cache Response to {addr}")
        elif data[1] == 4:
            print(f"Send IPv4 Prefix to {addr}")
        elif data[1] == 6:
            print(f"Send IPv6 Prefix to {addr}")
        elif data[1] == 7:
            print(f"Send End Of Data to {addr}")
        elif data[1] == 8:
            print(f"Send Cache Reset to {addr}")

    conn.sendall(data)

def load_keys(path, ext):
    global key_vault
    global log_level
    rot = 0
    i = 0
    spin = ["-", "\\", "|", "/"]

    for filename in os.listdir(path):
        if ext in filename:
            with open(os.path.join(path, filename), 'rb') as f:
                read_key(f)
        if log_level: 
            rot = floor((i % 399) / 100)
            print(f"Loading keys...{spin[rot]}", end="\r")
            i += .01
    if log_level:
        print(f"Loading keys... done")
        print(f"Successfully loaded {len(key_vault)} Router Keys")

def read_key(f):
    global key_vault
    global asn

    header = bytearray(router_key_header)
    key = bytearray()

    f.read(SPKI_OFFSET)
    spki = bytearray(f.read(SPKI_LEN))

    gen_dummy_asn()

    f.read(SPKI_TO_SKI_OFFSET)
    ski = bytearray(f.read(SKI_LEN))

    header[7] = 8 + len(spki) + len(asn) + len(ski)

    key += header
    key += ski
    key += asn
    key += spki
    
    key_vault.append(key)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Router Key Cache Server")
    parser.add_argument("host", help="hostname or IP address to host from")
    parser.add_argument("port", type=int, help="port to host from")
    parser.add_argument("-e", "--ext", default=".cert", help="router key file extension")
    parser.add_argument("-v", "--verbose", action="store_true", help="print more verbose debug output")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-k", "--keypath", metavar="PATH", help="path to router keys")
    group.add_argument("-d", "--dummy", type=int, metavar="N", help="use N amount of invalid dummy router keys")
    args = parser.parse_args()

    if not args.keypath and not args.dummy:
        print("must provide one of the arguments:\n  -k, -d\n")
        print("use -h or --help for usage")
        sys.exit(1)

    if args.dummy and (args.dummy <= 0 or args.dummy > 999):
        print("argument for -d, --dummy must be a value between 1 and 1000")
        print("use -h or --help for usage")
        sys.exit(1)

    if args.verbose:
        log_level = 1

    HOST = args.host
    PORT = args.port

    if args.keypath:
        load_keys(args.keypath, args.ext)
    elif args.dummy:
        gen_dummy_keys(args.dummy)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    STATE = States.RECV
    with sock as s:
        s.bind((HOST, PORT))
        if log_level: print(f"Started cache on {HOST}:{PORT}")
        while True:
            s.listen(1)
            conn, addr = s.accept()
            with conn:
                if log_level: print(f"Connected by {addr[0]}:{addr[1]}")
                while STATE != States.DONE:
                    try:
                        if STATE == States.RECV:
                            data = conn.recv(1024)
                            if log_level: process_data(data, addr[0])
                            STATE = States.SEND
                        elif STATE == States.SEND:
                            send_data(conn, addr[0], cache_response)
                            if log_level: print(f"Send Router Keys to {addr[0]}...", end=" ")
                            for key in key_vault:
                                send_data(conn, addr[0], key)
                            if args.keypath:
                                if log_level: print(f"{len(key_vault)} Router Keys sent")
                            elif args.dummy:
                                if log_level: print(f"{args.dummy} Router Keys sent")

                            send_data(conn, addr[0], end_of_data)
                            STATE = States.DONE
                    except:
                        STATE = States.DONE
                        break
                conn.close()
                if log_level: print(f"Closed connection to {addr[0]}:{addr[1]}")
                STATE = States.RECV
