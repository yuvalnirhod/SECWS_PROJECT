#!/usr/bin/env python3

import socket
import threading

HOST_OUT = '10.1.1.3'  # Standard loopback interface address (localhost)
HOST = '10.1.2.3'
PORT = 800        # Port to listen on (non-privileged ports are > 1023)
CSV_TEXT = "Content-type: text/csv"
ZIP_TEXT = "Content-type: application/zip"

lock = threading.Lock()

def parse_ip_addr(ip):
    ip = ip.split(".")
    ip_num = 0

    for i in range(len(ip)):
        ip_num = ip_num + int(ip[i])*(256**(len(ip)-i-1))
    return ip_num


def get_ip_addr_without_mask(number):
    ip_add = ""
    for i in range(4):
        ip_add += str(number // (256**(4-i-1))) + "."
        number = number % (256**(4-i-1))
    ip_add = ip_add[0:len(ip_add)-1]
    return ip_add

def mitm(client_socket, addr):
    Flag = 0
    with client_socket:
        
        dst_ip = 0
        with open('/sys/class/fw/conns/conns', 'r') as connections:
            line = connections.readline()
            while (line):
                line = line.replace("\n", "")
                conn1 = line.split()
                if (get_ip_addr_without_mask(int(conn1[0])) == addr[0] and conn1[2] == str(addr[1]) and conn1[3] == "80"):
                    dst_ip = get_ip_addr_without_mask(int(conn1[1]))
                line = connections.readline()

            if dst_ip == 0:
                print("did not find a connection!")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((HOST_OUT,0))
            MITM_PORT = server_socket.getsockname()[1]
            with open('/sys/class/fw/mitm/mitm', 'w') as mitm_dev:
                sen = "{} {} {} {} {} {}".format(parse_ip_addr(addr[0]), addr[1], parse_ip_addr(str(dst_ip)), 80, parse_ip_addr(HOST_OUT), MITM_PORT)
                mitm_dev.write(sen)
            server_socket.settimeout(10)
            try:
                server_socket.connect((dst_ip, 80))
            except:
                server_socket.close()
                client_socket.close()
                return
            
            server_socket.setblocking(False)
            client_socket.setblocking(False)
            while True:
                try:
                    data_c = client_socket.recv(1024)
                except:
                    data_c = 1
                try:
                    data_s = server_socket.recv(1024)
                except:
                    data_s = 1

                if not data_c or not data_s:
                    server_socket.close()
                    client_socket.close()
                    return

                if not data_c == 1:
                    server_socket.sendall(data_c)
                if not data_s == 1:
                    data_s_str = data_s.decode('utf-8')
                    data_s_str = data_s_str.split("\r\n\r\n")[0]
                    lock.acquire()
                    cond = model.predict(data_s_str)[0]
                    lock.release()
                    if ((not cond) and (data_s_str.find(CSV_TEXT) == -1 and data_s_str.find(ZIP_TEXT) == -1)):
                        client_socket.sendall(data_s)
                    else:
                        
                        client_socket.close()
                        server_socket.setblocking(True)
                        while True:
                            data_s = server_socket.recv(1024)
                            if not data_s:
                                server_socket.close()
                                return

def main(p_model):
    model = p_model
    global model
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=mitm, args=(conn,addr))
            t.start()

