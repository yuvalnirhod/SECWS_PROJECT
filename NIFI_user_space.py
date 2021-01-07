#!/usr/bin/env python3

import socket
import threading

HOST_OUT = '10.1.1.3'  # Standard loopback interface address (localhost)
HOST = '10.1.2.3'
PORT = 808        # Port to listen on (non-privileged ports are > 1023)
START = '"type":'
MIDDLE = ["org.apache.nifi.processors.standard.DeleteHDFS",
"org.apache.nifi.processors.standard.ExecureGroovyScript",
"org.apache.nifi.processors.standard.ExecuteProcess",
"org.apache.nifi.processors.standard.ExecuteScript",
"org.apache.nifi.processors.standard.ExecuteStreamCommand",
"org.apache.nifi.processors.standard.FetchFile",
"org.apache.nifi.processors.standard.FetchHDFS",
"org.apache.nifi.processors.standard.FetchParquet",
"org.apache.nifi.processors.standard.GetFile",
"org.apache.nifi.processors.standard.GetHDFS",
"org.apache.nifi.processors.standard.FetHDFSSequenceFile",
"org.apache.nifi.processors.standard.InvokeScriptedProcessor",
"org.apache.nifi.processors.standard.MoveHDFS",
"org.apache.nifi.processors.standard.PutFile",
"org.apache.nifi.processors.standard.PutHDFS",
"org.apache.nifi.processors.standard.PutParquet",
"org.apache.nifi.processors.standard.ScriptedTransformRecord",
"org.apache.nifi.processors.standard.TailFile"]


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
        print('Connected by', addr)
        print(client_socket)
        
        dst_ip = 0
        with open('/sys/class/fw/conns/conns', 'r') as connections:
            line = connections.readline()
            while (line):
                print(line)
                line = line.replace("\n", "")
                conn1 = line.split()
                if (get_ip_addr_without_mask(int(conn1[0])) == addr[0] and conn1[2] == str(addr[1]) and conn1[3] == "8080"):
                    dst_ip = get_ip_addr_without_mask(int(conn1[1]))
                line = connections.readline()

            if dst_ip == 0:
                print("did not find a connection!")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((HOST_OUT,0))
            MITM_PORT = server_socket.getsockname()[1]
            with open('/sys/class/fw/mitm/mitm', 'w') as mitm_dev:
                sen = "{} {} {} {} {} {}".format(parse_ip_addr(addr[0]), addr[1], parse_ip_addr(str(dst_ip)), 8080, parse_ip_addr(HOST_OUT), MITM_PORT)
                print(sen)
                mitm_dev.write(sen)
            server_socket.settimeout(10)
            try:
                server_socket.connect((dst_ip, 8080))
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
                    data_s_str = data_c.decode('utf-8')
                    print(data_s_str)
                    f = 0
                    for mid in MIDDLE:
                        search_string = START + '"' + mid + '"'
                        if (not (data_s_str.find(search_string) == -1)):
                            f = 1
                            break
                    if (not f):
                        server_socket.sendall(data_c)
                    else:
                        server_socket.close()
                        client_socket.setblocking(True)
                        while True:
                            data_s = client_socket.recv(1024)
                            if not data_s:
                                client_socket.close()
                                return

                if not data_s == 1:
                    client_socket.sendall(data_s)

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=mitm, args=(conn,addr))
            t.start()
        
        