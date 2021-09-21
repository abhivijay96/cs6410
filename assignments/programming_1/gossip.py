import sys
import time
import socket
import random
import traceback

from threading import Lock
from threading import Thread

if len(sys.argv) < 2:
    print('Usage:', sys.argv[0], 'port')
    exit(1)

class node:
    def __init__(self, ip, port, digit, time) -> None:
        self.ip = ip
        self.port = port
        self.digit = digit
        self.time = time

# map containing keys as node_id -> 255.255.255.255:port, value as obj node
nodes = {}
ip_to_nodes = {}
# mutex to protect nodes
nodes_lock = Lock()

black_list = set()
digit = 0
my_update_time = 0
PORT = int(sys.argv[1])
SLEEP_INTERVAL_S = 3
MAX_NODES_FROM_IP = 3

def get_utc_time_seconds():
    return int(time.time())

def get_my_ip():
    return socket.gethostbyname(socket.gethostname())

def get_printable_str(node_id, update_time, digit):
    return "{},{},{}\n".format(node_id, update_time, digit)

def get_my_info():
    return get_printable_str(get_my_ip() + ":" + str(PORT), my_update_time, digit)

def validate_ip(ip):
    parts = ip.split('.')
    for part in parts:
        try:
            value = int(part)
            assert(value >= 0 and value < 256)
        except Exception as error:
            print('IP addr validation failed for IP', ip, 'at', part)
            print(error)
            return False
    return True

def validate_port(port):
    try:
        port_value = int(port)
        assert(port_value < 65535)
    except Exception as error:
        print('Port validation failed for port', port)
        print(error)
        return False
    return True

def valid_node_entry(line):
    parts = line.split(':')
    ip = parts[0]
    port = parts[1]
    return validate_ip(ip) and validate_port(port) and (str(ip) + ":" + str(port) != get_my_ip() + ":" + str(PORT))

def add_node_to_list(line):
    parts = line.split(':')
    ip = parts[0]
    port = parts[1]
    if valid_node_entry(line):
        nodes_lock.acquire()
        if line not in nodes:
            nodes[line] = node(ip, int(port), -1, 0)
            if ip not in ip_to_nodes:
                ip_to_nodes[ip] = []
            ip_to_nodes[ip].append(int(port))
        nodes_lock.release()

def remove_node(node_id):
    parts = node_id.split(':')
    ip = parts[0]
    port = parts[1]
    nodes.pop(node_id, None)
    # print('Removing', port, 'from', ip_to_nodes[ip])
    ip_to_nodes[ip].remove(int(port))

def update_node(node_id, update_time, update_digit):
    global digit, my_update_time
    if update_time <= get_utc_time_seconds():
        add_node_to_list(node_id)
        nodes_lock.acquire()
        if node_id in nodes:
            nodes[node_id].time = update_time
            nodes[node_id].digit = update_digit
            if update_time > my_update_time:
                digit = update_digit  
                my_update_time = update_time

            # Capping the number of nodes from a give IP
            parts = node_id.split(':')
            ip = parts[0]
            port = parts[1]
            
            min_time = get_utc_time_seconds()
            min_node_id = None
            if len(ip_to_nodes[ip]) > MAX_NODES_FROM_IP:
                for port in ip_to_nodes[ip]:
                    node_id = ip + ":" + str(port)
                    if nodes[node_id].time < min_time:
                        min_time = nodes[node_id].time
                        min_node_id = node_id
            if min_node_id is not None:
                print('Removed', min_node_id)
                remove_node(min_node_id)
        nodes_lock.release()

# assumes nodes lock is already acquired
def contact_node(node_id):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((nodes[node_id].ip, nodes[node_id].port))
            s.settimeout(None)
            read_lines = ''
            data = s.recv(4096)
            while data:
                read_lines += data.decode('utf-8')
                data = s.recv(4096)
            lines = read_lines.splitlines()
            line_count = 0
            for line in lines:
                line = line.strip()
                parts = line.split(',')
                if len(parts) == 3:
                    node_id = parts[0]
                    update_time = parts[1]
                    update_digit = parts[2]
                    addr_parts = node_id.split(':')
                    if validate_ip(addr_parts[0]) and validate_port(addr_parts[1]):
                        update_node(node_id, int(update_time), int(update_digit))  
                line_count += 1
                if line_count == 256:
                    break          
    except Exception as error:
        print('Failed to contact node', node_id)
        print(traceback.format_exc())
        black_list.add(node_id)
        nodes_lock.acquire()
        remove_node(node_id)
        nodes_lock.release()

# background thread 1: 
#   wakes up every 3s
#   Picks a random node
#   Gets its map 
#   Updates entries
#   Print entries while updating        
def server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('0.0.0.0', PORT))
        s.listen()
        while True:
            # print('Waiting....')
            conn, addr = s.accept()
            # print(addr, 'contacting')
            strings_to_send = []
            nodes_lock.acquire()
            for node_id in nodes:
                strings_to_send.append(get_printable_str(node_id, nodes[node_id].time, nodes[node_id].digit).encode('utf-8'))
            strings_to_send.append(get_my_info().encode('utf-8'))
            nodes_lock.release()
            # print('Sending')
            for string_to_send in strings_to_send:
                conn.sendall(string_to_send)
            conn.close()
            # print('Done sending')

# background thread 2:
#   Read input
#   based on input
#       Add to map
#       print map
#       show updates
def client():
    while True:
        time.sleep(SLEEP_INTERVAL_S)
        nodes_lock.acquire()
        nodes_list = list(nodes.keys())
        nodes_lock.release()
        node_id = None
        while len(nodes_list) > 0:
            node_id = random.choice(nodes_list)
            if node_id not in black_list:
                break
        if node_id is not None:
            # print('# Client thread contacting: ', node_id)
            contact_node(node_id)

# Adds a node to the map
def add_node(line):
    line = str(line)
    line = line[1:]
    # print('Adding node', line)
    nodes_lock.acquire()
    line_in_nodes = line in nodes
    nodes_lock.release()

    if not line_in_nodes:
        if valid_node_entry(line):
            add_node_to_list(line)       
            contact_node(line)

# Shows nodes in the map
def show_nodes():
    nodes_lock.acquire()
    for node_id in nodes:
        print(get_printable_str(node_id, nodes[node_id].time, nodes[node_id].digit))
    print(get_my_info())
    nodes_lock.release()

def parse_input(line):
    global digit, my_update_time
    line = str(line)
    line = line.strip()
    if line.startswith('+'):
        add_node(line)
    if line.lower() == 'i':
        show_nodes()
    elif line.isdigit():
        digit = int(line)
        my_update_time = get_utc_time_seconds()

# main thread: takes input
print('Node info - IP:', get_my_ip(), 'PORT:', PORT)
client_thread = Thread(target=client)
server_thread = Thread(target=server)

client_thread.start()
server_thread.start()

while True:
    input_line = input(">> ")
    try:
        parse_input(input_line)
    except:
        print('Invalid input')
        traceback.format_exc()