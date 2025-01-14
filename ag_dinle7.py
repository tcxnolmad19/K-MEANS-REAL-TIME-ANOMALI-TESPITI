from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import time
import sys
import os
import csv
import logging

# Logging yapılandırması
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

destination_file_path = "/home/selcuk1453/shared/network_features.csv"
destination_folder = os.path.dirname(destination_file_path)
if not os.path.exists(destination_folder):
    os.makedirs(destination_folder, exist_ok=True)

flows = {}
connections_history = []

flow_timeout = 5
active_timeout = 2

allowed_services = [
    'private', 'remote_job', 'ftp_data', 'name', 'netbios_ns', 'eco_i', 'mtp',
    'finger', 'supdup', 'uucp_path', 'Z39_50', 'csnet_ns', 'uucp', 'netbios_dgm',
    'http', 'auth', 'domain', 'ftp', 'bgp', 'ldap', 'ecr_i', 'gopher', 'telnet',
    'vmnet', 'systat', 'http_443', 'efs', 'whois', 'other', 'imap4', 'iso_tsap',
    'echo', 'klogin', 'link', 'sunrpc', 'login', 'kshell', 'sql_net', 'time',
    'hostnames', 'exec', 'discard', 'nntp', 'courier', 'ctf', 'ssh', 'smtp',
    'daytime', 'shell', 'netstat', 'nnsp', 'pop_2', 'printer', 'tim_i', 'pop_3',
    'pm_dump', 'netbios_ssn', 'rje', 'urp_i', 'http_8001', 'X11', 'domain_u', 'aol',
    'http_2784', 'IRC', 'harvest', 'ntp_u', 'urh_i', 'red_i', 'tftp_u'
]

def safe_float(value, default=0.0):
    try:
        return float(value)
    except (ValueError, TypeError):
        return default

def calculate_duration(flow_packets):
    if not flow_packets:
        return 0.0
    duration = flow_packets[-1].time - flow_packets[0].time
    return safe_float(duration)

def determine_protocol(packet):
    if packet.haslayer(TCP):
        return 'tcp'
    elif packet.haslayer(UDP):
        return 'udp'
    elif packet.haslayer(ICMP):
        return 'icmp'
    else:
        return 'other'

def determine_service(packet):
    service_ports = {
        7: 'echo',
        21: 'ftp',
        20: 'ftp_data',
        23: 'telnet',
        25: 'smtp',
        53: 'domain',
        79: 'finger',
        80: 'http',
        110: 'pop_3',
        113: 'auth',
        119: 'nntp',
        123: 'ntp_u',
        137: 'netbios_ns',
        138: 'netbios_dgm',
        139: 'netbios_ssn',
        143: 'imap4',
        161: 'snmp',
        389: 'ldap',
        443: 'http_443',
        445: 'microsoft_ds',
        513: 'whois',
        514: 'shell',
        515: 'printer',
        540: 'uucp',
        554: 'rtsp',
        587: 'smtp',
        631: 'printer',
        993: 'imap4',
        995: 'pop_3',
        1433: 'sql_net',
        1521: 'oracle',
        3306: 'mysql',
        3389: 'rdp',
        6000: 'X11',
        6667: 'IRC',
        8080: 'http_8001',
        2784: 'http_2784',
        69: 'tftp_u',
        4321: 'harvest',
        5432: 'red_i',
        2222: 'urh_i'
    }

    if packet.haslayer(TCP):
        port = packet[TCP].dport
    elif packet.haslayer(UDP):
        port = packet[UDP].dport
    elif packet.haslayer(ICMP):
        return 'eco_i'
    else:
        return 'other'

    service = service_ports.get(port, 'other')
    if service not in allowed_services:
        return 'other'
    return service

def determine_flag(flow_packets):
    if not any(pkt.haslayer(TCP) for pkt in flow_packets):
        return 'OTH'
    syn_flag = False
    fin_flag = False
    rst_flag = False
    ack_flag = False

    for pkt in flow_packets:
        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            syn_flag |= bool(flags & 0x02)
            fin_flag |= bool(flags & 0x01)
            rst_flag |= bool(flags & 0x04)
            ack_flag |= bool(flags & 0x10)

    if syn_flag and ack_flag and not rst_flag:
        return 'SF'
    elif syn_flag and not ack_flag:
        return 'S0'
    elif rst_flag:
        return 'REJ'
    else:
        return 'OTH'

def calculate_src_bytes(flow_packets, src_ip):
    src_bytes = sum(len(pkt) for pkt in flow_packets if pkt.haslayer(IP) and pkt[IP].src == src_ip)
    return safe_float(src_bytes)

def calculate_dst_bytes(flow_packets, dst_ip):
    dst_bytes = sum(len(pkt) for pkt in flow_packets if pkt.haslayer(IP) and pkt[IP].dst == dst_ip)
    return safe_float(dst_bytes)

def calculate_land(flow_packets):
    if not flow_packets:
        return 0.0
    first_packet = flow_packets[0]
    if first_packet.haslayer(IP):
        src_ip = first_packet[IP].src
        dst_ip = first_packet[IP].dst
        if first_packet.haslayer(TCP):
            src_port = getattr(first_packet[TCP], 'sport', 0)
            dst_port = getattr(first_packet[TCP], 'dport', 0)
        elif first_packet.haslayer(UDP):
            src_port = getattr(first_packet[UDP], 'sport', 0)
            dst_port = getattr(first_packet[UDP], 'dport', 0)
        else:
            return safe_float(int(src_ip == dst_ip))
        return safe_float(int(src_ip == dst_ip and src_port == dst_port))
    return 0.0

def calculate_wrong_fragment(flow_packets):
    count = 0
    for pkt in flow_packets:
        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
            if ip_layer.frag != 0 and not ip_layer.flags.MF:
                count += 1
    return safe_float(count)

def calculate_urgent(flow_packets):
    count = 0
    for pkt in flow_packets:
        if pkt.haslayer(TCP) and (pkt[TCP].flags & 0x20):
            count += 1
    return safe_float(count)

def calculate_hot(flow_packets):
    hot_ports = [21, 22, 23, 25, 53, 79, 80, 110, 111, 443, 513, 514]
    count = 0
    for pkt in flow_packets:
        if pkt.haslayer(TCP) and pkt[TCP].dport in hot_ports:
            count += 1
        elif pkt.haslayer(UDP) and pkt[UDP].dport in hot_ports:
            count += 1
    return safe_float(count)

def calculate_logged_in(flow_packets):
    for pkt in flow_packets:
        if pkt.haslayer(Raw):
            try:
                payload = pkt[Raw].load.decode('utf-8', errors='ignore').lower()
                if "login successful" in payload or "welcome" in payload:
                    return 1.0
            except Exception as e:
                logging.debug(f"Payload decoding error: {e}")
    return 0.0

def calculate_num_compromised(flow_packets):
    count = 0
    for pkt in flow_packets:
        if pkt.haslayer(Raw):
            try:
                payload = pkt[Raw].load.decode('utf-8', errors='ignore').lower()
                if "compromised" in payload:
                    count += 1
            except Exception as e:
                logging.debug(f"Payload decoding error: {e}")
    return safe_float(count)

def calculate_su_attempted(flow_packets):
    for pkt in flow_packets:
        if pkt.haslayer(Raw):
            try:
                payload = pkt[Raw].load.decode('utf-8', errors='ignore').lower()
                if "su root" in payload or "su -" in payload:
                    return 1.0
            except Exception as e:
                logging.debug(f"Payload decoding error: {e}")
    return 0.0

def is_serror_flag(flag):
    return flag in ['S0', 'S1', 'S2', 'S3']

def is_rerror_flag(flag):
    return flag == 'REJ'

def compute_kdd_features(src_ip, dst_ip, service, flag, end_time):
    recent_connections = [c for c in connections_history if (end_time - c['end_time'] <= 2.0)]
    same_host_conns = [c for c in recent_connections if c['dst_ip'] == dst_ip]
    same_host_service_conns = [c for c in same_host_conns if c['service'] == service]

    count = len(same_host_conns)
    srv_count = len(same_host_service_conns)
    serror_count = sum(1 for c in same_host_conns if is_serror_flag(c['flag']))
    serror_rate = safe_float(serror_count / count) if count > 0 else 0.0
    srv_serror_count = sum(1 for c in same_host_service_conns if is_serror_flag(c['flag']))
    srv_serror_rate = safe_float(srv_serror_count / srv_count) if srv_count > 0 else 0.0
    rerror_count = sum(1 for c in same_host_conns if is_rerror_flag(c['flag']))
    rerror_rate = safe_float(rerror_count / count) if count > 0 else 0.0
    srv_rerror_count = sum(1 for c in same_host_service_conns if is_rerror_flag(c['flag']))
    srv_rerror_rate = safe_float(srv_rerror_count / srv_count) if srv_count > 0 else 0.0
    same_srv_rate = safe_float(srv_count / count) if count > 0 else 0.0
    diff_srv_rate = safe_float((count - srv_count) / count) if count > 0 else 0.0
    same_service_conns = [c for c in recent_connections if c['service'] == service]
    same_service_diff_host = [c for c in same_service_conns if c['dst_ip'] != dst_ip]
    srv_diff_host_rate = safe_float(len(same_service_diff_host) / srv_count) if srv_count > 0 else 0.0

    last_100 = connections_history[-100:] if len(connections_history) > 100 else connections_history[:]
    dst_host_conns = [c for c in last_100 if c['dst_ip'] == dst_ip]
    dst_host_count = len(dst_host_conns)
    if dst_host_count == 0:
        return {
            'count': safe_float(count), 'srv_count': safe_float(srv_count), 'serror_rate': safe_float(serror_rate),
            'srv_serror_rate': safe_float(srv_serror_rate), 'rerror_rate': safe_float(rerror_rate),
            'srv_rerror_rate': safe_float(srv_rerror_rate), 'same_srv_rate': safe_float(same_srv_rate),
            'diff_srv_rate': safe_float(diff_srv_rate), 'srv_diff_host_rate': safe_float(srv_diff_host_rate),
            'dst_host_count': 0.0, 'dst_host_srv_count': 0.0,
            'dst_host_same_srv_rate': 0.0, 'dst_host_diff_srv_rate': 0.0,
            'dst_host_same_src_port_rate': 0.0, 'dst_host_srv_diff_host_rate': 0.0,
            'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0,
            'dst_host_rerror_rate': 0.0, 'dst_host_srv_rerror_rate': 0.0
        }

    dst_host_srv_conns = [c for c in dst_host_conns if c['service'] == service]
    dst_host_srv_count = len(dst_host_srv_conns)
    dst_host_same_srv_rate = safe_float(dst_host_srv_count / dst_host_count) if dst_host_count > 0 else 0.0
    dst_host_diff_srv_rate = safe_float((dst_host_count - dst_host_srv_count) / dst_host_count) if dst_host_count > 0 else 0.0
    src_port = flows.get((src_ip, dst_ip, service), {}).get('src_port', 0.0)
    same_src_port_conns = [c for c in dst_host_conns if c['src_port'] == src_port]
    dst_host_same_src_port_rate = safe_float(len(same_src_port_conns) / dst_host_count) if dst_host_count > 0 else 0.0
    dst_host_srv_diff_host_conns = [c for c in dst_host_srv_conns if c['src_ip'] != src_ip]
    dst_host_srv_diff_host_rate = safe_float(len(dst_host_srv_diff_host_conns) / dst_host_srv_count) if dst_host_srv_count > 0 else 0.0
    dst_host_serror_count = sum(1 for c in dst_host_conns if is_serror_flag(c['flag']))
    dst_host_serror_rate = safe_float(dst_host_serror_count / dst_host_count) if dst_host_count > 0 else 0.0
    dst_host_srv_serror_count = sum(1 for c in dst_host_srv_conns if is_serror_flag(c['flag']))
    dst_host_srv_serror_rate = safe_float(dst_host_srv_serror_count / dst_host_srv_count) if dst_host_srv_count > 0 else 0.0
    dst_host_rerror_count = sum(1 for c in dst_host_conns if is_rerror_flag(c['flag']))
    dst_host_rerror_rate = safe_float(dst_host_rerror_count / dst_host_count) if dst_host_count > 0 else 0.0
    dst_host_srv_rerror_count = sum(1 for c in dst_host_srv_conns if is_rerror_flag(c['flag']))
    dst_host_srv_rerror_rate = safe_float(dst_host_srv_rerror_count / dst_host_srv_count) if dst_host_srv_count > 0 else 0.0

    return {
        'count': safe_float(count),
        'srv_count': safe_float(srv_count),
        'serror_rate': safe_float(serror_rate),
        'srv_serror_rate': safe_float(srv_serror_rate),
        'rerror_rate': safe_float(rerror_rate),
        'srv_rerror_rate': safe_float(srv_rerror_rate),
        'same_srv_rate': safe_float(same_srv_rate),
        'diff_srv_rate': safe_float(diff_srv_rate),
        'srv_diff_host_rate': safe_float(srv_diff_host_rate),
        'dst_host_count': safe_float(dst_host_count),
        'dst_host_srv_count': safe_float(dst_host_srv_count),
        'dst_host_same_srv_rate': safe_float(dst_host_same_srv_rate),
        'dst_host_diff_srv_rate': safe_float(dst_host_diff_srv_rate),
        'dst_host_same_src_port_rate': safe_float(dst_host_same_src_port_rate),
        'dst_host_srv_diff_host_rate': safe_float(dst_host_srv_diff_host_rate),
        'dst_host_serror_rate': safe_float(dst_host_serror_rate),
        'dst_host_srv_serror_rate': safe_float(dst_host_srv_serror_rate),
        'dst_host_rerror_rate': safe_float(dst_host_rerror_rate),
        'dst_host_srv_rerror_rate': safe_float(dst_host_srv_rerror_rate)
    }

def process_flow(flow_key, flow_packets):
    if not flow_packets:
        return
    first_packet = flow_packets[0]
    src_ip = flow_key[0]
    dst_ip = flow_key[1]
    protocol_name = flow_key[2]
    duration = calculate_duration(flow_packets)
    service = determine_service(first_packet)
    flag = determine_flag(flow_packets)
    src_bytes = calculate_src_bytes(flow_packets, src_ip)
    dst_bytes = calculate_dst_bytes(flow_packets, dst_ip)
    land = calculate_land(flow_packets)
    wrong_fragment = calculate_wrong_fragment(flow_packets)
    urgent = calculate_urgent(flow_packets)
    hot = calculate_hot(flow_packets)
    logged_in = calculate_logged_in(flow_packets)
    num_compromised = calculate_num_compromised(flow_packets)
    su_attempted = calculate_su_attempted(flow_packets)
    end_time = safe_float(flow_packets[-1].time)

    if protocol_name in ['tcp', 'udp']:
        src_port = safe_float(flow_key[3])
        dst_port = safe_float(flow_key[4])
    else:
        src_port = 0.0
        dst_port = 0.0

    kdd_features = compute_kdd_features(src_ip, dst_ip, service, flag, end_time)

    features = {
        'duration': duration,
        'protocol_type': protocol_name,
        'service': service,
        'flag': flag,
        'src_bytes': src_bytes,
        'dst_bytes': dst_bytes,
        'land': land,
        'wrong_fragment': wrong_fragment,
        'urgent': urgent,
        'hot': hot,
        'logged_in': logged_in,
        'num_compromised': num_compromised,
        'su_attempted': su_attempted,
        'count': kdd_features['count'],
        'srv_count': kdd_features['srv_count'],
        'serror_rate': kdd_features['serror_rate'],
        'srv_serror_rate': kdd_features['srv_serror_rate'],
        'rerror_rate': kdd_features['rerror_rate'],
        'srv_rerror_rate': kdd_features['srv_rerror_rate'],
        'same_srv_rate': kdd_features['same_srv_rate'],
        'diff_srv_rate': kdd_features['diff_srv_rate'],
        'srv_diff_host_rate': kdd_features['srv_diff_host_rate'],
        'dst_host_count': kdd_features['dst_host_count'],
        'dst_host_srv_count': kdd_features['dst_host_srv_count'],
        'dst_host_same_srv_rate': kdd_features['dst_host_same_srv_rate'],
        'dst_host_diff_srv_rate': kdd_features['dst_host_diff_srv_rate'],
        'dst_host_same_src_port_rate': kdd_features['dst_host_same_src_port_rate'],
        'dst_host_srv_diff_host_rate': kdd_features['dst_host_srv_diff_host_rate'],
        'dst_host_serror_rate': kdd_features['dst_host_serror_rate'],
        'dst_host_srv_serror_rate': kdd_features['dst_host_srv_serror_rate'],
        'dst_host_rerror_rate': kdd_features['dst_host_rerror_rate'],
        'dst_host_srv_rerror_rate': kdd_features['dst_host_srv_rerror_rate']
    }

    try:
        file_exists = os.path.isfile(destination_file_path)
        with open(destination_file_path, 'a', newline='') as destination_file:
            writer = csv.DictWriter(destination_file, fieldnames=features.keys())
            if not file_exists:
                writer.writeheader()
            writer.writerow(features)
        logging.info(f"Akış işlendi ve kaydedildi: {src_ip} -> {dst_ip}, Servis: {service}")
    except Exception as e:
        logging.error(f"CSV yazma hatası: {e}")

    connections_history.append({
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'service': service,
        'protocol': protocol_name,
        'flag': flag,
        'end_time': end_time,
        'src_port': src_port,
        'dst_port': dst_port
    })

def flush_flows():
    for key in list(flows):
        flow = flows[key]
        process_flow(key, flow['packets'])
        del flows[key]
    logging.info("Kalan akışlar işlendi ve kaydedildi.")

def packet_handler(packet):
    if not packet.haslayer(IP):
        return
    protocol_name = determine_protocol(packet)

    if protocol_name == 'icmp' and packet.haslayer(ICMP):
        icmp_layer = packet[ICMP]
        icmp_type = getattr(icmp_layer, 'type', 0)
        icmp_code = getattr(icmp_layer, 'code', 0)
        icmp_id = getattr(icmp_layer, 'id', 0)
        icmp_seq = getattr(icmp_layer, 'seq', 0)
        flow_key = (
            packet[IP].src, 
            packet[IP].dst, 
            'icmp',
            safe_float(icmp_type),
            safe_float(icmp_code),
            safe_float(icmp_id),
            safe_float(icmp_seq)
        )
    else:
        if packet.haslayer(TCP):
            sport = getattr(packet[TCP], 'sport', 0)
            dport = getattr(packet[TCP], 'dport', 0)
        elif packet.haslayer(UDP):
            sport = getattr(packet[UDP], 'sport', 0)
            dport = getattr(packet[UDP], 'dport', 0)
        else:
            sport = 0
            dport = 0
        flow_key = (packet[IP].src, packet[IP].dst, protocol_name, safe_float(sport), safe_float(dport))

    if flow_key not in flows:
        flows[flow_key] = {'packets': [], 'last_seen': time.time()}

    flows[flow_key]['packets'].append(packet)
    flows[flow_key]['last_seen'] = time.time()

    # ICMP paketlerini hemen işle
    if protocol_name == 'icmp':
        process_flow(flow_key, flows[flow_key]['packets'])
        del flows[flow_key]
    else:
        # Zaman aşımı kontrolleri
        current_time = time.time()
        for key in list(flows):
            flow = flows[key]
            if (current_time - flow['last_seen']) > flow_timeout:
                process_flow(key, flow['packets'])
                del flows[key]
            elif (current_time - flow['last_seen']) > active_timeout:
                process_flow(key, flow['packets'])
                flows[key]['packets'] = []

print("Paket yakalama başlatıldı. Programı durdurmak için Ctrl+C tuşlayın.")

try:
    sniff(prn=packet_handler, store=0)
except KeyboardInterrupt:
    logging.info("Program sonlandırılıyor...")
    flush_flows()
    sys.exit(0)
except Exception as e:
    logging.error(f"Paket yakalama hatası: {e}")
    flush_flows()
    sys.exit(1)

