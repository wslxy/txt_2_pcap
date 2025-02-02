from scapy.layers.l2 import Ether  # 显式导入Ether层
from scapy.layers.inet import IP, TCP
from scapy.all import *
import csv
import random
import time


# ================= 配置 =================
CLIENT_IP = "192.168.1.100"
CLIENT_MAC = "00:0c:29:aa:bb:cc"
SERVER_MAC = "00:0c:29:dd:ee:ff"
GATEWAY_MAC = "00:50:56:ab:cd:ef"


# ================= 协议构造工具 =================
def calculate_tcp_length(payload):
    """精确计算TCP载荷字节长度（含换行符）"""
    return len(payload.encode('utf-8'))


def build_http_layer(header, body):
    """构造符合RFC标准的HTTP载荷"""
    return header.strip() + "\r\n\r\n" + body.strip()


# ================= TCP流生成核心逻辑 =================
def generate_tcp_stream(req_header, req_body, resp_header, resp_body):
    packets = []
    timestamp = time.time()  # 统一时间基准

    # 解析目标服务器信息
    host_line = [line for line in req_header.splitlines() if "Host:" in line][0]
    host = host_line.split("Host: ")[1].strip()
    dst_ip = host.split(":")[0] if ":" in host else host
    dst_port = int(host.split(":")[1]) if ":" in host else 80

    # 生成随机TCP参数
    src_port = random.randint(1024, 65535)
    client_isn = random.getrandbits(32)
    server_isn = random.getrandbits(32)

    # ===== 三次握手 =====
    # 客户端SYN
    syn = Ether(src=CLIENT_MAC, dst=GATEWAY_MAC) / \
          IP(src=CLIENT_IP, dst=dst_ip, ttl=64) / \
          TCP(sport=src_port, dport=dst_port, flags="S", seq=client_isn)
    syn.time = timestamp
    packets.append(syn)
    timestamp += 0.1  # 100ms间隔

    # 服务器SYN-ACK
    syn_ack = Ether(src=SERVER_MAC, dst=GATEWAY_MAC) / \
              IP(src=dst_ip, dst=CLIENT_IP, ttl=64) / \
              TCP(sport=dst_port, dport=src_port, flags="SA", seq=server_isn, ack=client_isn + 1)
    syn_ack.time = timestamp
    packets.append(syn_ack)
    timestamp += 0.1

    # 客户端ACK
    ack = Ether(src=CLIENT_MAC, dst=GATEWAY_MAC) / \
          IP(src=CLIENT_IP, dst=dst_ip, ttl=64) / \
          TCP(sport=src_port, dport=dst_port, flags="A", seq=client_isn + 1, ack=server_isn + 1)
    ack.time = timestamp
    packets.append(ack)
    timestamp += 0.1

    # ===== HTTP请求 =====
    http_req = build_http_layer(req_header, req_body)
    req_pkt = Ether(src=CLIENT_MAC, dst=GATEWAY_MAC) / \
              IP(src=CLIENT_IP, dst=dst_ip, ttl=64) / \
              TCP(sport=src_port, dport=dst_port, flags="PA",
                  seq=client_isn + 1,
                  ack=server_isn + 1) / \
              Raw(load=http_req.encode('utf-8'))
    req_pkt.time = timestamp
    packets.append(req_pkt)
    timestamp += 0.1

    # ===== 服务器ACK请求 =====
    server_ack = Ether(src=SERVER_MAC, dst=GATEWAY_MAC) / \
                 IP(src=dst_ip, dst=CLIENT_IP, ttl=64) / \
                 TCP(sport=dst_port, dport=src_port, flags="A",
                     seq=server_isn + 1,
                     ack=client_isn + 1 + calculate_tcp_length(http_req))
    server_ack.time = timestamp
    packets.append(server_ack)
    timestamp += 0.1

    # ===== HTTP响应 =====
    http_resp = build_http_layer(resp_header, resp_body)
    resp_pkt = Ether(src=SERVER_MAC, dst=GATEWAY_MAC) / \
               IP(src=dst_ip, dst=CLIENT_IP, ttl=64) / \
               TCP(sport=dst_port, dport=src_port, flags="PA",
                   seq=server_isn + 1,
                   ack=client_isn + 1 + calculate_tcp_length(http_req)) / \
               Raw(load=http_resp.encode('utf-8'))
    resp_pkt.time = timestamp
    packets.append(resp_pkt)
    timestamp += 0.1

    # ===== 四次挥手 =====
    # 客户端FIN-ACK
    fin = Ether(src=CLIENT_MAC, dst=GATEWAY_MAC) / \
          IP(src=CLIENT_IP, dst=dst_ip, ttl=64) / \
          TCP(sport=src_port, dport=dst_port, flags="FA",
              seq=client_isn + 1 + calculate_tcp_length(http_req),
              ack=server_isn + 1 + calculate_tcp_length(http_resp))
    fin.time = timestamp
    packets.append(fin)
    timestamp += 0.1

    # 服务器FIN-ACK
    fin_ack = Ether(src=SERVER_MAC, dst=GATEWAY_MAC) / \
              IP(src=dst_ip, dst=CLIENT_IP, ttl=64) / \
              TCP(sport=dst_port, dport=src_port, flags="FA",
                  seq=server_isn + 1 + calculate_tcp_length(http_resp),
                  ack=client_isn + 1 + calculate_tcp_length(http_req) + 1)
    fin_ack.time = timestamp
    packets.append(fin_ack)
    timestamp += 0.1

    # 客户端最后ACK
    last_ack = Ether(src=CLIENT_MAC, dst=GATEWAY_MAC) / \
               IP(src=CLIENT_IP, dst=dst_ip, ttl=64) / \
               TCP(sport=src_port, dport=dst_port, flags="A",
                   seq=client_isn + 1 + calculate_tcp_length(http_req) + 1,
                   ack=server_isn + 1 + calculate_tcp_length(http_resp) + 1)
    last_ack.time = timestamp
    packets.append(last_ack)

    return packets


# ================= CSV处理 =================
def csv_to_pcap(input_csv, output_pcap):
    all_packets = []

    # 自动检测编码（需提前安装chardet）
    with open(input_csv, 'rb') as f:
        raw_data = f.read(1024)  # 仅读取部分内容检测编码
        encoding = 'utf-8'  # 默认编码

        # 简单编码探测逻辑
        try:
            raw_data.decode('utf-8')
            encoding = 'utf-8'
        except UnicodeDecodeError:
            try:
                raw_data.decode('gbk')
                encoding = 'gbk'
            except:
                encoding = 'latin1'

    with open(input_csv, 'r', encoding=encoding, errors='replace') as f:
        reader = csv.reader(f)
        next(reader)  # Skip header

        for row in reader:
            try:
                # 数据清洗
                req_header = row[0].strip().replace('""', '"')
                req_body = row[1].strip()
                resp_header = row[2].strip().replace('""', '"')
                resp_body = row[3].strip()

                # 生成数据包
                packets = generate_tcp_stream(req_header, req_body, resp_header, resp_body)
                all_packets.extend(packets)

            except Exception as e:
                print(f"Error processing row: {str(e)}")
                continue

    # 按时间排序并保存
    all_packets.sort(key=lambda x: x.time)
    wrpcap(output_pcap, all_packets)


if __name__ == "__main__":
    csv_to_pcap("input.csv", "output.pcap")
