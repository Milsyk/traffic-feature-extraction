import copy
import re
import subprocess
# import pcapy
import dpkt
import requests
import threading
from bs4 import BeautifulSoup
import json
import datetime
import time
import sys
from scapy.all import *
from copy import deepcopy

from scapy.layers.inet import TCP
from selenium import webdriver
import subprocess
import os

LOCK = threading.Lock()

HTTP_PORT = 9999
HTTPS_PORT = 9999
g_filter = "port 9999"
RESPONSE = False
packets = None
error_url_num = []
g_proxy = '127.0.0.1:9999'
g_headers = \
{
  "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
  "Accept-Encoding": "gzip, deflate, br, zstd",
  "Accept-Language": "zh-CN,zh;q=0.9",
  "Priority": "u=0, i",
  "Sec-Ch-Ua": "\"Google Chrome\";v=\"125\", \"Chromium\";v=\"125\", \"Not.A/Brand\";v=\"24\"",
  "Sec-Ch-Ua-Mobile": "?0",
  "Sec-Ch-Ua-Platform": "\"Windows\"",
  "Sec-Fetch-Dest": "document",
  "Sec-Fetch-Mode": "navigate",
  "Sec-Fetch-Site": "none",
  "Sec-Fetch-User": "?1",
  "Upgrade-Insecure-Requests": "1",
  "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    #windows edge
  #   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
  #   "Accept-Encoding": "gzip, deflate, br, zstd",
  #   "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
  #   "Cache-Control": "max-age=0",
  #   "Priority": "u=0, i",
  #   "Sec-Ch-Ua": "\"Microsoft Edge\";v=\"125\", \"Chromium\";v=\"125\", \"Not.A/Brand\";v=\"24\"",
  #   "Sec-Ch-Ua-Mobile": "?0",
  #   "Sec-Ch-Ua-Platform": "\"Windows\"",
  #   "Sec-Fetch-Dest": "document",
  #   "Sec-Fetch-Mode": "navigate",
  #   "Sec-Fetch-Site": "none",
  #   "Sec-Fetch-User": "?1",
  #   "Upgrade-Insecure-Requests": "1",
  #   "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0"
#iphone 夸克
    # "Connection": "keep-alive",
    # "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X; zh-cn) AppleWebKit/601.1.46 (KHTML, like Gecko) Mobile/20G75 Quark/6.12.5.2127 Mobile",
    # "Accept": "*/*",
    # "Accept-Encoding": "gzip, deflate",
    # "Accept-Language": "zh-Hans-CN;q=1"
    #安卓EDGE
    # "Connection": "keep-alive",
    # "Sec-Mesh-Client-Edge-Version": "124.0.2478.104",
    # "Sec-Mesh-Client-Edge-Channel": "stable",
    # "Sec-Mesh-Client-OS": "Android",
    # "Sec-Mesh-Client-OS-Version": "9",
    # "Sec-Mesh-Client-Arch": "aarch64",
    # "Sec-Mesh-Client-WebView": "0",
    # "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36 EdgA/124.0.0.0",
    # "Accept-Encoding": "gzip, deflate"
    #ios safari
    # "Accept": "image/webp,image/avif,video/*;q=0.8,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5",
    # "Accept-Language": "zh-CN,zh-Hans;q=0.9",
    # "Connection": "keep-alive",
    # "Accept-Encoding": "gzip, deflate",
    # "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1"
}
def check_adb_connection():
    # 检查是否有设备连接
    result = subprocess.run(['adb', 'devices'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if 'emulator-5554' in result.stdout:
        return True
    else:
        return False

def run_adb_command(command):
    result = subprocess.run(['adb', 'shell', command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode == 0:
        return result.stdout
    else:
        return result.stderr
def send_url_request(urls):

    proxy_http_address = 'http://127.0.0.1:9999'
    # headers = {
    #     'Content-Type': 'application/json'
    # }
    proxies = {
        'http': proxy_http_address,
        'https': proxy_http_address,
    }
    # headers = {
    #         "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    #         "Connection": "keep-alive",
    #         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
    # }
    try:
        # for url_contend in urls:
        # time.sleep(10)
        global RESPONSE
        global g_headers
        headers = g_headers
        url_response = requests.get(urls, proxies=proxies, headers=headers, verify=False, timeout=5)
        # url_response = requests.get(url_contend)
        RESPONSE = True
        # print(urls)
        print("url:", urls, "response:",  url_response)
        if url_response.headers.get('location') != None:
            url_response_retry = requests.get(url_response.headers.get('location'), proxies=proxies, headers=headers, verify=False)
            print("发生重定向 url_location:", url_response.headers.get('location'), "response:", url_response_retry)
        # interval = 40
        # time.sleep(interval)
    except Exception as e:
        print(e)
        RESPONSE = True

#过滤ACK、SYN数据包
def filter_syn_ack(packet):

    tcp_layer = packet.getlayer('TCP')
    flags = tcp_layer.flags  # get the flags of the TCP packet
    # Convert the flags (which are integer bitwise OR operations) to hexadecimal
    flags_hex = hex(flags.value)
    # Check if the SYN and ACK bits are set
    # print(flags_hex)
    if packet.haslayer('TCP') and flags_hex == '0x12':
        return True
    return False



def search_array_of_dicts(array, key):
    '''
    检索数组中的字典是否存在指定的key-value
    '''
    # i = 0
    # for item in array:
    #     if item.get(key) != None:
    #         return i
    #     i += 1
    # return None
    if key in array:
        return array[key]
    else:
        return None


def get_tcp_packet_features(packet):
    try:
        options = packet['TCP'].options
        tcp_window_size = packet['TCP'].window
        tcp_scale = None
        s_options = ''
        op_first = 0
        op_cont = 0
        ttl = packet['IP'].ttl
        for option in options:
            # opt_val = option[1]
            if option[0] == "WScale":
                tcp_scale = option[1]
            if option[0] == "MSS":
                s_options = str(option[1])
            # else:
            #     if isinstance(option[1], bytes):
            #         opt_val = int.from_bytes(option[1], byteorder='little', signed=False)
            #     if op_cont != op_first:
            #         if option[1] == None:
            #             opt_val = 0
            #         s_options += '_' + str(opt_val)
            #     else:
            #         if option[1] == None:
            #             opt_val = 0
            #         s_options += str(opt_val)
            op_cont += 1
        return tcp_window_size, tcp_scale, s_options + '_' + str(ttl)
    except:
        return None, None, None


# 打印数据包的window size、scale和option特征
def print_tcp_packet_features(url, tcp_window_size, tcp_scale, options):
    print("-" * 20)
    print("URL: ",url)
    print("TCP window size: ", tcp_window_size)
    print("TCP scale: ", tcp_scale)
    print("TCP options: ", options)

def check_packets(packets):
    global error_flag
    global sd_ip_port
    after_syn_ack = False
    cont = 0
    for packet in packets:
        cont += 1
        #判断是否SYNACK包之后的数据包
        tcp_layer = packet.getlayer('TCP')
        flags = tcp_layer.flags  # get the flags of the TCP packet
        # Convert the flags (which are integer bitwise OR operations) to hexadecimal
        flags_hex = hex(flags.value)

        TCP = 'TCP'
        if after_syn_ack:
            if packet.haslayer(TCP):
                if after_syn_ack:
                    if is_errorPacket(packet):  # 重传、错序
                        print(cont, "error packet:", packet.summary())
                        error_flag = True
                        return

        if packet.haslayer('TCP') and flags_hex == '0x12':
            after_syn_ack = True
    sd_ip_port = {}

sd_ip_port = {}
def is_errorPacket(packet):

    global sd_ip_port
    key = str(packet['IP'].src) + '_' + str(packet['TCP'].sport) + '_' + str(packet['IP'].dst) + '_' + str(packet['TCP'].dport) + '_' + str(packet['IP'].proto)
    value = search_array_of_dicts(sd_ip_port, key)
    if value != None:
        seq_len = value
        last_len = seq_len.split('_')[0]
        last_seq = seq_len.split('_')[1]

        # Check if the SYN and ACK bits are set
        # print(flags_hex)

        if packet['TCP'].seq != int(last_seq) + int(last_len):
            print("ERROR:", packet['TCP'].seq, "last_seq:", int(last_seq), "last_len:", int(last_len))
            sd_ip_port = {}
            pcap_name = value
            # wrpcap("C:/Users/Administrator/Desktop/analysis/" + pcap_name + "测试.pcap", packets)
            return True
    # print("payload_len:", packet['IP'].len - 40 - packet['TCP'].options.__len__(), "sep:", packet['TCP'].seq,"options len:", packet['TCP'].options.__len__())
    if packet['TCP'].options.__len__() != 0:
        len_options = 12
    else:
        len_options = 0
    sd_ip_port[key] = str(packet['IP'].len - 40 - len_options) + '_' + str(packet['TCP'].seq)
    return False

# Packets = []
# def is_out_of_order(packet):
#     global sd_ip_port
error_flag = False
after_syn_ack = False
def packet_callback(packet):

    global RESPONSE
    if RESPONSE:
        return RESPONSE

def packet_sniff():
    global g_filter
    filter = g_filter
    # sniff(prn=packet_handler, filter=filter, iface='以太网', stop_filter=packet_callback, timeout=20)
    global packets
    packets = sniff(filter=filter, iface='以太网', stop_filter=packet_callback, timeout=20)
    # packets = sniff(iface='以太网', timeout=10)
    # wrpcap("C:/Users/Administrator/Desktop/" + "9999.pcap", packets)
    # return packets

# 抓取数据包，并获取特征
def capture_and_get_features(urls, result):
    global HTTP_PORT
    global HTTPS_PORT
    TCP = 'TCP'
    global group_n
    global error_flag
    g_url_n = 1
    for url in urls:
        g_url_n += 1
        pcap_name = str(group_n) + '_' + str(g_url_n)
        print(pcap_name)
        # try_cont = 0
        # while try_cont < 9:
        #     # 开始捕获网络流量
        #     try_cont += 1
        t_sendUrl = threading.Thread(target=packet_sniff)
        t_sendUrl.start()
        send_url_request(url)
        # packets = sniff(filter=filter, timeout=10, count=0)
        t_sendUrl.join()
        global packets
        global RESPONSE
        RESPONSE = False

        check_packets(packets)
        if error_flag:
            # wrpcap("C:/Users/Administrator/Desktop/analysis/" + pcap_name + "测试.pcap", packets)
            correct_pkts = correct_packets(packets)
            packets = correct_pkts
            # wrpcap("C:/Users/Administrator/Desktop/analysis/" + pcap_name + "测试纠正!!!!!.pcap", correct_pkts)

        error_flag = False
        # time.sleep(1)
        # 保存数据包
        print(pcap_name)
        wrpcap("C:/Users/Administrator/Desktop/analysis/" + pcap_name + ".pcap", packets)
        deal_packets(packets, url, result)


def deal_packets(packets, url, result):
    TCP = 'TCP'
    stats = {}
    # stats[url] = {'Window': 0, 'scale': 0, 'options': ''}
    stats[url] = {'Window': "", 'scale': "", 'options': '', 'type': '', 'direction': '',
    'http': {'up': 0, 'up_load': 0, 'down': 0, 'down_load': 0, 'len': 0, 'total': 0},
    'https': {'up': 0, 'up_load': 0, 'down': 0, 'down_load': 0, 'len': 0, 'total': 0}}
    protocols_type = url.split(":")[0]
    # pack_cont: int = 1
    # global LOCK
    after_syn_ack = False
    for packet in packets:
        #过滤SYN+ACK数据包
        if filter_syn_ack(packet):
            after_syn_ack = True
            tcp_window_size, tcp_scale, options = get_tcp_packet_features(packet)
            if tcp_window_size is not None and packet[TCP].sport == HTTPS_PORT:

                stats[url]['Window'] = str(tcp_window_size)
                # else:
                #     stats[url]['Window'] += str(tcp_window_size)
                if tcp_scale is not None:
                    stats[url]['scale'] = str(tcp_scale)
                else:
                    stats[url]['scale'] = "0"
                if len(options) != 0:
                    stats[url]['options'] = options
                else:
                    stats[url]['options'] = "0"
            else:
                stats[url]['Window'] = "0"

        else:
            if packet.haslayer(TCP) and after_syn_ack:
                if packet['TCP'].options.__len__() != 0:
                    len_options = 12
                else:
                    len_options = 0
                tcp_payload = packet['IP'].len - 40 - len_options
                    # continue
                # 检查数据包是否为HTTP协议
                # if packet[TCP].dport == HTTP_PORT or packet[TCP].sport == HTTP_PORT:
                if protocols_type == 'http':
                    # stats[url]['total'] += 1

                    stats[url]['type'] = 'http'
                    # 检查数据包方向
                    if packet[TCP].sport == HTTP_PORT:
                        if tcp_payload != 0:
                            if stats[url]['direction'] != '':
                                stats[url]['direction'] += '_-' + str(tcp_payload)
                            else:
                                stats[url]['direction'] += '-' + str(tcp_payload)
                            stats[url]['http']['total'] += 1
                            stats[url]['http']['down'] += 1
                            stats[url]['http']['down_load'] += tcp_payload
                            stats[url]['http']['len'] += tcp_payload
                    else:
                        if tcp_payload != 0:
                            if stats[url]['direction'] != '':
                                stats[url]['direction'] += '_+' + str(tcp_payload)
                            else:
                                stats[url]['direction'] += '+' + str(tcp_payload)
                            stats[url]['http']['total'] += 1
                            stats[url]['http']['up'] += 1
                            stats[url]['http']['up_load'] += tcp_payload
                            stats[url]['http']['len'] += tcp_payload
                # 检查数据包是否为HTTPS协议
                # elif packet[TCP].dport == HTTPS_PORT or packet[TCP].sport == HTTPS_PORT:
                elif protocols_type == 'https':
                    # stats[url]['total'] += 1

                    stats[url]['type'] = 'https'
                    # 检查数据包方向
                    if packet[TCP].sport == HTTPS_PORT:
                        if tcp_payload != 0:
                            if stats[url]['direction'] != '':
                                stats[url]['direction'] += '_-' + str(tcp_payload)
                            else:
                                stats[url]['direction'] += '-' + str(tcp_payload)
                            stats[url]['https']['total'] += 1
                            stats[url]['https']['down'] += 1
                            stats[url]['https']['down_load'] += tcp_payload
                            stats[url]['https']['len'] += tcp_payload
                    else:
                        if tcp_payload != 0:
                            if stats[url]['direction'] != '':
                                stats[url]['direction'] += '_+' + str(tcp_payload)
                            else:
                                stats[url]['direction'] += '+' + str(tcp_payload)
                            stats[url]['https']['total'] += 1
                            stats[url]['https']['up'] += 1
                            stats[url]['https']['up_load'] += tcp_payload
                            stats[url]['https']['len'] += tcp_payload
                # pack_cont += 1
                    # with LOCK:
                    # search_result = search_array_of_dicts(result, url)
                    # if search_result is not None:
                    #     result[search_result].update(stats)
                    # else:
    result.append(deepcopy(stats))

    # with LOCK:
    print("-" * 20)
    print("Stats for: ", url, "feature analysis finished")
    print('\tTotal Packets:', stats[url]['http']['total'] + stats[url]['https']['total'])
    print('\tTotal Length:', stats[url]['http']['len'] + stats[url]['https']['len'])

def correct_packets(packets):
    packet_SeqLen = {}#存储上下行的上一个数据包的seq_len
    # positive_finished = False
    # negative_finished = False
    working_packets = copy.deepcopy(packets)
    new_packets = []#重组packets
    OutOfOder_packets = []
    after_syn_ack = False
    out_of_oreder_needDelete = []
    # while not positive_finished and not negative_finished:
    for packet in working_packets:
        tcp_layer = packet.getlayer('TCP')
        flags = tcp_layer.flags  # get the flags of the TCP packet
        # Convert the flags (which are integer bitwise OR operations) to hexadecimal
        flags_hex = hex(flags.value)
        if not after_syn_ack:#synACK之前的数据包直接保存
            new_packets.append(copy.deepcopy(packet))
        else:
            key = str(packet['IP'].src) + '_' + str(packet['TCP'].sport) + '_' + str(packet['IP'].dst) \
                  + '_' + str(packet['TCP'].dport) + '_' + str(packet['IP'].proto)
            value = search_array_of_dicts(packet_SeqLen, key)
            if packet['TCP'].options.__len__() != 0:
                len_options = 12
            else:
                len_options = 0
            if value != None:
                seq_len = value
                last_len = seq_len.split('_')[0]
                last_seq = seq_len.split('_')[1]
                if last_seq == packet['TCP'].seq and last_len == packet['IP'].len - 40 - len_options:
                    continue
            if value == None or packet['TCP'].seq == int(last_seq) + int(last_len):#符合seq = lastSeq+lastLen的数据包加入新数据包数组

                packet_SeqLen[key] = str(packet['IP'].len - 40 - len_options) + '_' + str(packet['TCP'].seq)
                new_packets.append(copy.deepcopy(packet))
                # print("len:", packet['IP'].len - 40 - len_options,
                #       'seq:', packet['TCP'].seq)
            else:#不符合seq = lastSeq+lastLen的数据包加入错序数组并判断错序数组中是否有合适的数据包
                OutOfOder_packets.append(copy.deepcopy(packet))
                # for ppkt in out_of_oreder_needDelete:
                #     OutOfOder_packets.remove(ppkt)
                # out_of_oreder_needDelete = []
        if packet.haslayer('TCP') and flags_hex == '0x12':#收到SYNACK数据包后 after_syn_ack置为true
            after_syn_ack = True
        for pkt in OutOfOder_packets:
            if packet['TCP'].options.__len__() != 0:
                len_options = 12
            else:
                len_options = 0
            pkt_key = str(pkt['IP'].src) + '_' + str(pkt['TCP'].sport) + '_' + str(pkt['IP'].dst) \
                      + '_' + str(pkt['TCP'].dport) + '_' + str(pkt['IP'].proto)
            pkt_value = search_array_of_dicts(packet_SeqLen, pkt_key)
            if pkt_value != None:
                pkt_seq_len = pkt_value
                pkt_last_len = pkt_seq_len.split('_')[0]
                pkt_last_seq = pkt_seq_len.split('_')[1]
                if pkt_last_seq == pkt['TCP'].seq and pkt_last_len == pkt['IP'].len - 40 - len_options:
                    continue
            if pkt['TCP'].seq == int(pkt_last_seq) + int(pkt_last_len):
                key = str(pkt['IP'].src) + '_' + str(pkt['TCP'].sport) + '_' + str(pkt['IP'].dst) + '_' + str(
                    pkt['TCP'].dport) + '_' + str(pkt['IP'].proto)
                packet_SeqLen[key] = str(pkt['IP'].len - 40 - len_options) + '_' + str(pkt['TCP'].seq)
                new_packets.append(copy.deepcopy(pkt))
                out_of_oreder_needDelete.append(copy.deepcopy(pkt))
                print("错序数据包缓存中加入 len:", pkt['IP'].len - 40 - len_options, 'seq:',
                      pkt['TCP'].seq)
                # OutOfOder_packets.remove(pkt)
        # OutOfOder_packets.append(copy.deepcopy(packet))
        for ppkt in out_of_oreder_needDelete:
            OutOfOder_packets.remove(ppkt)
        out_of_oreder_needDelete = []
    return new_packets


# 定义一个字典来存储按照五元组分组的数据包
# packets_by_five_tuple = {}
# 定义回调函数，用于处理捕获到的数据包并分组
def packet_handler(packet, packets_by_five_tuple):
    # 提取五元组信息
    src_ip = packet['IP'].src
    dst_ip = packet['IP'].dst
    sport = packet['TCP'].sport if TCP in packet else None
    dport = packet['TCP'].dport if TCP in packet else None
    tcp_layer = packet.getlayer('TCP')
    flags = tcp_layer.flags  # get the flags of the TCP packet
    # Convert the flags (which are integer bitwise OR operations) to hexadecimal
    flags_hex = hex(flags.value)
    # 创建五元组键（使用frozenset来保证其可哈希性）
    five_tuple = frozenset([(src_ip, sport, dst_ip, dport)])
    reverse_five_tuple = frozenset([(dst_ip, dport, src_ip, sport)])
    # global packets_by_five_tuple
    # 如果五元组键不存在于字典中，则创建一个新列表
    if five_tuple not in packets_by_five_tuple and reverse_five_tuple not in packets_by_five_tuple:
        if packet.haslayer('TCP') and flags_hex == '0x2':
            packets_by_five_tuple[five_tuple] = []
        else:
            return
    # 将数据包添加到对应的列表中
    if five_tuple in packets_by_five_tuple:
        packets_by_five_tuple[five_tuple].append(packet)
    elif reverse_five_tuple in packets_by_five_tuple:
        packets_by_five_tuple[reverse_five_tuple].append(packet)

g_packet_lock = threading.Lock()
def get_url_list(url_request, result, group_n, f):
    # 要请求的URL
    # 发送请求并获取响应
    try:
        proxy_http_address = 'http://127.0.0.1:9999'
        proxies = {
            'http': proxy_http_address,
            'https': proxy_http_address,
        }
        # headers = {
        #         "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        #         "Connection": "keep-alive",
        #         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
        # }
        # time.sleep(5)
        links = []
        # links.append(url_request)
        global RESPONSE
        global error_flag
        global packets
        global g_packet_lock
        # global group_n
        try_cont = 0
        with g_packet_lock:
            t_sendUrl = threading.Thread(target=packet_sniff)
            # 开始捕获网络流量
            t_sendUrl.start()
            global g_headers
            headers = g_headers
            # response = requests.get(url=url_request, proxies=proxies, headers=headers, verify=False, timeout=20)
            run_adb_command(f'am start -a android.intent.action.VIEW -d "{url_request}"')
            # browser.get(f'{url_request}')
            # print(chrome.page_source)
            # chrome.quit()  # 退出
            time.sleep(10)
            RESPONSE = True
            t_sendUrl.join()
        RESPONSE = False
        # wrpcap("C:/Users/Administrator/Desktop/analysis/" + str(group_n) + "测试(all packets).pcap", packets)
        packets_by_five_tuple = {}
        for packet in packets:
            packet_handler(packet, packets_by_five_tuple)
        # g_nn = 1
        g_n = 1
        # global packets_by_five_tuple
        for five_tuple, packets_f in packets_by_five_tuple.items():
            if len(packets_f) < 20:
                continue
            # wrpcap("C:/Users/Administrator/Desktop/analysis/" + str(group_n) + '_' + str(g_nn) + "测试.pcap", packets_f)
            check_packets(packets_f)

            if error_flag:
                # wrpcap("C:/Users/Administrator/Desktop/analysis/" + str(group_n) + '_' + '1' + "测试.pcap", packets)
                correct_pkts = correct_packets(packets_f)
                packets_f = correct_pkts
            error_flag = False
            # time.sleep(1)
            deal_packets(packets_f, url_request, result)
            wrpcap("C:/Users/Administrator/Desktop/analysis/" + str(group_n) + '_' + str(g_n) + ".pcap", packets_f)
            g_n += 1
        output(result, group_n, f)
        # packets_by_five_tuple = {}
    except Exception as e:
        print(e)
        return links

g_lock = threading.Lock()
def output(result, group_n, f):
    # global group_n
    # group_n = 1
    global g_lock
    with g_lock:
        for stats in result:
            # 打印统计结果
            urll = list(stats)
            url = urll[0]
            # f.write(url)
            if stats[url]['http']['total'] < 10 and stats[url]['https']['total'] < 10:
                continue
            if stats[url]['https']['down_load'] == 0 and stats[url]['http']['down_load'] == 0:
                continue
            print("-" * 20)
            print("URL: ", url)
            print(group_n, end='\t', file=f)
            print(url.encode('gbk', errors='ignore').decode('gbk'), end='\t', file=f)
            print("\tTCP window size: ", stats[url]['Window'])
            print(str(stats[url]['Window']), end='\t', file=f)
            print("\tTCP scale: ", stats[url]['scale'])
            print(str(stats[url]['scale']), end='\t', file=f)
            print("\tTCP options: ", stats[url]['options'])
            print(str(stats[url]['options']), end='\t', file=f)
            print('\tStats for:', url)
            print('\tDirection:', stats[url]['direction'])
            print(str(stats[url]['direction']), end='\t', file=f)
            if stats[url]['type'] == 'http':
                print('HTTP:')
                # print("HTTP", end='\t', file=f)
                print('\tUp Packets:', stats[url]['http']['up'])
                print(str(stats[url]['http']['up']), end='\t', file=f)
                print('\tUp Loads:', stats[url]['http']['up_load'])
                print(str(stats[url]['http']['up_load']), end='\t', file=f)
                print('\tDown Packets:', stats[url]['http']['down'])
                print(str(stats[url]['http']['down']), end='\t', file=f)
                print('\tDown Loads:', stats[url]['http']['down_load'])
                print(str(stats[url]['http']['down_load']), end='\t', file=f)
                print('\tTotal Packets:', stats[url]['http']['total'])
                print(str(stats[url]['http']['total']), end='\t', file=f)
                print('\tTotal Length:', stats[url]['http']['len'])
                print(str(stats[url]['http']['len']), end='', file=f)
            if stats[url]['type'] == 'https':
                print('HTTPS:')
                # print("HTTPS", end='\t', file=f)
                print('\tUp Packets:', stats[url]['https']['up'])
                print(str(stats[url]['https']['up']), end='\t', file=f)
                print('\tUp Loads:', stats[url]['https']['up_load'])
                print(str(stats[url]['https']['up_load']), end='\t', file=f)
                print('\tDown Packets:', stats[url]['https']['down'])
                print(str(stats[url]['https']['down']), end='\t', file=f)
                print('\tDown Loads:', stats[url]['https']['down_load'])
                print(str(stats[url]['https']['down_load']), end='\t', file=f)
                print('\tTotal Packets:', stats[url]['https']['total'])
                print(str(stats[url]['https']['total']), end='\t', file=f)
                print('\tTotal Length:', stats[url]['https']['len'])
                print(str(stats[url]['https']['len']), end='', file=f)
                # print('Overall:')
                # print('\tTotal Packets:', stats[url]['http']['total'] + stats[url]['https']['total'])
                # print(str(stats[url]['http']['total'] + stats[url]['https']['total']), end='\t', file=f)
                # print('\tTotal Length:', stats[url]['http']['len'] + stats[url]['https']['len'])
                # print(str(stats[url]['http']['len'] + stats[url]['https']['len']), end='\t', file=f)
            print('')
            print('\n', end="", file=f)
    # group_n += 1

if __name__ == "__main__":

    if check_adb_connection():
        print("设备已连接")
        # 示例：获取设备上的文件列表
        # command_output = run_adb_command('am start -a android.intent.action.VIEW -d "https://www.baidu.com"')
        # print(command_output)
    else:
        print("没有连接的设备，请确保设备已连接并启用USB调试")

    # 读取文件
    # path = 'C:/Users/Administrator/Desktop/foreigndomains'
    file = open('C:/Users/Administrator/Desktop/foreigndomains', 'r', encoding='utf-8')
    file_contents = file.readlines()
    url_list = []
    t_list = []
    proxy = '127.0.0.1:9999'
    # selenium 模仿chrom
    # browser_options = webdriver.ChromeOptions()  # 代理IP,由快代理提供
    # # 设置代理
    # browser_options.add_argument('--proxy-server=%s' % proxy)
    # browser_options.add_experimental_option('excludeSwitches', ['enable-automation'])
    # # 注意：这里的'--user-data-dir'是指向用户数据目录，可以设置为真实用户的Chrome数据目录，但这可能涉及隐私问题
    # browser_options.add_argument(r'--user-data-dir=C:\Users\Administrator\AppData\Local\Google\Chrome\User Data\Default')
    # # 注意options的参数用之前定义的chrome_options
    # browser = webdriver.Chrome(options=browser_options)

    for content in file_contents:
        split_cont = content.split('|')
        # print(split_cont)
        if len(split_cont) > 1:
            url_list.append(deepcopy('https://' + split_cont[1]))

    # with open(r'C:\Users\Administrator\Desktop\url_feature.bcp', 'w', newline='') as f:
    f = open(r'C:\Users\Administrator\Desktop\url_feature.bcp', 'w', newline='')
    print(
        "group_n\tURL\twindow\tscale\toptions\tdirection\tUp_Packets\tUp_Loads\tDown_Packets\tDown_Loads\tTotal_Packets\tTotal_Length"
        "\t",
        file=f
        )
    # global group_n
    group_n = 1
    for URL in url_list:
        # 要请求的URL
        result = []
        # t_getUrl = threading.Thread(target=get_url_list, args=(URL, result, group_n, f))
        get_url_list(URL, result, group_n, f)
        # t_getUrl.start()
        # t_list.append(t_getUrl)
        group_n += 1
            # interval = 600
            # start_time = datetime.now()
    # for t_work in t_list:
    #     t_work.join()
    f.close()
    # browser.quit()  # 退出
