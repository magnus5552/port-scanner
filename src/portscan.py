from multiprocessing.pool import ThreadPool

from scapy.all import sr1
from scapy.layers.inet import IP, TCP, UDP, ICMP

from ScanResult import ScanResult
from cmd_parser import configure_parser
from constants import TIMEOUT, OPEN_FILTERED, OPEN, CLOSED, NO_PROTO
from protocol_guess import guess_application_protocol

scan_results = []


def tcp_scan(host, port, timeout):
    proto = 'TCP'
    try:
        packet = IP(dst=host) / TCP(dport=port, flags='S')
        response = sr1(packet, timeout=timeout, verbose=False)

        if response is None:
            scan_result = ScanResult(proto, port, TIMEOUT)
        elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            scan_result = ScanResult(proto, port, OPEN,
                                     (response.time - packet.sent_time) * 1000)
        else:
            scan_result = ScanResult(proto, port, CLOSED)

        scan_results.append(scan_result)
        sr1(IP(dst=host) / TCP(dport=port, flags='AR'),
            timeout=timeout, verbose=False)

    except Exception as e:
        scan_result = ScanResult(proto, port, f'Error: {str(e)}')
        scan_results.append(scan_result)


# Функция сканирования UDP портов
def udp_scan(host, port, timeout):
    proto = 'UDP'
    try:
        packet = IP(dst=host) / UDP(dport=port)
        response = sr1(packet, timeout=timeout, verbose=False)

        if not response:
            scan_result = ScanResult(proto, port, OPEN_FILTERED)
        elif response.haslayer(ICMP) and response.getlayer(ICMP).type == 3:
            scan_result = ScanResult(proto, port, CLOSED)
        else:
            scan_result = ScanResult(proto, port, OPEN,
                                     (response.time - packet.sent_time) * 1000)
        scan_results.append(scan_result)

    except Exception as e:
        scan_result = ScanResult(proto, port, f'Error: {str(e)}')
        scan_results.append(scan_result)


def port_scan(host, ports, timeout, num_threads, verbose, guess,
              show_all):
    port_queue = []
    for port in ports:
        if '/' in port:
            protocol, port_range = port.split('/')
            if '-' in port_range:
                start_port, end_port = map(int, port_range.split('-'))
                for port_num in range(start_port, end_port + 1):
                    port_queue.append((protocol, port_num))
            else:
                port_queue.append((protocol, int(port_range)))
        else:
            port_queue.append(('tcp', int(port)))

    def scan_port(pair):
        protocol, port = pair
        if protocol.upper() == 'TCP':
            tcp_scan(host, port, timeout)
        elif protocol.upper() == 'UDP':
            udp_scan(host, port, timeout)

    def guess_proto(scan_result):
        app_proto = guess_application_protocol(host, scan_result.port,
                                               scan_result.protocol, timeout)
        if app_proto != NO_PROTO:
            scan_result.application_protocol = app_proto
            scan_result.status = OPEN

    threadpool = ThreadPool(num_threads)
    threadpool.map(scan_port, port_queue)
    threadpool.close()
    threadpool.join()

    scan_results.sort(key=lambda res: res.port)
    if guess:
        open_or_filter = filter(
            lambda res: res.status == OPEN or res.status == OPEN_FILTERED,
            scan_results)
        threadpool = ThreadPool(num_threads)
        threadpool.map(guess_proto, open_or_filter)
        threadpool.close()
        threadpool.join()

    open_ports = filter(lambda res: res.status == OPEN or
                                    res.application_protocol != NO_PROTO,
                        scan_results)

    if show_all:
        print("\nScan results")
        for scan_result in scan_results:
            print(scan_result.format(verbose))
    else:
        print("\nOpen ports:")
        for scan_result in open_ports:
            print(scan_result.format(verbose))


# Функция main для парсинга аргументов командной строки и запуска сканирования портов
def main():
    parser = configure_parser()
    args = parser.parse_args()
    target_ip = args.target_ip
    ports = args.ports.split()
    timeout = args.timeout
    num_threads = args.num_threads
    verbose = args.verbose
    show = args.all
    guess = args.guess

    port_scan(target_ip, ports, timeout, num_threads, verbose, guess, show)


if __name__ == '__main__':
    main()
