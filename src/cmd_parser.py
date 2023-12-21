import argparse


def configure_parser():
    parser = argparse.ArgumentParser(description='Port scanning utility')
    parser.add_argument('target_ip', type=str, help='Target IP address')
    parser.add_argument('ports', type=str,
                        help='Ports to scan (e.g. "tcp/80 tcp/12000-12500 udp/3000-3100,3200,3300-4000")')
    parser.add_argument('--timeout', type=int, default=2,
                        help='Timeout for response (default: 2s)')
    parser.add_argument('-j', '--num-threads', type=int, default=1,
                        help='Number of threads (default: 1)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose mode')
    parser.add_argument('-a', '--all', action='store_true',
                        default=False, help='Show all ports')
    parser.add_argument('-g', '--guess', action='store_true',
                        default=False, help='Guess application layer protocol')
    return parser
