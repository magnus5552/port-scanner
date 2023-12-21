# Port Scanner

## Usage

```
portscan.py [-h] [--timeout TIMEOUT] [-j NUM_THREADS] [-v] [-a] [-g] target_ip ports

positional arguments:
  target_ip             Target IP address
  ports                 Ports to scan (e.g. "tcp/80 tcp/12000-12500 udp/3000-3100,3200,3300-4000")

options:
  -h, --help            show this help message and exit
  --timeout TIMEOUT     Timeout for response (default: 2s)
  -j NUM_THREADS, --num-threads NUM_THREADS
                        Number of threads (default: 1)
  -v, --verbose         Verbose mode
  target_ip             Target IP address
  ports                 Ports to scan (e.g. "tcp/80 tcp/12000-12500 udp/3000-3100,3200,3300-4000")
```