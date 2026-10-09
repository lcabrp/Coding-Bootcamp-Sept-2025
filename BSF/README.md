# Network Traffic Analyzer (Pure Python)

Capstone project for the Coding Bootcamp for Cybersecurity (The Cyber Instructor) by Samuel Ajakaiye.

A command-line tool that reads a packet capture (`.pcap`) and reports who is talking to whom, which ports are busiest, and two kinds of suspicious traffic. It parses the Ethernet, IPv4, TCP and UDP headers by hand using Python's `struct` module, so it needs no packet library.

## What it reports

- **Top talkers:** the busiest source → destination IP pairs
- **Top destination ports** for TCP and UDP
- **High-volume connections:** pairs with more than 100 packets
- **Average packet rate** across the capture
- **Alerts**
  - `DoS_Suspicion`: one source sending more than 500 packets per minute (judged on at least 20 packets, one alert per source)
  - `Unencrypted_Creds`: an HTTP `Authorization: Basic` header sent in clear text, with the username decoded

## Run it

Requires Python 3.8 or later. `pandas` is optional and only needed for `--csv`.

```bash
# Demo mode: generates dummy.pcap with sample HTTP traffic and analyzes it
python "python traffic_analyzer.py"

# Analyze your own capture and also write CSV and HTML reports
python "python traffic_analyzer.py" -f capture.pcap -o report.json --csv --html
```

Outputs: `report.json`, plus `talkers.csv` and `ports.csv` with `--csv`, and `report.html` with `--html`.

To capture traffic to test with: `sudo tcpdump -i eth0 -w capture.pcap`. Wireshark saves `.pcapng` by default; convert with `editcap -F pcap in.pcapng out.pcap`.

## Parsing details

- Classic pcap in either byte order, with microsecond or nanosecond timestamps
- Ethernet link type only; 802.1Q and QinQ VLAN tags are skipped
- IPv4 only; Ethernet padding is trimmed using the IP total length
- Only the first IP fragment is read for ports, since later fragments carry no TCP/UDP header
- The TCP header length comes from the data offset field, so packets with TCP options are read correctly
- Text taken from packets is HTML-escaped in `report.html`, because capture data is untrusted

## Limitations

- No IPv6 and no pcapng
- Credentials are only found when the HTTP header sits in a single TCP segment (no stream reassembly)
- Thresholds are constants at the top of the script (`DOS_RATE_THRESHOLD`, `DOS_MIN_PACKETS`)
