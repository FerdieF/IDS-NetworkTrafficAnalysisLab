# IDS & Network Traffic Analysis Lab

Hands-on lab for understanding how network traffics seen on packet level, how Suricata (IDS) recorded and detected the traffics. The focus was not on exploit, but reading traffics and alerts as investigator: From raw packets in wireshark/tcpdump to log in Suricata

> **Catatan:** The whole activities done in VM (Host-Only Adapter). Do not scan to your network or device.
---

## Goals 

- Understanding the network flow: IP → ARP → MAC → Ethernet Frame → ICMP/TCP.
- Identifying the characteristics of port scan traffic (Nmap) at the packet level.
- Running Suricata as an IDS and analyzing its output (`eve.json`, `fast.log`).
- Correlating **Suricata alerts** with the **original packets in Wireshark**.
- Developing an investigator mindset: *Who? What? When? How?* before drawing conclusions.


## Lab Topology

```
            Host-Only Network (192.168.56.0/24)
                         |
      +------------------+------------------+
      |                  |                  |
    Kali              Windows 11        DHCP Server
 (attacker)           (victim)
 192.168.56.103     192.168.56.104     192.168.56.100
      |
      |  traffic on eth0
      v
 Wireshark / tcpdump  ->  Suricata  ->  Alerts + Logs
```

| Host | IP | Peran |
|------|----|-------|
| Kali Linux | `192.168.56.103` (eth0) | Generate traffic, packet capture, run Suricata |
| Windows 11 | `192.168.56.104` | Target scan |
| DHCP server | `192.168.56.100` | Configuring IP Settings on Kali |

Kali also has `eth1` (NAT, `10.0.3.15/24`), but all analysis focuses on `eth0`.

## Tools & Version

| Tool | Function |
|------|--------|
| Kali Linux | Analysis engine and traffic source |
| Windows 11 | Target/victim |
| `tcpdump` | View packets via CLI |
| Wireshark | In-depth packet analysis |
| Nmap 7.99 | Generates traffic scans |
| Suricata 8.0.6 | IDS: matches traffic against signatures |
| suricata-update 1.3.8 | Downloads/updates ruleset (52,995 rules loaded, 0 failed) |

---

## Lab Content

### 1. Baseline Network Traffic
- Capture `ping` requests from Kali to Windows using `tcpdump` and Wireshark (filter `icmp`): 4 Echo Requests + 4 Echo Replies (ICMP Type 8 / Code 0, sequence number increases).
- Understand the relationship between IP, ARP, MAC, and Ethernet frames (ARP may not appear if the MAC is already in the neighbor cache).

### 2. Nmap Scanning
- `nmap -sT 192.168.56.104` initially returned *“Host seems down”* even though `ping` succeeded, because Nmap’s host discovery failed. The solution is to use `-Pn` (skip host discovery): `nmap -Pn -sT 192.168.56.104`.
- In Wireshark, it’s visible that Kali is sending **TCP SYN** packets to many different ports on Windows.
- There are no `SYN, ACK` (open) or `RST, ACK` (closed) responses. Conclusion: it’s highly likely that **Windows Firewall is dropping the packets**, so Kali receives no response at all.

### 3. Suricata as an IDS
- Installation, rule updates (`suricata-update`), configuration validation (`suricata -T`), and running Suricata on `eth0`.
- Generated logs: `eve.json`, `fast.log`, `stats.log`, `suricata.log`.
- Nmap traffic **is recorded as a flow** in `eve.json` (`syn: true`, `state: syn_sent`, `pkts_toclient: 0`, `alerted: false`), but **does not generate an alert**. The active ruleset does not have a port scan signature that matches this pattern.

### 4. Alert Investigation: Kali Hostname in DHCP
- The only alert that appeared: `ET INFO Possible Kali Linux hostname in DHCP Request Packet` (SID `2022973`, `192.168.56.103:68 -> 192.168.56.100:67`, action `allowed`).
- Correlated with Wireshark: The DHCP Request carries Option 12 *Host Name* = `kali`, which triggered the signature.
- Analyzed a single DHCP conversation (Discover → Offer → Request → ACK) and correlated the Request with the ACK using the **Transaction ID**, **Client MAC**, and **Client IP**.

---

## Key Findings

1. **An IDS is not a packet capture tool.** Suricata monitors all traffic but only generates alerts when a rule is matched.
2. **`0 alerts` ≠ `0 traffic`, and `0 alerts` ≠ “secure network”.** Nmap scans appear in the flow logs even if no alerts are generated.
3. **Informational alerts do not necessarily indicate an attack.** The alert for the Kali hostname in DHCP is normal in the context of this lab; there is no evidence of an attack from that packet.
4. **General port scan pattern:** one source host → one destination host → multiple destination ports → SYN with no response.
5. **The absence of a response can have many causes,** one of which is a firewall dropping the packet.

## How to Reproduce

```bash
# 1. Check the interface and network
ip a && ip route

# 2. Baseline traffic
sudo tcpdump -i eth0 -n
ping -c 4 192.168.56.104

# 3. Install and set up Suricata
sudo apt update && sudo apt install suricata
sudo suricata-update
sudo suricata -T -c /etc/suricata/suricata.yaml

# 4. Run Suricata (terminal 1)
sudo suricata -i eth0 -c /etc/suricata/suricata.yaml

# 5. Generate traffic (terminal 2)
ping -c 4 192.168.56.104
nmap -Pn -sT -p 1-1000 192.168.56.104

# 6. Stop Suricata (Ctrl+C), then check the results
sudo tail -n 20 /var/log/suricata/fast.log
sudo grep '"event_type":"alert"' /var/log/suricata/eve.json | tail -n 10
sudo grep '"event_type":"flow"' /var/log/suricata/eve.json | grep '192.168.56.104' | tail -n 10
```

To trigger a DHCP refresh (NetworkManager):

```bash
nmcli connection show
sudo nmcli connection down "<NAMA_CONNECTION>"
sudo nmcli connection up "<NAMA_CONNECTION>"
```

Wireshark filters Used: `icmp`, `tcp && ip.addr == 192.168.56.104`, `tcp.port == <port>`, `dhcp` / `bootp`.
## Skill yang Dilatih

`Packet analysis` · `TCP/IP fundamentals` · `Network scanning (Nmap)` · `IDS (Suricata)` · `Log analysis (eve.json)` · `Alert triage & correlation`
