**Objective**

Capture and analyze the same Nmap scan performed in Lab 04 but from the network level, using Wireshark for
packet-level inspection and Zeek for automated, structured traffic summarization. This closes the gap
demonstrated in Lab 04, where neither the Windows Security Log nor Sysmon detected the scan at all.

**Lab Environment**

Capture host: Kali Linux - 192.168.11.10

Target: Windows 10 - 192.168.11.20

Tools: Wireshark (pre-installed on Kali), Zeek (installed via official openSUSE-hosted repo)

**Methodology**

1. Installed Wireshark (pre-installed) and Zeek (via Zeek's official repo after Kali's default package did
   not work with current version of the system's libc6).

2. Performed nmap -sV scan on Windows VM, the same scan investigated via firewall logs in lab04.

3. Used Wireshark display filters (_tcp.flags.syn==1 && tcp.flags.ack==0_ then _tcp.flags.syn==1 && tcp.flags.ack==1_)
   on the open port 5357.

4. Used "Follow TCP Stream" on port 5357 exchange and learned that the -sV option in Nmap really makes an
   application-layer interaction, not just a port-open check by sending a real GET/HTTP/1.0 request and receiving
   an HTTP 503 error.

5. Measured and explained the timing difference between scanned ports: where instant rejection/silence for
   closed/filtered ports versus HTTP exchange with port 5357 took several seconds because it interacts with
   real application to process and respond back.

6. Save the capture file and re-analyzed it using Zeek with _zeek -r_ comparing its conn.log and http.log
   files.

7. Since it's hard to read the columns from log files, I used zeek-cut to extract the specific columns
   from zeek logs.
   
8. Identified the exact connection for HTTP exchange via its resp_bytes value (490, versus 0 for all non-
   HTTP probe attempts) and verified zeek's precise duration (5.02 seconds).

**Key Findings**

1. nmap -sV performs real application-layer interaction not just a TCP handshake - HTTP error response (503)
   can give some fingerprinting information via response headers, which is why banner suppression is a
   legitimate hardening practice.

2. Network-layer rejection works faster than application-layer interaction - closed/filtered ports resolve
   within microseconds while the open port took over 5 seconds (verified via Zeek duration field), because
   a real service had to receive, process, and respond.

3. Zeek's conn_state field is the actual fingerprint of behaviors - RSTO (originator sent reset) vs SF
   (standard FIN teardown) can indicate automated/scanning tool behavior, as good clients would follow
   the standard connection termination with FIN.

4. Packet capture is the only data source which cannot be faked or overlooked in host-based logging -
   resolving the visibility gap identified in Lab04, where Sysmon and Windows Security logs showed nothing
   for this same scan.

**Skills Demonstrated**

Wireshark live packet capture. TCP stream reconstruction. Zeek installation and structured log analysis. 
_zeek-cut_ field extraction. distinguishing network-layer from application-layer behavior. connecting 
findings across three independent data sources (firewall log, packet capture, Zeek summary) investigating
the same event.

_Screenshots are also available in this file_

_This lab is entirely hands-on using real traffic generated and captured in my own lab environment - no
provided case study was used._
