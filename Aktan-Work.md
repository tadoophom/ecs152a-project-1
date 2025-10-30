# ECS 152A Project 1 – Working Notes

## Part 1(a) – Questions 3 & 4

### Q3. Destination IP addresses and first packets

| Activity | Destination IP | First packet (UTC) |
| --- | --- | --- |
| Ping google.com | 142.250.189.206 | 2025-10-21T21:23:23.159701Z |
| Visit example.com | 23.220.75.232 | 2025-10-21T22:08:26.486174Z |
| Visit httpforever.com | 146.190.62.39 | 2025-10-21T22:09:02.141485Z |
| Visit tmz.com | 3.169.183.125 | 2025-10-21T22:09:33.736467Z |
| FTP anonymous login | 209.51.188.20 | 2025-10-21T21:28:20.825205Z |
| FTP (no login) | 209.51.188.20 | 2025-10-21T21:27:54.820943Z |
| SSH session | 169.237.240.10 | 2025-10-21T21:30:36.139693Z |

_Assumption:_ I list only the first external IPv4 destination that actually carried each activity’s payload; supporting infrastructure (campus DNS, local gateways, multicast chatter) appears in the captures but is excluded because the prompt asks for the activity destinations.

### Q4. Browser identification from captures
- Activity 2 (example.com, HTTPS): TLS hides the headers, so the browser cannot be identified.
- Activity 3 (httpforever.com, HTTP): `User-Agent` shows Chrome 141 on macOS.
- Activity 4 (tmz.com, HTTPS): TLS hides the headers, so the browser cannot be identified.

_Assumption:_ Browser identification depends entirely on clear-text `User-Agent` strings; for encrypted TLS traffic I assume no session keys are available, so the browser stays unknown.

## Part 1(b) – PCAP1_1 Analysis
Using `dpkt` to scan `PCAP1_1.pcap` for clear-text application data shows one HTTP GET request carrying obvious secrets:

```
GET /?secret=secret1 HTTP/1.1
Host: example.com
User-Agent: test-client/2
MY-SECRET: Zubair Rocks!!
```

Key findings:
- The client exposed the query parameter `secret=secret1` directly in the URL.
- A custom header `MY-SECRET` leaked the phrase **“Zubair Rocks!!”**, constituting another secret sent to the server.
- Request originated from the client to `example.com` over HTTP (unencrypted), so anyone capturing the traffic can read these secrets.

Implementation reference: `analyze_pcap1_1.py`. Running it prints:

```
----- Secret-bearing HTTP request -----
Timestamp    : 2025-10-15T01:00:58.200875+00:00
Client -> Server: 2601:204:c200:a930:4d70:f5b6:e2e8:ac72 -> 2600:1408:ec00:36::1736:7f31
Request line : GET /?secret=secret1
Header       : my-secret: Zubair Rocks!!
```
