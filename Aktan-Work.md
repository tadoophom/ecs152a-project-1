# ECS 152A Project 1 – Working Notes

## Part 1(a) – Questions 3 & 4

### Q3. Destination IP addresses and first-observed timestamps
Captured packets include campus DNS/gateway chatter, so the table focuses on the external destinations that carried the activity traffic (IPv4 only, timestamps in UTC from the capture).

| Activity | Destination IP | First packet | Notes |
| --- | --- | --- | --- |
| Ping google.com | 142.250.189.206 | 2025-10-21T21:23:23.159701Z | `sfo03s25-in-f14.1e100.net` – Google ICMP echo target. |
|  | 162.159.135.234 | 2025-10-21T21:23:23.441497Z | Cloudflare address hit by additional echo requests from the OS. |
| Visit https://example.com | 23.220.75.232 | 2025-10-21T22:08:26.323556Z | `a23-220-75-232.deploy.static.akamaitechnologies.com` – Akamai edge serving example.com. |
|  | 142.250.189.202 | 2025-10-21T22:08:25.460931Z | Google CDNs contacted for ancillary assets (Chrome prefetch). |
| Visit http://httpforever.com | 146.190.62.39 | 2025-10-21T22:09:02.141485Z | Primary HTTP server for httpforever.com (DigitalOcean). |
|  | 23.222.206.145 | 2025-10-21T22:09:10.315932Z | Akamai CDN host fetched by the page. |
| Visit https://www.tmz.com | 3.169.183.125 | 2025-10-21T22:09:33.736467Z | CloudFront edge delivering tmz.com. |
|  | 35.186.224.24 | 2025-10-21T22:09:34.745926Z | Google Cloud asset domain referenced by TMZ. |
|  | 57.144.220.192 | 2025-10-21T22:09:34.404965Z | Fastly edge carrying TMZ media resources. |
| FTP ftp.gnu.org | 209.51.188.20 | 2025-10-21T21:28:20.825205Z | `ftp.gnu.org` – anonymous FTP control/data connection. |
| SSH into CSIF | 169.237.240.10 | 2025-10-21T21:30:36.139693Z | `vpn.library.ucdavis.edu` – target of the SSH session. |

_(Campus resolver/gateway chatter such as `168.150.108.232` and local multicast `224.0.0.251` was observed but omitted because they are supporting infrastructure rather than external activity endpoints.)_

### Q4. Browser identification from captures
- **Activity 2 (example.com, HTTPS)** – Packets are TLS on port 443; the HTTP request headers (and therefore the `User-Agent`) are encrypted, so the browser cannot be identified from this capture alone.
- **Activity 3 (httpforever.com, HTTP)** – Plain-text GET requests include `User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36`, revealing the browser as Chrome 141 on macOS.
- **Activity 4 (tmz.com, HTTPS)** – Like activity 2, only TLS handshakes are visible, so the browser cannot be determined without decrypting the session.

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

Script fragment used to locate the leak:

Implementation reference: `analyze_pcap1_1.py`. Running it prints:

```
----- Secret-bearing HTTP request -----
Timestamp    : 2025-10-15T01:00:58.200875+00:00
Client -> Server: 2601:204:c200:a930:4d70:f5b6:e2e8:ac72 -> 2600:1408:ec00:36::1736:7f31
Request line : GET /?secret=secret1
Header       : my-secret: Zubair Rocks!!
```