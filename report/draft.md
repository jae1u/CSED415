title: SNIC: SNI-Concealing Anti-Censorship Proxy

# Problem Definition

## Internet Censorship

Internet censorship is an act of controlling access to contents on internet. Usually this is done by blocking access to certain website that is deemed problemetic by governments; movitations behind internet censorship ranges from legal enforcement to political intentions. Methods that are commonly utilized by government or censorship agent include DNS poisoning, IP address blocking, and SNI-based filtering. Among these, SNI-based filtering is a primary method to block access to HTTPS-enabled websites. In this section, we first discuss how SNI-based filtering works, and review existing solution to bypass it. After that, we present our team's goal to comabt against internet censorship.

## SNI-based filtering

Transport Layer Security (TLS) protocol allows client/server application to communicate over the Internet in a way that is designed to prevent eavesdropping, tampering, and message forgery [RFC8446]. TLS has become a fundamental protocol of World Wide Web such that most of the websites communicates using HTTP over TLS (HTTPS).

While TLS provides confidentiality and integrity of communication, it does not guarantee availability. The first packet sent by a client, ClientHello, is unencrypted, and usually contains Server Name Indicator (SNI) field that indicates hostname of the server. A middleman thus can identify to which website the ClientHello is destined to, and if that website should be blocked, it can drop the packet or send TCP reset packet to server or client. This technique of inspecing SNI to block access to certain websites is called SNI-based filtering.

<figure 1: how SNI-based filtering>

SNI-based filtering has become effective method to implement censorship. IP address blocking, a traditional way to block access to website, is losing its effectiveness due to widespread use of reverse proxy, CDN and website hosting service. Website that utilize such services share same IP address with many other websites, so blocking that IP address might cause innocent websites to be blocked. But SNI is essential for websites sharing IP to establish TLS connection with client, so TLS clients includes SNI to ClientHello by default. This makes SNI-based filtering very effective in blocking HTTPS-based websites.

Due to its effectiveness, SNI-based filtering is currently utilized in national level by countires such as South Korea, China, and Russia. 

## Existing Solution to Combat SNI-Based Filtering

### Tunneling
One of the most widespread ways to bypass censorship is to create a secure tunnel to a network without censorship in action. Various protocols can be used to create a secure tunnel. OpenVPN and WireGuard are widely used, but they are easily detectable and in countries such as China they are blocked altogether. To mitigate this, one can utilize TLS as a tunneling protocol, which is too popular to block. Also, there exists protocols specifically designed to bypass censorship, with shadowsocks being the prominent example.

Along with development of anti-censorship tunneling protocols, detection mechanism are also evolving. China government utilizes active probing to discover shadowsocks servers [gfw]. Also, there are evidences that it can also detect TLS used as a tunneling protocol by using machine learning to classify protocols. In our research, we created a few shadowsocks server then tried to connect to those servers inside China, but they got instantly banned.

Another problem is that it often requires high cost. To create a tunnel, a server outside country is required and cost of operating server and network traffic is not cheap. Anti-censorship VPN providers exists but they demand quite high prices.

Despite these problems, tunneling is still a effective method in bypassing censorship due to its ability to send and receive arbitrary packets. It works transparently when viewed from application's perspective, so they don't need special settings to work with tunneled network.

### Encrypted ClientHello
Encrypted ClientHello is a mechanism for encrypting a ClientHello message under a server public key [draft-ietf-tls-esni-24], proposed as a extension of TLS version 1.3. The server provides public key using DNS record, with which client can encrypt sensitive informations in ClientHello message, including SNI. But this mechanism is not designed to bypass censorship so the fact that ClientHello uses ECH is easily detectable and thus can be blocked. Currently, China and Russia are known to block ECH-enabled ClientHello messages. Also, ECH is currently a draft so most websites does not support this mechanism. Furthurmore, websites need additional configurations to enable ECH: pre-shared public key needs to be uploaded to DNS servers. Because of this problems, ECH is not a viable solution to SNI-based filtering.

## Our Goal
Our first goal is to design a method to bypass SNI-based filtering that is both currently usable and economically feasible. Creating a tunnel works seamlessly but is economically demanding; on the other hand, ECH does not require additional cost but is not currently usable due to incompatibility with most websites and blockage in some countries. We strive to develop method that is compatible with existing websites and does not require a lot of money to operate. 

# Motivation

...

# Methodology

## Background: QUIC & HTTPS/3

QUIC protocol is a relatively new transport layer protocol that aims to replace Transport Layer Control (TCP) protocol. QUIC's primary goal is to make connections more faster and robust. QUIC requires one or zero RTT (round-trip time) to establish connection, while TLS over TCP requires two RTTs. This is achieved by combining both TLS and QUIC handshake messages in a same packet.

QUIC connection is also robust to changes in underlying network environments. QUI builds on UDP (user datagram protocol) over IP, but QUIC connection can be maintained even if client or server's IP address or UDP port number changes. To accomplish this, QUIC identifies each packet using connection ID (CID). A procedure of migrating endpoints of either client or server is called connection migration. Connection migration can be divided into active and passive connection migration according to different initiators [quic-conn-migration]. Active connection migration is initiated by the application layer. The peer that initiates active connection migration first validates new network path by sending probing packets then migrates connection to the new path. Server and client uses different set of CIDs to prevent network observer to associate different paths to the same connection. Passive connection migration is initiated by lower layers such as UDP or IP; server and client does not (actually can't) send additional probing packet. Both peer uses same CIDs to maintain connection across different network paths.

HTTP/3 is a new version of HTTP protocol that builds on QUIC. It does not differ greatly from previous version of HTTP protocol, HTTP/2. Client sends request message to server once QUIC connection is established, and server responds to it with data of requested resource.

## QUICstep: sending initial message via a secure tunnel
QUICstep [quicstep] is a method to circumvent SNI-based filtering by utilizing QUIC connection migration. It establishes connection to server over secure tunnel, then migrates connection to path that is outside of tunnel. These steps are outlined in Figure 2.

QUICstep is cost-effective in the sense that only handshake messages are sent through tunnel, which alleviates computation and network load of relay server. It is especially effective when large amount of data are transmitted over network, such as multimedia or large bulk file. But one of its weak point is that it's not widely supported by websites. For QUICstep to work, web server needs to support HTTP/3 but support for the protocol is not widespread; currently around 30% of traffics are served using HTTP/3 while adoptation [cloudflare-radar] rate has been increasing over time. Also, some websites forbids active connection migration due to complexity involved in network settings. 

We proposes a few modification on original work to imporve its weakness. First, our method uses passive connection migration rather than active connection migration. We found that support for passive connection migration is larger than active connection migration; google services being the most prominent example. Secondly, we chose to use QUICstep optionally by first trying QUICstep then falling back to communicate over tunnel by using timeout. This significantly improves websites that can be accessed while initial latency slightly increases if website does not support QUICstep. 

(NOTE: we came up with idea of QUICstep without knowing that the reasearch on same idea exists.)

## SNIC: a HTTPS proxy implementing QUICstep
Based on the method discussed above, we built SNIC, a concrete implementation of QUICstep as a form of HTTPS proxy. SNIC opens a local web server that accepts HTTPS request. It establishes TLS connection with client by impersonating as an actual web server by generating fake TLS certificate using self-signed root CA certificate. On the other side, it fetches requested resource from the server by using QUICstep method then returns response back to client. It assumes secure tunnel exists and can be accessed using SOCKS5 protocol. Design of SNIC is presented at Figure 3.

# Demonstration & Evaluation
We evaluated SNIC on two different environments to test its usability and cost effectiveness respectively.

First, we evaluated usability of SNIC in a high-censorship setting by running it in VM in mainland China and trying to connect to blocked website. We create another VM acting as a relay server in Hong Kong and used v2ray [v2ray] to create a secure tunnel over the great firewall of China. We were able to successfully load `www.theguardian.com` by using QUICstep method. 

<사진 1: the guardian 로드 성공>

Next, we evaluated cost effectiveness of SNIC by measuring total bytes sent and received with and without proxy respectively. In a setting where a user watched a 10-minute video on `www.youtube.com`, SNIC sent and received 491KB and 1MB of data through tunnel while it sent and received 2MB and 303MB of data without tunnel. This demonstrates that SNIC can be helpful in reducing cost of running relay server in real world settings.

# Contribution
...

[RFC8446] https://datatracker.ietf.org/doc/html/rfc8446

[gfw] https://dl.acm.org/doi/10.5555/3620237.3620386

[RFC9000]

[quic-conn-migration] https://datatracker.ietf.org/doc/html/draft-tan-quic-connection-migration-00

[quicstep] https://arxiv.org/abs/2304.01073


[draft-ietf-tls-esni-24] https://www.ietf.org/archive/id/draft-ietf-tls-esni-24.html

[cloudflare-radar] https://radar.cloudflare.com/adoption-and-usage

[v2ray] https://github.com/v2ray/v2ray-core