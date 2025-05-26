SNIC: SNI-Concealing Anti-Censorship Proxy

# Problem Definition

## Internet Censorship

Internet censorship refers to the practice of controlling access to online content. Governments typically implement censorship by blocking access to websites they consider problematic. Motivations for such censorship range from legal enforcement to political agendas. Common techniques include DNS poisoning, IP address blocking, and SNI-based filtering. Among these, SNI-based filtering is a primary method used to block access to HTTPS-enabled websites. In this section, we discuss how SNI-based filtering works, review existing solutions to bypass it, and present our team’s goal of combating internet censorship.

## SNI-Based Filtering

Transport Layer Security (TLS) protocol allows client/server application to communicate over the Internet in a way that is designed to prevent eavesdropping, tampering, and message forgery [RFC8446]. TLS has become fundamental to the web, with most websites using HTTP over TLS (HTTPS).

While TLS provides confidentiality and integrity, it does not guarantee availability. The first message sent by a client, called `ClientHello`, is unencrypted and typically contains the Server Name Indication (SNI) field, which reveals the target server’s hostname. A censoring agent can inspect this field to identify the website the client is attempting to access and block it by dropping packets or sending TCP reset packets. This technique is known as SNI-based filtering.

<figure 1: How SNI-based filtering works>

SNI-based filtering is effective because traditional IP blocking has become less viable due to the widespread use of reverse proxies, CDNs, and hosting services. Websites using these services often share IP addresses, so blocking one IP may affect many unrelated websites. However, SNI is essential for establishing TLS connections on shared IPs, so TLS clients include the SNI field in `ClientHello` messages by default, making SNI-based filtering a powerful tool for censorship.

Due to its effectiveness, SNI-based filtering is deployed at the national level in countries such as South Korea, China, and Russia.

## Existing Solutions to Combat SNI-Based Filtering

### Tunneling

One of the most common methods to bypass censorship is to establish a secure tunnel to an uncensored network. Various protocols can be used for this purpose. OpenVPN and WireGuard are popular, but they are easily detectable and blocked in countries like China. TLS-based tunneling is harder to block due to its ubiquity. Additionally, there are protocols designed specifically for anti-censorship, such as Shadowsocks.

As anti-censorship tunneling protocols evolve, so do censorship detection mechanisms. For example, China employs active probing to discover Shadowsocks servers [gfw]. Machine learning techniques have also been used to detect TLS tunneling. In our research, we created several Shadowsocks servers and attempted to connect to them from within China, but they were immediately IP-banned.

Tunneling is also costly. It requires a server located outside the censored country, and both server operation and bandwidth incur significant expenses. Some anti-censorship VPN providers exist, but they tend to be expensive.

Despite these issues, tunneling remains an effective censorship circumvention method due to its ability to transmit arbitrary packets transparently from the application’s perspective, requiring no special configuration.

### Encrypted ClientHello

Encrypted ClientHello (ECH) is a mechanism for encrypting the `ClientHello` message using the preshared server public key [draft-ietf-tls-esni-24], proposed as an extension to TLS 1.3. The server provides a public key via DNS, which the client uses to encrypt sensitive information in the `ClientHello`, including the SNI.

However, ECH is not designed for anti-censorship, and its use is easily detectable, making it susceptible to blocking. China and Russia are known to block ECH-enabled `ClientHello` messages. Moreover, ECH standard is still a internet draft and thus is not widely supported. Enabling ECH also requires extra configuration: server administrator need to upload a pre-shared public key to DNS, which hinders adoption. Due to these limitations, ECH is not a practical solution against SNI-based filtering.

## Our Goal

Our goal is to design a solution to bypass SNI-based filtering that is both usable today and cost-effective. Tunneling is seamless but expensive, while ECH is inexpensive but currently unusable due to limited support and government blocking. We aim to develop a method that is compatible with existing websites and requires minimal operational cost.

# Motivation
Internet censorship is not merely about blocking specific websites; ultimately, it severely infringes on users' right to access information and their privacy. In modern society, the internet is not just a means of sharing information—it serves as essential infrastructure for the economy, politics, education, and social communication. However, some governments are restricting the openness of the internet and are continuously enhancing their censorship and surveillance technologies in increasingly sophisticated ways.
If this issue is not addressed, not only will the free accessibility of information on the internet continue to be threatened, but also censorship will further strengthen governmental control over information, reducing opportunities for social and political discourse. Moreover, as censorship technologies evolve, the shift toward a surveillance society is likely to accelerate, posing severe risks to personal privacy. Therefore, researching and developing censorship circumvention technologies is crucial to ensuring that users can access the internet freely and securely. By doing so, we can challenge the unjust nature of information censorship and contribute to building a more open and democratic internet environment.

# Methodology

## Background: QUIC & HTTP/3

QUIC is a relatively new transport protocol intended to replace TCP. Its primary aim is to make connections faster and more robust. Unlike TLS over TCP, which requires two round-trip times (RTTs) to establish a connection, QUIC can do so in one or zero RTTs by combining TLS and QUIC handshakes into a single packet.

QUIC is also resilient to changes in the underlying network. Although it runs over UDP, QUIC connections can survive changes in the client or server’s IP address or port number. This is achieved using connection IDs (CIDs). Migrating a connection from one path to another is called connection migration and can be either active or passive [quic-conn-migration].

* **Active migration** is initiated by the application layer. The initiator first validates the new path using probing packets before migrating. Server and client uses new set of CIDs to prevent network observer to associate different paths to the same connection.
* **Passive migration** is initiated by the lower layers such as UDP or IP.  requires no additional probing. Both peers continue using the same CIDs. Passive migration is usually initiated by NAT rebinding.

HTTP/3 is a new version of HTTP built on QUIC. It retains most of concepts established in HTTP/2: HTTP requests are encoded as binary rather than plaintext, and streams are used to multiplex multiple requests and responses. 

## QUICstep: Sending Initial Messages via a Secure Tunnel

QUICstep [quicstep] is a method to circumvent SNI-based filtering by exploiting QUIC's connection migration feature. It first establishes a connection through a secure tunnel, then migrates it to a direct path outside the tunnel. This process is illustrated in Figure 2.

<Figure 2>

QUICstep is cost-effective because only the initial handshake goes through the tunnel, reducing the load on the relay server. This is particularly advantageous for high-bandwidth activities like video streaming or large file transfers. However, its major drawback is limited compatibility: only about 30% of traffic is currently served via HTTP/3 [cloudflare-radar], and some websites block active migration due to complexity in network settings.

We propose two key modifications to improve QUICstep:

1. **Use of passive instead of active migration**, which is more widely supported: Google services, for example, allow it.
2. **Fallback mechanism**: our system first attempts QUICstep, then falls back to full tunneling after a timeout if unsupported. This significantly improves website compatibility at the cost of slight initial latency.

(Note: We independently developed the idea of QUICstep before discovering related existing research.)

## SNIC: An HTTPS Proxy Implementing QUICstep

Based on the above approach, we developed **SNIC**, an HTTPS proxy that implements QUICstep. SNIC runs a local HTTPS server, establishes TLS connections with clients using fake certificates generated from a self-signed root CA, and fetches resources from the destination server using QUICstep or through tunnel. It then relays the response to the client. SNIC assumes a secure tunnel exists and is accessible via the SOCKS5 protocol. Figure 3 shows the system architecture of SNIC.

<Figure 3>

# Demonstration & Evaluation

We evaluated SNIC in two settings to assess usability and cost-effectiveness.

First, to test usability under high censorship, we ran SNIC in a virtual machine (VM) located in mainland China and attempted to access a blocked website. A second VM, acting as a relay server, was hosted in Hong Kong. We used v2ray [v2ray] to create a secure tunnel through the Great Firewall. Using SNIC, we successfully loaded `www.theguardian.com` via QUICstep.

Second, to test cost-effectiveness, we compared data sent and received with and without tunnel respectively. In a 10-minute YouTube session:

* Through SNIC's tunnel: 491 KB sent, 1 MB received
* Without SNIC (direct): 2 MB sent, 303 MB received

This shows SNIC significantly reduces the relay server’s data load, lowering operational costs.

# Contribution


