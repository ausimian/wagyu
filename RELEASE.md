### Changed

- Each peer now runs as three processes. The peer runs the handshakes and the
  timers, and decrypts inbound packets. A sealer encrypts outbound packets. A
  sender writes the datagrams to the UDP socket. The three processes run under
  one supervisor for each peer, and they stop together. Bulk TCP through a
  tunnel is faster: on Linux, with a kernel WireGuard peer, about 30–50% for
  downloads and 40–90% for uploads. Over gigabit Ethernet from macOS, where
  the UDP send itself is the limit, uploads are about 15–20% faster.
- Each peer now queues up to 512 inbound packets or 1 MiB, not 128 packets or
  256 KiB. A kernel WireGuard peer sends in bursts that the smaller queue could
  not hold. During a bulk download, the interface refused up to 1.5% of the
  packets, and TCP stalled until it retransmitted them. The outbound queue and
  the queue of packets that wait for a key stay at 128 packets or 256 KiB.
