### Changed

- Each peer now writes its datagrams to the UDP socket from a separate sender
  process, so the send no longer runs in the process that encrypts. Bulk TCP
  uploads through a tunnel are faster: about 15–20% over gigabit Ethernet from
  macOS, where the send itself is the limit, and about 55–75% on Linux. The
  sender and the peer run under one supervisor for each peer, and they stop
  together.
- Each peer now queues up to 512 inbound packets or 1 MiB, not 128 packets or
  256 KiB. A kernel WireGuard peer sends in bursts that the smaller queue could
  not hold. During a bulk download, the interface refused up to 1.5% of the
  packets, and TCP stalled until it retransmitted them. The outbound queue and
  the queue of packets that wait for a key stay at 128 packets or 256 KiB.
