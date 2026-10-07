### Changed

- Each peer now writes its datagrams to the UDP socket from a separate sender
  process, so the send no longer runs in the process that encrypts. Bulk TCP
  uploads through a tunnel are faster: about 15–20% over gigabit Ethernet from
  macOS, where the send itself is the limit, and about 55–75% on Linux. The
  sender and the peer run under one supervisor for each peer, and they stop
  together.
