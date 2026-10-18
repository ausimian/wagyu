### Added

- The `:receive_buffer` option sets the size of the receive buffer of the
  UDP socket. If the OS gives a smaller buffer than the option, the
  interface logs a warning. `Wagyu.info/1` gives the size that the OS
  reports, as `:receive_buffer`.

### Changed

- By default, the interface now requests the largest receive buffer that
  the OS allows for its UDP socket, not 1 MiB. When this buffer is full, the
  kernel drops inbound datagrams, and `Wagyu.info/1` does not count them.
  On Linux with the default `net.core.rmem_max` (212,992 bytes), the buffer
  does not change, because Linux limited the 1 MiB request to the same size.
  The `Wagyu` module documentation tells how to raise this limit. On macOS,
  the buffer increases from 1 MiB to 8 MiB.
- Each peer now runs as four processes. A new opener process decrypts inbound
  packets and gives them to the stack, so the peer process runs only the
  handshakes and the timers, and holds no transport keys. The sealer still
  encrypts outbound packets, and the sender still writes the datagrams to the
  UDP socket. The four processes run under one supervisor for each peer, and
  they stop together.
- Wagyu now requires Decibel 1.4, which can move both directions of a transport
  session to other processes.
