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
