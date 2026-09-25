# Wagyu

Wagyu is a user-mode WireGuard endpoint for SmolNet application sockets. The
design and implementation order are tracked in
https://github.com/ausimian/wagyu/issues/2. So far configuration validation,
the wire-format building blocks, the supervised interface (UDP socket,
SmolNet stack and link, bounded admission), peer-owned handshakes with key
confirmation, the encrypted data path, WireGuard's retry, rekey,
keepalive and key-expiry timers, and cookie replies with MAC2 under load
exist.

## Development

- Use Elixir 1.19.5 with Erlang/OTP 28.3 locally.
- Run `mix precommit` before committing. The wireguard-go interop tests in
  it need Go on the `PATH` (see MAINTAINING.md); without Go they are skipped.
- Keep `@version` in `mix.exs` as the single source of truth.
- Add user-visible release notes to `RELEASE.md` using Keep a Changelog sections.
- Publish public releases to Hex.pm with `mix publisho <level>` when ready.
