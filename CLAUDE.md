# Wagyu

Wagyu is a user-mode WireGuard endpoint for `:gen_tcp` and `:gen_udp` sockets.
It runs the sockets on SmolNet, a userspace TCP/IP stack. Thus it does not need
a TUN device. https://github.com/ausimian/wagyu/issues/2 records the design,
the implementation sequence and the progress. The issue for each step is the
specification for that step.

## Development

MAINTAINING.md describes the toolchain, the checks, the interop tests, the
benchmarks and the release procedure. The main rules are:

- Use Elixir 1.19.5 with Erlang/OTP 28.3 on your machine.
- Run `mix precommit` before you commit. Its wireguard-go interop tests need
  Go on the `PATH`. If Go is not on the `PATH`, these tests do not run.
- Keep `@version` in `mix.exs` as the single source of truth.
- Add release notes that users can see to `RELEASE.md`. Use Keep a Changelog
  sections.
