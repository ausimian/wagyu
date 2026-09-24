# Wagyu

Wagyu is a user-mode WireGuard endpoint for SmolNet application sockets. The
design and implementation order are tracked in
https://github.com/ausimian/wagyu/issues/2. So far only configuration
validation and the wire-format building blocks exist; the running interface
does not.

## Development

- Use Elixir 1.19.5 with Erlang/OTP 28.3 locally.
- Run `mix precommit` before committing.
- Keep `@version` in `mix.exs` as the single source of truth.
- Add user-visible release notes to `RELEASE.md` using Keep a Changelog sections.
- Publish public releases to Hex.pm with `mix publisho <level>` when ready.
