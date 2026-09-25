# Maintaining Wagyu

Notes for working on Wagyu itself. If you want to use Wagyu, see the
[README](README.md).

## Toolchain

- Elixir 1.19.5 and Erlang/OTP 28.3, pinned in `.tool-versions`. The project
  supports Elixir 1.18 and newer on compatible OTP releases, and CI covers
  that range.
- Go 1.25 or later for the interop tests. This is optional locally; see
  [Interop tests](#interop-tests).

## Checks

```sh
mix deps.get
mix precommit
```

Run `mix precommit` before every commit. It runs in the test environment and
performs, in order:

1. `compile --warnings-as-errors`
2. `deps.unlock --unused`, which removes unused entries from `mix.lock`
3. `format`, which rewrites any unformatted files
4. `credo --strict`
5. `test`

Run the whole alias rather than picking individual steps, so none is missed.
Because `deps.unlock` and `format` rewrite files, review the working tree
before committing.

## Interop tests

The tests tagged `interop` run Wagyu against
[wireguard-go](https://git.zx2c4.com/wireguard-go) on its userspace network
stack (`tun/netstack`), which needs no TUN device or root. They build a small
Go helper in `test/interop`, pinned by its own `go.mod` and `go.sum`. The
helper runs a wireguard-go peer, with TCP and UDP echo servers and a TCP
sink on its netstack and an optional delay on the datagrams it sends. Its
`vectors` command prints a fixed-key handshake transcript that a golden test
compares byte for byte.

- With `go` on the `PATH`, `mix test` and `mix precommit` run them.
- Without `go`, they are skipped.
- `WAGYU_INTEROP=1` turns a missing `go` into an error instead of a skip. CI
  sets it.
- `mix test --exclude interop` skips them regardless.
- One of them measures single-stream TCP throughput over a simulated 50 ms
  round trip, against a loose floor. `WAGYU_THROUGHPUT=1` prints the rate it
  measured.

## CI

`.github/workflows/ci.yml` runs on pushes to `main` and on pull requests. It
runs `mix precommit` on Linux and macOS for each of these Elixir/OTP pairs:
1.20/29, 1.20/28, 1.20/27, 1.19/28, 1.19/27 and 1.18/27. It installs Go from
`test/interop/go.mod` and sets `WAGYU_INTEROP=1`, so every job runs the interop
tests.

## Design and roadmap

The architecture, protocol decisions and implementation order are in the
tracking issue [#2](https://github.com/ausimian/wagyu/issues/2). Each step has
its own issue linked from there, and its body is the spec for that work.

## Making changes

- Work on a branch and merge through a pull request. Don't commit directly to
  `main`.
- Write commit messages as [Conventional Commits](https://www.conventionalcommits.org/).
- Add user-visible changes to `RELEASE.md` under Keep a Changelog headings
  (`### Added`, `### Changed`, `### Fixed`, and so on). These notes become the
  next release's `CHANGELOG.md` entry.

## Releasing

Wagyu has not been released, and there is no release workflow yet.

`@version` in `mix.exs` is the single source of truth for the version.
Releases use [Publisho](https://hex.pm/packages/publisho):
`mix publisho <level>` updates `@version`, moves the `RELEASE.md` notes into
`CHANGELOG.md` at its `<!-- %% CHANGELOG_ENTRIES %% -->` placeholder, and
creates a version commit and an annotated tag. Tags are bare semver, with no
`v` prefix. Publisho doesn't push the commit or the tag, and publishing to
Hex.pm isn't automated yet.
