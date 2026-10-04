# Maintaining Wagyu

This document is for people who work on Wagyu itself. To use Wagyu, see the
[README](README.md).

## Toolchain

- Elixir 1.19.5 and Erlang/OTP 28.3. `.tool-versions` sets these versions.
  The project supports Elixir 1.18 and later on compatible OTP releases. CI
  tests that range.
- Go 1.25 or later for the interop tests. Go is optional on your machine. See
  [Interop tests](#interop-tests).

## Checks

```sh
mix deps.get
mix precommit
```

Run `mix precommit` before each commit. It runs in the test environment. It
does these steps in this sequence:

1. `compile --warnings-as-errors`
2. `deps.unlock --unused`, which removes unused entries from `mix.lock`
3. `format`, which writes the correct format into files that do not have it
4. `credo --strict`
5. `docs --warnings-as-errors`, which fails on a documentation warning.
   An example is a public type that refers to a hidden module.
6. `test`

Run the full alias. Do not select individual steps, because you can forget a
step. `deps.unlock` and `format` can change files. Thus, examine the working
tree before you commit.

## Interop tests

The tests with the `interop` tag run Wagyu against
[wireguard-go](https://git.zx2c4.com/wireguard-go). wireguard-go uses its
userspace network stack (`tun/netstack`), which does not need a TUN device or
root. The tests build a small Go helper in `test/interop`. The `go.mod` and
`go.sum` files of the helper set its dependency versions.

The helper runs a wireguard-go peer. Its netstack has these items:

- TCP and UDP echo servers.
- A TCP sink.
- An optional delay on the datagrams that it sends.

The `vectors` command of the helper prints a handshake transcript from fixed
keys. The transcript includes a cookie reply and MAC2. A golden test compares
it byte for byte.

- If `go` is on the `PATH`, `mix test` and `mix precommit` run these tests.
- If `go` is not on the `PATH`, the tests do not run.
- With `WAGYU_INTEROP=1`, a missing `go` causes an error. CI sets this
  variable.
- `mix test --exclude interop` always skips these tests.
- One test measures the TCP throughput of one stream with a simulated round
  trip of 50 ms. It compares the rate with a low minimum.
  `WAGYU_THROUGHPUT=1` prints the measured rate.

## Benchmarks

`bench/throughput.exs` uses [Benchee](https://github.com/bencheeorg/benchee)
to measure bulk TCP through the tunnel. It runs two interfaces on 127.0.0.1,
and each interface is a peer of the other. Sockets on one stack send to a
listener on the other stack, through 1, 4 and 8 streams. The baseline is the
loopback link of SmolNet, which sends the same TCP without a tunnel.

```sh
mix run bench/throughput.exs
```

These environment variables change the benchmark:

- `WAGYU_BENCH_MB` sets the MiB that each run sends (default 16).
- `WAGYU_BENCH_TIME` sets the seconds that the script measures for each
  scenario (default 10).
- `WAGYU_BENCH_MTU` sets the MTU of the stacks (default 1280).

After the Benchee report, the script prints the median rate of each scenario
in MiB/s. It also prints the packets that the interface dropped.

The two ends use the same VM. Thus the rates are a loopback value for two
interfaces, not the capacity of one interface. Each scenario opens its
connections one time and uses them again for each run. The reason is that the
stacks have the default of 64 socket slots. A closed TCP socket keeps its slot
through TIME_WAIT, for about 10 seconds.

## CI

`.github/workflows/ci.yml` runs on pushes to `main` and on pull requests. It
runs `mix precommit` on Linux for each of these Elixir/OTP pairs: 1.20/29,
1.20/28, 1.20/27, 1.19/28, 1.19/27 and 1.18/27. On macOS, it runs only the
Elixir 1.20 pairs. The workflow installs the Go version from
`test/interop/go.mod` and sets `WAGYU_INTEROP=1`. Thus each job runs the
interop tests.

`.github/workflows/release.yml` runs when you push a release tag. It publishes
to Hex.pm. See [Releasing](#releasing).

## Design and roadmap

The tracking issue [#2](https://github.com/ausimian/wagyu/issues/2) contains
the architecture, the protocol decisions and the implementation sequence. Each
step has its own issue, with a link from issue #2. The body of that issue is
the specification for the step.

## Making changes

- Work on a branch, and merge it through a pull request. Do not commit
  directly to `main`. The only exception is the version commit that Publisho
  makes for a release. See [Releasing](#releasing).
- Write commit messages as [Conventional Commits](https://www.conventionalcommits.org/).
- Add changes that users can see to `RELEASE.md`, under Keep a Changelog
  headings (`### Added`, `### Changed`, `### Fixed`, and the others). These
  notes become the `CHANGELOG.md` entry for the next release.

## Releasing

The release workflow publishes releases to
[Hex.pm](https://hex.pm/packages/wagyu). `CHANGELOG.md` lists them.

`@version` in `mix.exs` is the single source of truth for the version.
Releases use [Publisho](https://hex.pm/packages/publisho) and the release
workflow:

1. Make sure that `main` is up to date and that `RELEASE.md` contains the
   release notes.
2. Run `mix publisho <level>`. This command does these steps:
   - It updates `@version`.
   - It moves the `RELEASE.md` notes into `CHANGELOG.md`, at the
     `<!-- %% CHANGELOG_ENTRIES %% -->` placeholder.
   - It makes a version commit and an annotated tag. Tags are bare semver,
     without a `v` prefix.
3. Run `git push --follow-tags` to push the version commit and its tag
   together. This push goes directly to `main`, without a pull request. The
   commit changes only the version and the release notes. The workflow
   publishes only if the tag points to a commit that is already on `main`.

A push of a tag in the form `X.Y.Z` or `X.Y.Z-*` starts
`.github/workflows/release.yml`. This workflow publishes the package and its
docs to Hex.pm. Before it publishes, it makes sure of these conditions:

- The `HEX_API_KEY` repository secret has a value.
- The tag is equal to `@version` in `mix.exs`.
- The tagged commit is on `main`. Thus, its code went through a pull request
  and the CI matrix.
- `mix hex.audit` and `mix precommit`, with the interop tests, pass on
  Elixir 1.19.5 and OTP 28.3. They also do not change the tree.

If a check fails, the workflow does not publish. `HEX_API_KEY` must be a Hex
API key with publish rights for the `wagyu` package.

The workflow does not make a GitHub release. After the workflow publishes,
make the GitHub release from the tag. The tag contains the release notes:

```sh
gh release create X.Y.Z --verify-tag --notes-from-tag --title X.Y.Z
```
