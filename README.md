# Wagyu

Wagyu is an Elixir application skeleton with a supervision tree. Its public
functionality has not been designed yet.

## Development

Use Elixir 1.19.5 and Erlang/OTP 28.3 locally. The project supports Elixir
1.18 and newer on compatible OTP releases.

```sh
mix deps.get
mix precommit
```

`mix precommit` compiles with warnings treated as errors, checks dependency
usage and formatting, runs Credo, and executes the tests.
