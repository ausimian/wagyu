# The interoperability tests have the :interop tag. They build and run
# wireguard-go from test/interop, so they need Go. They run when `go` is on
# the PATH. If `go` is not on the PATH, they do not run.
# `mix test --exclude interop` always skips them.
#
# CI sets WAGYU_INTEROP=1. With this variable, a missing `go` causes an
# error, and the tests do not skip.
interop? =
  cond do
    System.find_executable("go") -> true
    System.get_env("WAGYU_INTEROP") == "1" -> raise "WAGYU_INTEROP=1, but go is not on the PATH"
    true -> false
  end

# Many tests wait for a process that does a Noise handshake or a key
# derivation. On a slow CI runner, that can take more than the default of
# 100 ms. A test that passes returns as soon as its message arrives, so only
# a test that fails waits longer.
#
# On a host with a small UDP receive buffer, for example Linux with the
# default net.core.rmem_max, each interface logs a warning when it starts.
# ExUnit shows the log of a test only if the test fails.
ExUnit.start(
  exclude: if(interop?, do: [], else: [:interop]),
  assert_receive_timeout: 1_000,
  capture_log: true
)
