# The interoperability tests, tagged :interop, build and run wireguard-go
# from test/interop, so they need Go. They run whenever `go` is on the PATH
# and are skipped otherwise; `mix test --exclude interop` skips them anyway.
# CI sets WAGYU_INTEROP=1, which turns a missing `go` into an error rather
# than a reason to skip them.
interop? =
  cond do
    System.find_executable("go") -> true
    System.get_env("WAGYU_INTEROP") == "1" -> raise "WAGYU_INTEROP=1, but go is not on the PATH"
    true -> false
  end

ExUnit.start(exclude: if(interop?, do: [], else: [:interop]))
