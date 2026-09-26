defmodule Wagyu.Config.Peer do
  @moduledoc """
  A peer in a `Wagyu.Config`, built by `Wagyu.Config.new/1` from the
  `:peers` option.

  The fields hold the validated option values. `:allowed_ips` has host bits
  cleared and keeps the order given. `:endpoint` is `nil` when none is
  configured, `:preshared_key` is 32 zero bytes when none is configured, and
  `:persistent_keepalive` is `0` when it is off. `inspect/2` hides the
  preshared key, with the same limits as `Wagyu.Config`.
  """

  @derive {Inspect, except: [:preshared_key]}
  @enforce_keys [:public_key]
  defstruct [:public_key, endpoint: nil, allowed_ips: [], preshared_key: <<0::256>>, persistent_keepalive: 0]

  @type t :: %__MODULE__{
          public_key: <<_::256>>,
          endpoint: %{address: :inet.ip_address(), port: 1..65_535} | nil,
          allowed_ips: [{:inet.ip_address(), non_neg_integer()}],
          preshared_key: <<_::256>>,
          persistent_keepalive: 0..65_535
        }
end
