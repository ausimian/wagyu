defmodule Wagyu.Config.Peer do
  @moduledoc """
  A validated peer definition.

  `:allowed_ips` holds normalized prefixes (host bits cleared) in configured
  order. `:endpoint` is `nil` for a responder-only peer. `:preshared_key` is
  the protocol's all-zero key, the only one this release supports; the
  struct's `Inspect` implementation omits it all the same, with the limits
  described in `Wagyu.Config`.
  """

  @derive {Inspect, except: [:preshared_key]}
  @enforce_keys [:public_key]
  defstruct [:public_key, endpoint: nil, allowed_ips: [], preshared_key: <<0::256>>]

  @type t :: %__MODULE__{
          public_key: <<_::256>>,
          endpoint: %{address: :inet.ip_address(), port: 1..65_535} | nil,
          allowed_ips: [{:inet.ip_address(), non_neg_integer()}],
          preshared_key: <<_::256>>
        }
end
