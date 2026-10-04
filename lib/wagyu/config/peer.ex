defmodule Wagyu.Config.Peer do
  @moduledoc """
  A peer in a `Wagyu.Config`. `Wagyu.Config.new/1` builds it from the
  `:peers` option.

  The fields hold the validated option values. In `:allowed_ips`, the host
  bits are clear, and the prefixes keep the sequence that you gave. If you
  do not configure these fields, they have these values:

    * `:endpoint` is `nil`.
    * `:preshared_key` is 32 zero bytes.
    * `:persistent_keepalive` is `0`, which is off.

  `inspect/2` hides the preshared key, with the same limits as
  `Wagyu.Config`.
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
