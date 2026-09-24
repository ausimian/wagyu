defmodule Wagyu.Packet.Initiation do
  @moduledoc false

  # Handshake initiation (type 1, 148 bytes). The encrypted fields are opaque
  # Noise ciphertext; MAC1 and MAC2 cover the bytes before them.

  @enforce_keys [:sender_index, :ephemeral, :encrypted_static, :encrypted_timestamp]
  defstruct [:sender_index, :ephemeral, :encrypted_static, :encrypted_timestamp, mac1: <<0::128>>, mac2: <<0::128>>]

  @type t :: %__MODULE__{
          sender_index: non_neg_integer(),
          ephemeral: <<_::256>>,
          encrypted_static: <<_::384>>,
          encrypted_timestamp: <<_::224>>,
          mac1: <<_::128>>,
          mac2: <<_::128>>
        }
end
