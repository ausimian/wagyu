defmodule Wagyu.Packet.Response do
  @moduledoc false

  # Handshake response (type 2, 92 bytes). `receiver_index` is the initiator's
  # sender index; `encrypted_nothing` is the AEAD tag over an empty payload.

  @enforce_keys [:sender_index, :receiver_index, :ephemeral, :encrypted_nothing]
  defstruct [:sender_index, :receiver_index, :ephemeral, :encrypted_nothing, mac1: <<0::128>>, mac2: <<0::128>>]

  @type t :: %__MODULE__{
          sender_index: non_neg_integer(),
          receiver_index: non_neg_integer(),
          ephemeral: <<_::256>>,
          encrypted_nothing: <<_::128>>,
          mac1: <<_::128>>,
          mac2: <<_::128>>
        }
end
