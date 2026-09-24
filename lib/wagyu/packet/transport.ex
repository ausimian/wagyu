defmodule Wagyu.Packet.Transport do
  @moduledoc false

  # Transport data (type 4): a 16-byte header and at least a 16-byte AEAD tag.
  # An encrypted empty payload, exactly 32 bytes on the wire, is a keepalive.

  @enforce_keys [:receiver_index, :counter, :encrypted_packet]
  defstruct [:receiver_index, :counter, :encrypted_packet]

  @type t :: %__MODULE__{
          receiver_index: non_neg_integer(),
          counter: non_neg_integer(),
          encrypted_packet: binary()
        }
end
