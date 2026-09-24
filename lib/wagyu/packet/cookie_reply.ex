defmodule Wagyu.Packet.CookieReply do
  @moduledoc false

  # Cookie reply (type 3, 64 bytes): an XChaCha20-Poly1305 nonce and the
  # encrypted 16-byte cookie with its tag.

  @enforce_keys [:receiver_index, :nonce, :encrypted_cookie]
  defstruct [:receiver_index, :nonce, :encrypted_cookie]

  @type t :: %__MODULE__{
          receiver_index: non_neg_integer(),
          nonce: <<_::192>>,
          encrypted_cookie: <<_::256>>
        }
end
