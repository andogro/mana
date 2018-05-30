defmodule ExWire.RLPx do
  alias ExWire.Handshake

  def handle_auth_received(
        encoded_auth_msg,
        my_ephemeral_key_pair,
        my_nonce,
        my_static_private_key
      ) do
    with {:ok, auth_msg} <- decode_auth(encoded_auth_msg, my_static_private_key),
         {:ok, encoded_ack_resp} <- prepare_ack_response(auth_msg, my_ephemeral_key_pair),
         {:ok, secrets} <-
           derive_shared_secrets(
             auth_msg,
             encoded_auth_msg,
             encoded_ack_resp,
             my_ephemeral_key_pair,
             my_nonce
           ) do
      {:ok, auth_msg, encoded_ack_resp, secrets}
    end
  end

  def decode_auth(encoded_auth_msg, my_static_private_key) do
    with {:ok, auth_msg = %Handshake.Struct.AuthMsgV4{}, <<>>} <-
           Handshake.read_auth_msg(encoded_auth_msg, my_static_private_key) do
      {:ok, auth_msg}
    end
  end

  def prepare_ack_response(auth_msg, my_ephemeral_key_pair) do
    auth_msg
    |> build_ack_resp()
    |> ExWire.Handshake.Struct.AckRespV4.serialize()
    |> ExWire.Handshake.EIP8.wrap_eip_8(
      auth_msg.remote_public_key,
      my_ephemeral_key_pair
    )
  end

  def derive_shared_secrets(
        auth_msg,
        encoded_auth_msg,
        encoded_ack_resp,
        my_ephemeral_key_pair,
        my_nonce
      ) do
    auth_initiator = false
    {private_key, _public_key} = my_ephemeral_key_pair

    secrets =
      ExWire.Framing.Secrets.derive_secrets(
        auth_initiator,
        private_key,
        auth_msg.remote_ephemeral_public_key,
        auth_msg.remote_nonce,
        my_nonce,
        encoded_auth_msg,
        encoded_ack_resp
      )

    {:ok, secrets}
  end

  defp build_ack_resp(auth_msg) do
    ExWire.Handshake.build_ack_resp(
      auth_msg.remote_ephemeral_public_key,
      auth_msg.remote_nonce
    )
  end

  defp build_ack_resp(auth_msg, {_private, public_key} = my_ephemeral_key_pair) do
    IO.inspect(auth_msg)

    ack_resp =
      ExWire.Handshake.build_ack_resp(
        auth_msg.remote_ephemeral_public_key,
        auth_msg.remote_nonce
      )

    {:ok, encoded_ack_resp} =
      ack_resp
      |> ExWire.Handshake.Struct.AckRespV4.serialize()
      |> ExWire.Handshake.EIP8.wrap_eip_8(
        auth_msg.remote_public_key,
        my_ephemeral_key_pair
      )

    encoded_ack_resp
  end

  defp build_secrets(
         auth_msg_received,
         auth_data,
         encoded_resp,
         nonce,
         {private_key, _publick_key}
       ) do
    ExWire.Framing.Secrets.derive_secrets(
      false,
      private_key,
      auth_msg_received.remote_ephemeral_public_key,
      auth_msg_received.remote_nonce,
      nonce,
      auth_data,
      encoded_resp
    )
  end

  def build_ack(auth_msg_received) do
    %ExWire.Handshake.Struct.AuthMsgV4{
      signature: _signature,
      remote_public_key: _remote_public_key,
      remote_nonce: remote_nonce,
      remote_version: remote_version,
      remote_ephemeral_public_key: remote_ephemeral_public_key
    } = auth_msg_received
  end
end
