defmodule ExWire.RLPxTest do
  use ExUnit.Case, async: true
  doctest ExWire.RLPx

  alias ExWire.{RLPx, Handshake}
  alias ExWire.Framing.Secrets

  describe "handles_auth_received/4" do
    test "decodes auth message from remote, creates ack response, and create secrets" do
      creds = build_all_credentials()

      {:ok, unencoded_auth_message, my_ack_response, my_secrets} =
        RLPx.handle_auth_received(
          creds.her_encoded_auth_msg,
          creds.my_ephemeral_key_pair,
          creds.my_nonce,
          creds.my_static_private_key
        )

      assert remove_remote_public_key(unencoded_auth_message) == creds.her_unencoded_auth_msg
      assert is_binary(my_ack_response)
      assert %Secrets{} = my_secrets
    end
  end

  describe "decode_auth/2" do
    test "decodes encoded auth message Alice sends us" do
      creds = build_all_credentials()

      {:ok, auth_msg} = RLPx.decode_auth(creds.her_encoded_auth_msg, creds.my_static_private_key)

      assert creds.her_unencoded_auth_msg == %{auth_msg | remote_ephemeral_public_key: nil}
    end
  end

  describe "prepare_ack_response/2" do
    test "generates an ack response and encodes it, in response to an auth msg" do
      creds = build_all_credentials()

      {:ok, auth_msg} = RLPx.decode_auth(creds.her_encoded_auth_msg, creds.my_static_private_key)

      {:ok, encoded_ack_resp} = RLPx.prepare_ack_response(auth_msg, creds.my_ephemeral_key_pair)

      # decode and assert is same as ack resp
      assert auth_msg
      assert encoded_ack_resp
    end
  end

  describe "derive_shared_secrets/2" do
    test "it generates all shared secrets from an auth_msg" do
      creds = build_all_credentials()

      {:ok, auth_msg} = RLPx.decode_auth(creds.her_encoded_auth_msg, creds.my_static_private_key)
      {:ok, encoded_ack_resp} = RLPx.prepare_ack_response(auth_msg, creds.my_ephemeral_key_pair)

      {:ok, secrets} =
        RLPx.derive_shared_secrets(
          auth_msg,
          creds.her_encoded_auth_msg,
          encoded_ack_resp,
          creds.my_ephemeral_key_pair,
          creds.my_nonce
        )

      assert %Secrets{} = secrets
    end
  end

  def remove_remote_public_key(auth_message) do
    %{auth_message | remote_ephemeral_public_key: nil}
  end

  def build_all_credentials do
    keys = build_keys()

    keys
    |> Map.merge(build_my_credentials(keys))
    |> Map.merge(build_her_credentials(keys))
  end

  def build_keys do
    %{
      my_static_public_key: ExthCrypto.Test.public_key(:key_a),
      my_static_private_key: ExthCrypto.Test.private_key(:key_a),
      her_static_public_key: ExthCrypto.Test.public_key(:key_b),
      her_static_private_key: ExthCrypto.Test.private_key(:key_b)
    }
  end

  def build_my_credentials(keys) do
    {my_auth_msg, my_ephemeral_key_pair, my_nonce} =
      Handshake.build_auth_msg(
        keys.my_static_public_key,
        keys.my_static_private_key,
        keys.her_static_public_key
      )

    {:ok, encoded_auth_msg} =
      my_auth_msg
      |> Handshake.Struct.AuthMsgV4.serialize()
      |> Handshake.EIP8.wrap_eip_8(keys.her_static_public_key, my_ephemeral_key_pair)

    %{
      my_unencoded_auth_msg: my_auth_msg,
      my_ephemeral_key_pair: my_ephemeral_key_pair,
      my_nonce: my_nonce,
      my_encoded_auth_msg: encoded_auth_msg
    }
  end

  def build_her_credentials(keys) do
    {her_auth_msg, her_ephemeral_key_pair, her_nonce} =
      Handshake.build_auth_msg(
        keys.her_static_public_key,
        keys.her_static_private_key,
        keys.my_static_public_key
      )

    {:ok, encoded_auth_msg} =
      her_auth_msg
      |> Handshake.Struct.AuthMsgV4.serialize()
      |> Handshake.EIP8.wrap_eip_8(keys.my_static_public_key, her_ephemeral_key_pair)

    %{
      her_unencoded_auth_msg: her_auth_msg,
      her_ephemeral_key_pair: her_ephemeral_key_pair,
      her_nonce: her_nonce,
      her_encoded_auth_msg: encoded_auth_msg
    }
  end
end
