defmodule ExthCrypto.Keystore.Decoder do
  @moduledoc """
  Module to decode an encrypted JSON keystore file.
  """
  import ExthCrypto.Math

  @spec unlock_file(String.t, String.t) :: {:ok, binary()} | {:error, String.t}
  def unlock_file(filename, password) do
    File.read!(filename)
    |> Poison.decode!
    |> Map.get("crypto")
    |> unlock(password)
  end

  @spec unlock(map(), String.t) :: {:ok, binary()} | {:error, String.t}
  defp unlock(crypto_map, password) do
    with {:ok, derived_key} <- password
                       |> kdf(crypto_map["kdf"], crypto_map["kdfparams"])
                       |> split_and_verify(crypto_map["ciphertext"] |> hex_to_bin, crypto_map["mac"] |> hex_to_bin) do
      decode_ciphertext(derived_key, crypto_map["cipher"], crypto_map["ciphertext"] |> hex_to_bin, crypto_map["cipherparams"])
    end
  end

  @spec kdf(String.t, String.t, map()) :: binary()
  defp kdf(password, "pbkdf2", kdf_params) do
    Pbkdf2.Base.hash_password(
      password,
      kdf_params["salt"] |> hex_to_bin,
      rounds: kdf_params["c"],
      length: kdf_params["dklen"],
      digest: get_digest(kdf_params["prf"]),
      format: :hex
    ) |> hex_to_bin
  end

  @spec get_digest(String.t) :: atom()
  defp get_digest("hmac-sha256"), do: :sha256

  @spec decode_ciphertext(<<_::128>>, binary(), binary(), map()) :: {:ok, binary()} | {:error, String.t}
  def decode_ciphertext(derived_key, "aes-128-ctr", ciphertext, cipher_params) do
    {:ok, ExthCrypto.AES.decrypt(ciphertext, :ctr, derived_key, cipher_params["iv"] |> hex_to_bin)}
  end

  @spec split_and_verify(<<_::256>>, binary(), binary()) :: {:ok, <<_::128>>} | {:error, String.t}
  def split_and_verify(key, ciphertext, mac) do
    <<former::binary-size(16), latter::binary-size(16)>> = key

    # SHA3( derivedKey[16:32] || cipherText )
    if ExthCrypto.Hash.Keccak.kec(latter <> ciphertext) == mac do
      {:ok, former}
    else
      {:erorr, "Invalid passphrase"}
    end
  end

end