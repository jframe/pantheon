/*
 * Copyright 2019 ConsenSys AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package tech.pegasys.pantheon.crypto;

import tech.pegasys.pantheon.util.bytes.BytesValue;
import tech.pegasys.pantheon.util.bytes.BytesValues;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class AesEncryption {
  private final SecretKey key;

  public AesEncryption(final SecretKey key) {
    this.key = key;
  }

  private Cipher createCipher(final int encryptMode, final SecretKey key, final byte[] iv) {
    try {
      final Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
      cipher.init(encryptMode, key, new IvParameterSpec(iv));
      return cipher;
    } catch (NoSuchAlgorithmException
        | NoSuchPaddingException
        | InvalidKeyException
        | InvalidAlgorithmParameterException e) {
      throw new IllegalStateException("Unable to obtain AES cipher for chain encryption");
    }
  }

  public EncryptedData encrypt(final BytesValue data) {
    try {
      final byte[] iv = createIv();
      final Cipher cipher = createCipher(Cipher.ENCRYPT_MODE, key, iv);
      final BytesValue encryptedData = BytesValue.wrap(cipher.doFinal(data.extractArray()));
      return new EncryptedData(encryptedData, BytesValue.wrap(iv));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  public BytesValue decrypt(final EncryptedData encryptedData) {
    try {
      final Cipher cipher =
          createCipher(Cipher.DECRYPT_MODE, key, encryptedData.getIv().extractArray());
      return BytesValue.wrap(cipher.doFinal(encryptedData.getData().extractArray()));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  public static SecretKey createKey() throws NoSuchAlgorithmException {
    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
    keyGenerator.init(256);
    return keyGenerator.generateKey();
  }

  public static byte[] createIv() throws NoSuchAlgorithmException {
    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
    keyGenerator.init(8 * 16); // IV must be 16 bytes
    return keyGenerator.generateKey().getEncoded();
  }

  public static class EncryptedData {

    private final BytesValue data;
    private final BytesValue iv;

    EncryptedData(final BytesValue data, final BytesValue iv) {
      this.data = data;
      this.iv = iv;
    }

    public BytesValue getData() {
      return data;
    }

    public BytesValue getIv() {
      return iv;
    }

    public static BytesValue encode(final EncryptedData encryptedData) {
      return BytesValues.concatenate(encryptedData.getIv(), encryptedData.getData());
    }

    public static EncryptedData decode(final BytesValue bytesValue) {
      final BytesValue iv = bytesValue.slice(0, 16);
      final BytesValue data = bytesValue.slice(16);
      return new EncryptedData(data, iv);
    }
  }
}
