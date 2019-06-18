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

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class AesEncryption {

  public static BytesValue encrypt(final BytesValue data, final SecretKey key, final byte[] iv) {
    try {
      return BytesValue.wrap(encrypt(data.extractArray(), key, iv));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  public static byte[] encrypt(final byte[] data, final SecretKey key, final byte[] iv)
      throws GeneralSecurityException {
    final Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
    return cipher.doFinal(data);
  }

  public static BytesValue decrypt(final BytesValue data, final SecretKey key, final byte[] iv) {
    try {
      return BytesValue.wrap(decrypt(data.extractArray(), key, iv));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  public static byte[] decrypt(final byte[] data, final SecretKey key, final byte[] iv)
      throws GeneralSecurityException {
    final Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
    return cipher.doFinal(data);
  }

  public static SecretKey key() throws NoSuchAlgorithmException {
    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
    keyGenerator.init(256);
    return keyGenerator.generateKey();
  }

  public static byte[] iv() throws NoSuchAlgorithmException {
    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
    keyGenerator.init(8 * 16); // IV must be 16 bytes
    return keyGenerator.generateKey().getEncoded();
  }
}
