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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AesEncryption {
  private static final Logger LOG = LogManager.getLogger();
  private final Cipher encryptCipher;
  private final Cipher decryptCipher;

  public AesEncryption(final SecretKey key, final byte[] iv) {
    encryptCipher = createCipher(Cipher.ENCRYPT_MODE, key, iv);
    decryptCipher = createCipher(Cipher.DECRYPT_MODE, key, iv);
    LOG.debug("AES encryption cipher is using vendor {}", encryptCipher.getProvider().getName());
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

  public BytesValue encrypt(final BytesValue data) {
    try {
      return BytesValue.wrap(encryptCipher.doFinal(data.extractArray()));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  public BytesValue decrypt(final BytesValue data) {
    try {
      return BytesValue.wrap(decryptCipher.doFinal(data.extractArray()));
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
}
