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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

import java.security.GeneralSecurityException;
import java.security.Security;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

public class AesEncryptionTest {
  {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Test
  public void encryptAndDecryptReturnsOriginalData() throws GeneralSecurityException {
    final byte[] iv = AesEncryption.iv();
    final SecretKey key = AesEncryption.key();
    byte[] dataToEncrypt = "0x01636861696e4865616448617368".getBytes(UTF_8);
    byte[] encryptedData = AesEncryption.encrypt(dataToEncrypt, key, iv);
    byte[] decryptedData = AesEncryption.decrypt(encryptedData, key, iv);
    assertThat(decryptedData).isEqualTo(dataToEncrypt);
  }
}
