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