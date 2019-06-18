/*
 * Copyright 2018 ConsenSys AG.
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
package tech.pegasys.pantheon.services.kvstore;

import tech.pegasys.pantheon.crypto.AesEncryption;
import tech.pegasys.pantheon.util.bytes.BytesValue;

import java.io.Closeable;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;
import javax.crypto.SecretKey;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EncryptedKeyValueStorage implements KeyValueStorage, Closeable {

  private static final Logger LOG = LogManager.getLogger();

  private KeyValueStorage keyValueStorage;
  private final SecretKey secretKey;
  private final byte[] iv;

  // TODO add metrics
  public EncryptedKeyValueStorage(
      final KeyValueStorage keyValueStorage, final SecretKey secretKey, final byte[] iv) {
    this.keyValueStorage = keyValueStorage;
    this.secretKey = secretKey;
    this.iv = iv;
  }

  public static EncryptedKeyValueStorage create(final KeyValueStorage keyValueStorage)
      throws StorageException {
    try {
      final SecretKey key = AesEncryption.key();
      final byte[] iv = AesEncryption.iv();
      return new EncryptedKeyValueStorage(keyValueStorage, key, iv);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("Error creating private key", e);
    }
  }

  @Override
  public Optional<BytesValue> get(final BytesValue key) throws StorageException {
    final BytesValue decryptedKey = AesEncryption.decrypt(key, secretKey, iv);
    final Optional<BytesValue> bytesValue = keyValueStorage.get(decryptedKey);
    return bytesValue.map(data -> AesEncryption.decrypt(data, secretKey, iv));
  }

  @Override
  public void close() {
    try {
      keyValueStorage.close();
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  @Override
  public Transaction startTransaction() {
    return new EncryptedTransaction(keyValueStorage.startTransaction());
  }

  private class EncryptedTransaction extends AbstractTransaction {
    private Transaction transaction;

    EncryptedTransaction(final Transaction transaction) {
      this.transaction = transaction;
    }

    @Override
    protected void doPut(final BytesValue key, final BytesValue value) {
      final BytesValue encryptedKey = AesEncryption.encrypt(key, secretKey, iv);
      final BytesValue encryptedValue = AesEncryption.encrypt(value, secretKey, iv);
      transaction.put(encryptedKey, encryptedValue);
    }

    @Override
    protected void doRemove(final BytesValue key) {
      final BytesValue encryptedKey = AesEncryption.encrypt(key, secretKey, iv);
      transaction.remove(encryptedKey);
    }

    @Override
    protected void doCommit() throws StorageException {
      transaction.commit();
    }

    @Override
    protected void doRollback() {
      transaction.rollback();
    }
  }
}
