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
import tech.pegasys.pantheon.crypto.AesEncryption.EncryptedData;
import tech.pegasys.pantheon.metrics.MetricCategory;
import tech.pegasys.pantheon.metrics.MetricsSystem;
import tech.pegasys.pantheon.metrics.OperationTimer;
import tech.pegasys.pantheon.metrics.prometheus.PrometheusMetricsSystem;
import tech.pegasys.pantheon.metrics.rocksdb.RocksDBStats;
import tech.pegasys.pantheon.util.bytes.BytesValue;

import java.io.Closeable;
import java.io.IOException;
import java.util.Optional;
import javax.crypto.SecretKey;

import org.rocksdb.Statistics;

public class EncryptedKeyValueStorage implements KeyValueStorage, Closeable {

  private final KeyValueStorage keyValueStorage;
  private final AesEncryption aesEncryption;

  private final OperationTimer readLatency;
  private final OperationTimer removeLatency;
  private final OperationTimer writeLatency;

  private EncryptedKeyValueStorage(
      final RocksDbConfiguration rocksDbConfiguration,
      final MetricsSystem metricsSystem,
      final KeyValueStorage keyValueStorage,
      final SecretKey aesKey) {
    this.keyValueStorage = keyValueStorage;
    this.aesEncryption = new AesEncryption(aesKey);

    final Statistics stats = new Statistics();

    readLatency =
        metricsSystem
            .createLabelledTimer(
                MetricCategory.KVSTORE_ROCKSDB,
                "encrypted_read_latency_seconds",
                "Latency for encrypted read from RocksDB.",
                "database")
            .labels(rocksDbConfiguration.getLabel());
    removeLatency =
        metricsSystem
            .createLabelledTimer(
                MetricCategory.KVSTORE_ROCKSDB,
                "encrypted_remove_latency_seconds",
                "Latency of remove encrypted requests from RocksDB.",
                "database")
            .labels(rocksDbConfiguration.getLabel());
    writeLatency =
        metricsSystem
            .createLabelledTimer(
                MetricCategory.KVSTORE_ROCKSDB,
                "encrypted_write_latency_seconds",
                "Latency for encrypted write to RocksDB.",
                "database")
            .labels(rocksDbConfiguration.getLabel());

    if (metricsSystem instanceof PrometheusMetricsSystem) {
      RocksDBStats.registerRocksDBMetrics(stats, (PrometheusMetricsSystem) metricsSystem);
    }
  }

  public static EncryptedKeyValueStorage create(
      final SecretKey key,
      final RocksDbConfiguration rocksDbConfiguration,
      final MetricsSystem metricsSystem,
      final KeyValueStorage keyValueStorage)
      throws StorageException {
    return new EncryptedKeyValueStorage(rocksDbConfiguration, metricsSystem, keyValueStorage, key);
  }

  @Override
  public Optional<BytesValue> get(final BytesValue key) throws StorageException {
    try (final OperationTimer.TimingContext ignored = readLatency.startTimer()) {
      final Optional<BytesValue> bytesValue = keyValueStorage.get(key);
      return bytesValue.map(
          encryptedData -> aesEncryption.decrypt(EncryptedData.decode(encryptedData)));
    }
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
      try (final OperationTimer.TimingContext ignored = writeLatency.startTimer()) {
        final EncryptedData encryptedValue = aesEncryption.encrypt(value);
        final BytesValue dataToStore = EncryptedData.encode(encryptedValue);
        transaction.put(key, dataToStore);
      }
    }

    @Override
    protected void doRemove(final BytesValue key) {
      try (final OperationTimer.TimingContext ignored = removeLatency.startTimer()) {
        transaction.remove(key);
      }
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