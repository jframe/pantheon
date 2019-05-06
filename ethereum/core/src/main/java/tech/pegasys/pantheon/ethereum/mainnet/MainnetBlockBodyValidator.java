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
package tech.pegasys.pantheon.ethereum.mainnet;

import tech.pegasys.pantheon.ethereum.ProtocolContext;
import tech.pegasys.pantheon.ethereum.core.Block;
import tech.pegasys.pantheon.ethereum.core.BlockBody;
import tech.pegasys.pantheon.ethereum.core.BlockHeader;
import tech.pegasys.pantheon.ethereum.core.Hash;
import tech.pegasys.pantheon.ethereum.core.LogsBloomFilter;
import tech.pegasys.pantheon.ethereum.core.TransactionReceipt;
import tech.pegasys.pantheon.util.bytes.Bytes32;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class MainnetBlockBodyValidator<C> implements BlockBodyValidator<C> {

  private static final Logger LOG = LogManager.getLogger();

  private static final int MAX_OMMERS = 2;

  private static final int MAX_GENERATION = 6;
  private final ProtocolSchedule<C> protocolSchedule;

  public MainnetBlockBodyValidator(final ProtocolSchedule<C> protocolSchedule) {
    this.protocolSchedule = protocolSchedule;
  }

  @Override
  public boolean validateBody(
      final ProtocolContext<C> context,
      final Block block,
      final List<TransactionReceipt> receipts,
      final Hash worldStateRootHash,
      final HeaderValidationMode ommerValidationMode) {

    if (!validateBodyLight(context, block, receipts, ommerValidationMode)) {
      return false;
    }

    if (!validateStateRoot(block.getHeader().getStateRoot(), worldStateRootHash)) {
      return false;
    }

    return true;
  }

  @Override
  public boolean validateBodyLight(
      final ProtocolContext<C> context,
      final Block block,
      final List<TransactionReceipt> receipts,
      final HeaderValidationMode ommerValidationMode) {
    final BlockHeader header = block.getHeader();
    final BlockBody body = block.getBody();

    final Bytes32 transactionsRoot = BodyValidation.transactionsRoot(body.getTransactions());
    if (!validateTransactionsRoot(header.getTransactionsRoot(), transactionsRoot)) {
      return false;
    }

    final Bytes32 receiptsRoot = BodyValidation.receiptsRoot(receipts);
    if (!validateReceiptsRoot(header.getReceiptsRoot(), receiptsRoot)) {
      return false;
    }

    final long gasUsed =
        receipts.isEmpty() ? 0 : receipts.get(receipts.size() - 1).getCumulativeGasUsed();
    if (!validateGasUsed(header.getGasUsed(), gasUsed)) {
      return false;
    }

    if (!validateLogsBloom(header.getLogsBloom(), BodyValidation.logsBloom(receipts))) {
      return false;
    }

    if (!validateEthHash(context, block, ommerValidationMode)) {
      return false;
    }

    return true;
  }

  private static boolean validateTransactionsRoot(final Bytes32 expected, final Bytes32 actual) {
    if (!expected.equals(actual)) {
      LOG.warn(
          "Invalid block: transaction root mismatch (expected={}, actual={})", expected, actual);
      return false;
    }

    return true;
  }

  private static boolean validateLogsBloom(
      final LogsBloomFilter expected, final LogsBloomFilter actual) {
    if (!expected.equals(actual)) {
      LOG.warn(
          "Invalid block: logs bloom filter mismatch (expected={}, actual={})", expected, actual);
      return false;
    }

    return true;
  }

  private static boolean validateGasUsed(final long expected, final long actual) {
    if (expected != actual) {
      LOG.warn("Invalid block: gas used mismatch (expected={}, actual={})", expected, actual);
      return false;
    }

    return true;
  }

  private static boolean validateReceiptsRoot(final Bytes32 expected, final Bytes32 actual) {
    if (!expected.equals(actual)) {
      LOG.warn("Invalid block: receipts root mismatch (expected={}, actual={})", expected, actual);
      return false;
    }

    return true;
  }

  private static boolean validateStateRoot(final Bytes32 expected, final Bytes32 actual) {
    if (!expected.equals(actual)) {
      LOG.warn("Invalid block: state root mismatch (expected={}, actual={})", expected, actual);
      return false;
    }

    return true;
  }

  private boolean validateEthHash(
      final ProtocolContext<C> context,
      final Block block,
      final HeaderValidationMode ommerValidationMode) {
    final BlockHeader header = block.getHeader();
    final BlockBody body = block.getBody();

    final Bytes32 ommerHash = BodyValidation.ommersHash(body.getOmmers());
    if (!validateOmmersHash(header.getOmmersHash(), ommerHash)) {
      return false;
    }

    if (!validateOmmers(context, header, body.getOmmers(), ommerValidationMode)) {
      return false;
    }

    return true;
  }

  private static boolean validateOmmersHash(final Bytes32 expected, final Bytes32 actual) {
    if (!expected.equals(actual)) {
      LOG.warn("Invalid block: ommers hash mismatch (expected={}, actual={})", expected, actual);
      return false;
    }

    return true;
  }

  private boolean validateOmmers(
      final ProtocolContext<C> context,
      final BlockHeader header,
      final List<BlockHeader> ommers,
      final HeaderValidationMode ommerValidationMode) {
    if (ommers.size() > MAX_OMMERS) {
      LOG.warn("Invalid block: ommer count {} exceeds ommer limit {}", ommers.size(), MAX_OMMERS);
      return false;
    }

    if (!areOmmersUnique(ommers)) {
      LOG.warn("Invalid block: ommers are not unique");
      return false;
    }

    for (final BlockHeader ommer : ommers) {
      if (!isOmmerValid(context, header, ommer, ommerValidationMode)) {
        LOG.warn("Invalid block: ommer is invalid");
        return false;
      }
    }

    return true;
  }

  private static boolean areOmmersUnique(final List<BlockHeader> ommers) {
    final Set<BlockHeader> uniqueOmmers = new HashSet<>(ommers);

    return uniqueOmmers.size() == ommers.size();
  }

  private static boolean areSiblings(final BlockHeader a, final BlockHeader b) {
    // Siblings cannot be the same.
    if (a.equals(b)) {
      return false;
    }

    return a.getParentHash().equals(b.getParentHash());
  }

  private boolean isOmmerValid(
      final ProtocolContext<C> context,
      final BlockHeader current,
      final BlockHeader ommer,
      final HeaderValidationMode ommerValidationMode) {
    final ProtocolSpec<C> protocolSpec = protocolSchedule.getByBlockNumber(ommer.getNumber());
    if (!protocolSpec
        .getOmmerHeaderValidator()
        .validateHeader(ommer, context, ommerValidationMode)) {
      return false;
    }

    if (!ommerValidationMode.isFormOfLightValidation()) {
      return isOmmerSiblingOfAncestor(context, current, ommer);
    } else {
      return true;
    }
  }

  private boolean isOmmerSiblingOfAncestor(
      final ProtocolContext<C> context, final BlockHeader current, final BlockHeader ommer) {
    // The current block is guaranteed to have a parent because it's a valid header.
    final long lastAncestorBlockNumber = Math.max(current.getNumber() - MAX_GENERATION, 0);

    BlockHeader previous = current;
    while (previous.getNumber() > lastAncestorBlockNumber) {
      final BlockHeader ancestor =
          context.getBlockchain().getBlockHeader(previous.getParentHash()).get();
      if (areSiblings(ommer, ancestor)) {
        return true;
      }
      previous = ancestor;
    }
    return false;
  }
}
