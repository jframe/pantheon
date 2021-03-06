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
package tech.pegasys.pantheon.consensus.ibftlegacy;

import tech.pegasys.pantheon.consensus.common.EpochManager;
import tech.pegasys.pantheon.consensus.common.VoteTally;
import tech.pegasys.pantheon.consensus.common.VoteType;
import tech.pegasys.pantheon.consensus.ibft.VoteTallyUpdater;
import tech.pegasys.pantheon.ethereum.chain.Blockchain;
import tech.pegasys.pantheon.ethereum.core.Address;
import tech.pegasys.pantheon.ethereum.core.BlockHeader;
import tech.pegasys.pantheon.util.bytes.BytesValue;

import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Provides the logic to extract vote tally state from the blockchain and update it as blocks are
 * added.
 */
public class IbftVoteTallyUpdater implements VoteTallyUpdater {

  private static final Logger LOG = LogManager.getLogger();
  private static final Address NO_VOTE_SUBJECT = Address.wrap(BytesValue.wrap(new byte[20]));

  private final EpochManager epochManager;

  public IbftVoteTallyUpdater(final EpochManager epochManager) {
    this.epochManager = epochManager;
  }

  /**
   * Create a new VoteTally based on the current blockchain state.
   *
   * @param blockchain the blockchain to load the current state from
   * @return a VoteTally reflecting the state of the blockchain head
   */
  @Override
  public VoteTally buildVoteTallyFromBlockchain(final Blockchain blockchain) {
    final long chainHeadBlockNumber = blockchain.getChainHeadBlockNumber();
    final long epochBlockNumber = epochManager.getLastEpochBlock(chainHeadBlockNumber);
    LOG.info("Loading validator voting state starting from block {}", epochBlockNumber);
    final BlockHeader epochBlock = blockchain.getBlockHeader(epochBlockNumber).get();
    final List<Address> initialValidators =
        IbftExtraData.decode(epochBlock.getExtraData()).getValidators();
    final VoteTally voteTally = new VoteTally(initialValidators);
    for (long blockNumber = epochBlockNumber + 1;
        blockNumber <= chainHeadBlockNumber;
        blockNumber++) {
      updateForBlock(blockchain.getBlockHeader(blockNumber).get(), voteTally);
    }
    return voteTally;
  }

  /**
   * Update the vote tally to reflect changes caused by appending a new block to the chain.
   *
   * @param header the header of the block being added
   * @param voteTally the vote tally to update
   */
  @Override
  public void updateForBlock(final BlockHeader header, final VoteTally voteTally) {
    final Address candidate = header.getCoinbase();
    if (epochManager.isEpochBlock(header.getNumber())) {
      voteTally.discardOutstandingVotes();
      return;
    }

    if (!candidate.equals(NO_VOTE_SUBJECT)) {
      final IbftExtraData ibftExtraData = IbftExtraData.decode(header.getExtraData());
      final Address proposer = IbftBlockHashing.recoverProposerAddress(header, ibftExtraData);
      voteTally.addVote(proposer, candidate, VoteType.fromNonce(header.getNonce()).get());
    }
  }
}
