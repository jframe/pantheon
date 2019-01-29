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
package tech.pegasys.pantheon.consensus.ibft;

import static java.util.Collections.newSetFromMap;

import tech.pegasys.pantheon.consensus.ibft.messagedata.CommitMessageData;
import tech.pegasys.pantheon.consensus.ibft.messagedata.IbftV2;
import tech.pegasys.pantheon.consensus.ibft.messagedata.NewRoundMessageData;
import tech.pegasys.pantheon.consensus.ibft.messagedata.PrepareMessageData;
import tech.pegasys.pantheon.consensus.ibft.messagedata.ProposalMessageData;
import tech.pegasys.pantheon.consensus.ibft.messagedata.RoundChangeMessageData;
import tech.pegasys.pantheon.consensus.ibft.network.ValidatorMulticaster;
import tech.pegasys.pantheon.consensus.ibft.payload.SignedData;
import tech.pegasys.pantheon.crypto.SECP256K1.Signature;
import tech.pegasys.pantheon.ethereum.core.Address;
import tech.pegasys.pantheon.ethereum.p2p.api.Message;
import tech.pegasys.pantheon.ethereum.p2p.api.MessageData;

import java.util.List;
import java.util.Set;

import com.google.common.collect.Lists;

/** Class responsible for rebroadcasting IBFT messages to known validators */
public class IbftGossip {
  private final ValidatorMulticaster multicaster;

  // Set that starts evicting members when it hits capacity
  private final Set<Signature> seenMessages;

  IbftGossip(final ValidatorMulticaster multicaster, final int maxSeenMessages) {
    // Size of the seenMessages cache, should end up utilising 65bytes * this number + some meta
    // data
    this.multicaster = multicaster;
    seenMessages = newSetFromMap(new EvictingMap<>(maxSeenMessages));
  }

  /**
   * Constructor that attaches gossip logic to a set of multicaster
   *
   * @param multicaster Network connections to the remote validators
   */
  public IbftGossip(final ValidatorMulticaster multicaster) {
    this(multicaster, 10_000);
  }

  /**
   * Retransmit a given IBFT message to other known validators nodes
   *
   * @param message The raw message to be gossiped
   * @return Whether the message was rebroadcast or has been ignored as a repeat
   */
  public boolean gossipMessage(final Message message) {
    final MessageData messageData = message.getData();
    final SignedData<?> signedData;
    switch (messageData.getCode()) {
      case IbftV2.PROPOSAL:
        signedData = ProposalMessageData.fromMessageData(messageData).decode();
        break;
      case IbftV2.PREPARE:
        signedData = PrepareMessageData.fromMessageData(messageData).decode();
        break;
      case IbftV2.COMMIT:
        signedData = CommitMessageData.fromMessageData(messageData).decode();
        break;
      case IbftV2.ROUND_CHANGE:
        signedData = RoundChangeMessageData.fromMessageData(messageData).decode();
        break;
      case IbftV2.NEW_ROUND:
        signedData = NewRoundMessageData.fromMessageData(messageData).decode();
        break;
      default:
        throw new IllegalArgumentException(
            "Received message does not conform to any recognised IBFT message structure.");
    }
    final Signature signature = signedData.getSignature();
    if (seenMessages.contains(signature)) {
      return false;
    } else {
      final List<Address> excludeAddressesList =
          Lists.newArrayList(
              message.getConnection().getPeer().getAddress(), signedData.getSender());
      multicaster.send(messageData, excludeAddressesList);
      seenMessages.add(signature);
      return true;
    }
  }
}
