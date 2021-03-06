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
package tech.pegasys.pantheon.ethereum.p2p.discovery.internal;

import static com.google.common.base.Preconditions.checkArgument;
import static tech.pegasys.pantheon.crypto.Hash.keccak256;
import static tech.pegasys.pantheon.util.Preconditions.checkGuard;
import static tech.pegasys.pantheon.util.bytes.BytesValues.asUnsignedBigInteger;

import tech.pegasys.pantheon.crypto.SECP256K1;
import tech.pegasys.pantheon.crypto.SECP256K1.PublicKey;
import tech.pegasys.pantheon.crypto.SECP256K1.Signature;
import tech.pegasys.pantheon.ethereum.p2p.discovery.PeerDiscoveryPacketDecodingException;
import tech.pegasys.pantheon.ethereum.rlp.RLP;
import tech.pegasys.pantheon.ethereum.rlp.RLPException;
import tech.pegasys.pantheon.ethereum.rlp.VertxBufferRLPOutput;
import tech.pegasys.pantheon.util.bytes.BytesValue;
import tech.pegasys.pantheon.util.bytes.MutableBytesValue;
import tech.pegasys.pantheon.util.uint.UInt256Bytes;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Optional;

import io.vertx.core.buffer.Buffer;

public class Packet {

  private static final int PACKET_TYPE_INDEX = 97;
  private static final int PACKET_DATA_INDEX = 98;
  private static final int SIGNATURE_INDEX = 32;

  private final PacketType type;
  private final PacketData data;

  private final BytesValue hash;
  private final Signature signature;
  private final PublicKey publicKey;

  private Packet(final PacketType type, final PacketData data, final SECP256K1.KeyPair keyPair) {
    this.type = type;
    this.data = data;

    final BytesValue typeBytes = BytesValue.of(this.type.getValue());
    final BytesValue dataBytes = RLP.encode(this.data::writeTo);

    this.signature = SECP256K1.sign(keccak256(BytesValue.wrap(typeBytes, dataBytes)), keyPair);
    this.hash =
        keccak256(
            BytesValue.wrap(BytesValue.wrap(encodeSignature(signature), typeBytes), dataBytes));
    this.publicKey = keyPair.getPublicKey();
  }

  private Packet(
      final PacketType packetType, final PacketData packetData, final BytesValue message) {
    final BytesValue hash = message.slice(0, SIGNATURE_INDEX);
    final BytesValue encodedSignature =
        message.slice(SIGNATURE_INDEX, PACKET_TYPE_INDEX - SIGNATURE_INDEX);
    final BytesValue signedPayload =
        message.slice(PACKET_TYPE_INDEX, message.size() - PACKET_TYPE_INDEX);

    // Perform hash integrity check.
    final BytesValue rest = message.slice(SIGNATURE_INDEX, message.size() - SIGNATURE_INDEX);
    if (!Arrays.equals(keccak256(rest).extractArray(), hash.extractArray())) {
      throw new PeerDiscoveryPacketDecodingException(
          "Integrity check failed: non-matching hashes.");
    }

    this.type = packetType;
    this.data = packetData;
    this.hash = hash;
    this.signature = decodeSignature(encodedSignature);
    this.publicKey =
        PublicKey.recoverFromSignature(keccak256(signedPayload), this.signature)
            .orElseThrow(
                () ->
                    new PeerDiscoveryPacketDecodingException(
                        "Invalid packet signature, " + "cannot recover public key"));
  }

  public static Packet create(
      final PacketType packetType, final PacketData packetData, final SECP256K1.KeyPair keyPair) {
    return new Packet(packetType, packetData, keyPair);
  }

  public static Packet decode(final Buffer message) {
    checkGuard(
        message.length() >= PACKET_DATA_INDEX,
        PeerDiscoveryPacketDecodingException::new,
        "Packet too short: expected at least %s bytes, got %s",
        PACKET_DATA_INDEX,
        message.length());

    final byte type = message.getByte(PACKET_TYPE_INDEX);

    final PacketType packetType =
        PacketType.forByte(type)
            .orElseThrow(
                () ->
                    new PeerDiscoveryPacketDecodingException("Unrecognized packet type: " + type));

    final PacketType.Deserializer<?> deserializer = packetType.getDeserializer();
    final PacketData packetData;
    try {
      packetData = deserializer.deserialize(RLP.input(message, PACKET_DATA_INDEX));
    } catch (final RLPException e) {
      throw new PeerDiscoveryPacketDecodingException("Malformed packet of type: " + packetType, e);
    }

    return new Packet(packetType, packetData, BytesValue.wrapBuffer(message));
  }

  public Buffer encode() {
    final BytesValue encodedSignature = encodeSignature(signature);
    final VertxBufferRLPOutput encodedData = new VertxBufferRLPOutput();
    data.writeTo(encodedData);

    final Buffer buffer =
        Buffer.buffer(hash.size() + encodedSignature.size() + 1 + encodedData.encodedSize());
    hash.appendTo(buffer);
    encodedSignature.appendTo(buffer);
    buffer.appendByte(type.getValue());
    encodedData.appendEncoded(buffer);
    return buffer;
  }

  @SuppressWarnings("unchecked")
  public <T extends PacketData> Optional<T> getPacketData(final Class<T> expectedPacketType) {
    if (data == null || !data.getClass().equals(expectedPacketType)) {
      return Optional.empty();
    }
    return Optional.of((T) data);
  }

  public BytesValue getNodeId() {
    return publicKey.getEncodedBytes();
  }

  public PacketType getType() {
    return type;
  }

  public BytesValue getHash() {
    return hash;
  }

  @Override
  public String toString() {
    return "Packet{"
        + "type="
        + type
        + ", data="
        + data
        + ", hash="
        + hash
        + ", signature="
        + signature
        + ", publicKey="
        + publicKey
        + '}';
  }

  private static BytesValue encodeSignature(final SECP256K1.Signature signature) {
    final MutableBytesValue encoded = MutableBytesValue.create(65);
    UInt256Bytes.of(signature.getR()).copyTo(encoded, 0);
    UInt256Bytes.of(signature.getS()).copyTo(encoded, 32);
    final int v = signature.getRecId();
    encoded.set(64, (byte) v);
    return encoded;
  }

  private static SECP256K1.Signature decodeSignature(final BytesValue encodedSignature) {
    checkArgument(
        encodedSignature != null && encodedSignature.size() == 65, "encodedSignature is 65 bytes");
    final BigInteger r = asUnsignedBigInteger(encodedSignature.slice(0, 32));
    final BigInteger s = asUnsignedBigInteger(encodedSignature.slice(32, 32));
    final int recId = encodedSignature.get(64);
    return SECP256K1.Signature.create(r, s, (byte) recId);
  }
}
