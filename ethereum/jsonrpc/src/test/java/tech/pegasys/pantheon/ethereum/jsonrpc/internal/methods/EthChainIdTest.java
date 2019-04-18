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
package tech.pegasys.pantheon.ethereum.jsonrpc.internal.methods;

import static org.assertj.core.api.Assertions.assertThat;

import tech.pegasys.pantheon.ethereum.jsonrpc.internal.JsonRpcRequest;
import tech.pegasys.pantheon.ethereum.jsonrpc.internal.response.JsonRpcResponse;
import tech.pegasys.pantheon.ethereum.jsonrpc.internal.response.JsonRpcSuccessResponse;
import tech.pegasys.pantheon.ethereum.jsonrpc.internal.results.Quantity;

import java.math.BigInteger;
import java.util.Optional;

import org.junit.Before;
import org.junit.Test;

public class EthChainIdTest {

  private EthChainId method;
  private final BigInteger CHAIN_ID = BigInteger.ONE;

  @Before
  public void setUp() {
    method = new EthChainId(Optional.of(CHAIN_ID));
  }

  @Test
  public void shouldReturnCorrectMethodName() {
    assertThat(method.getName()).isEqualTo("eth_chainId");
  }

  @Test
  public void shouldReturnChainId() {
    JsonRpcResponse expectedResponse = new JsonRpcSuccessResponse(null, Quantity.create(CHAIN_ID));

    JsonRpcResponse response = method.response(request());

    assertThat(response).isEqualToComparingFieldByField(expectedResponse);
  }

  private JsonRpcRequest request() {
    return new JsonRpcRequest(null, "eth_chainId", null);
  }
}
