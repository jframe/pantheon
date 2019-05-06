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

import tech.pegasys.pantheon.config.GenesisConfigFile;
import tech.pegasys.pantheon.ethereum.core.PrivacyParameters;

import java.nio.charset.StandardCharsets;

import com.google.common.io.Resources;
import io.vertx.core.json.JsonObject;
import org.assertj.core.api.Assertions;
import org.junit.Test;

public class MainnetProtocolScheduleTest {

  @Test
  public void shouldReturnDefaultProtocolSpecsWhenCustomNumbersAreNotUsed() {
    final ProtocolSchedule<Void> sched = MainnetProtocolSchedule.create();
    Assertions.assertThat(sched.getByBlockNumber(1L).getName()).isEqualTo("Frontier");
    Assertions.assertThat(sched.getByBlockNumber(1_150_000L).getName()).isEqualTo("Homestead");
    Assertions.assertThat(sched.getByBlockNumber(1_920_000L).getName())
        .isEqualTo("DaoRecoveryInit");
    Assertions.assertThat(sched.getByBlockNumber(1_920_001L).getName())
        .isEqualTo("DaoRecoveryTransition");
    Assertions.assertThat(sched.getByBlockNumber(1_920_010L).getName()).isEqualTo("Homestead");
    Assertions.assertThat(sched.getByBlockNumber(2_463_000L).getName())
        .isEqualTo("TangerineWhistle");
    Assertions.assertThat(sched.getByBlockNumber(2_675_000L).getName()).isEqualTo("SpuriousDragon");
    Assertions.assertThat(sched.getByBlockNumber(4_730_000L).getName()).isEqualTo("Byzantium");
    // Constantinople was originally scheduled for 7_080_000, but postponed
    Assertions.assertThat(sched.getByBlockNumber(7_080_000L).getName()).isEqualTo("Byzantium");
    Assertions.assertThat(sched.getByBlockNumber(7_280_000L).getName())
        .isEqualTo("ConstantinopleFix");
    Assertions.assertThat(sched.getByBlockNumber(Long.MAX_VALUE).getName())
        .isEqualTo("ConstantinopleFix");
  }

  @Test
  public void shouldOnlyUseFrontierWhenEmptyJsonConfigIsUsed() {
    final JsonObject json = new JsonObject("{}");
    final ProtocolSchedule<Void> sched =
        MainnetProtocolSchedule.fromConfig(GenesisConfigFile.fromConfig(json).getConfigOptions());
    Assertions.assertThat(sched.getByBlockNumber(1L).getName()).isEqualTo("Frontier");
    Assertions.assertThat(sched.getByBlockNumber(Long.MAX_VALUE).getName()).isEqualTo("Frontier");
  }

  @Test
  public void createFromConfigWithSettings() {
    final JsonObject json =
        new JsonObject(
            "{\"config\": {\"homesteadBlock\": 2, \"daoForkBlock\": 3, \"eip150Block\": 14, \"eip158Block\": 15, \"byzantiumBlock\": 16, \"constantinopleBlock\": 18, \"constantinopleFixBlock\": 19, \"chainId\":1234}}");
    final ProtocolSchedule<Void> sched =
        MainnetProtocolSchedule.fromConfig(GenesisConfigFile.fromConfig(json).getConfigOptions());
    Assertions.assertThat(sched.getByBlockNumber(1).getName()).isEqualTo("Frontier");
    Assertions.assertThat(sched.getByBlockNumber(2).getName()).isEqualTo("Homestead");
    Assertions.assertThat(sched.getByBlockNumber(3).getName()).isEqualTo("DaoRecoveryInit");
    Assertions.assertThat(sched.getByBlockNumber(4).getName()).isEqualTo("DaoRecoveryTransition");
    Assertions.assertThat(sched.getByBlockNumber(13).getName()).isEqualTo("Homestead");
    Assertions.assertThat(sched.getByBlockNumber(14).getName()).isEqualTo("TangerineWhistle");
    Assertions.assertThat(sched.getByBlockNumber(15).getName()).isEqualTo("SpuriousDragon");
    Assertions.assertThat(sched.getByBlockNumber(16).getName()).isEqualTo("Byzantium");
    Assertions.assertThat(sched.getByBlockNumber(18).getName()).isEqualTo("Constantinople");
    Assertions.assertThat(sched.getByBlockNumber(19).getName()).isEqualTo("ConstantinopleFix");
  }

  @Test
  public void outOfOrderForksFails() {
    final JsonObject json =
        new JsonObject(
            "{\"config\": {\"homesteadBlock\": 2, \"daoForkBlock\": 3, \"eip150Block\": 14, \"eip158Block\": 15, \"byzantiumBlock\": 16, \"constantinopleBlock\": 18, \"constantinopleFixBlock\": 17, \"chainId\":1234}}");
    Assertions.assertThatExceptionOfType(RuntimeException.class)
        .describedAs(
            "Genesis Config Error: 'ConstantinopleFix' is scheduled for block 17 but it must be on or after block 18.")
        .isThrownBy(
            () ->
                MainnetProtocolSchedule.fromConfig(
                    GenesisConfigFile.fromConfig(json).getConfigOptions()));
  }

  @Test
  public void shouldCreateRopstenConfig() throws Exception {
    final ProtocolSchedule<Void> sched =
        MainnetProtocolSchedule.fromConfig(
            GenesisConfigFile.fromConfig(
                    Resources.toString(
                        this.getClass().getResource("/ropsten.json"), StandardCharsets.UTF_8))
                .getConfigOptions(),
            PrivacyParameters.DEFAULT);
    Assertions.assertThat(sched.getByBlockNumber(0).getName()).isEqualTo("TangerineWhistle");
    Assertions.assertThat(sched.getByBlockNumber(1).getName()).isEqualTo("TangerineWhistle");
    Assertions.assertThat(sched.getByBlockNumber(10).getName()).isEqualTo("SpuriousDragon");
    Assertions.assertThat(sched.getByBlockNumber(1700000).getName()).isEqualTo("Byzantium");
    Assertions.assertThat(sched.getByBlockNumber(4230000).getName()).isEqualTo("Constantinople");
    Assertions.assertThat(sched.getByBlockNumber(4939394).getName()).isEqualTo("ConstantinopleFix");
    Assertions.assertThat(sched.getByBlockNumber(Long.MAX_VALUE).getName())
        .isEqualTo("ConstantinopleFix");
  }
}
