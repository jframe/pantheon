package tech.pegasys.pantheon.consensus.ibft;


import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;

public class MaxSizeEvictingMapTest {

  @Test
  public void evictMessageRecordAtCapacity() {
    MaxSizeEvictingMap<String, Boolean> map = new MaxSizeEvictingMap<>(5);

    map.put("message1", true);
    assertThat(map).hasSize(1);

    // add messages so map is at capacity
    for (int i=2; i<=5; i++) {
      map.put("message" + i, true);
    }
    assertThat(map).hasSize(5);

    map.put("message6", false);
    assertThat(map).hasSize(5);
    assertThat(map.keySet()).doesNotContain("message1");
    assertThat(map.keySet()).contains("message2", "message3", "message4", "message5", "message6");

    map.put("message7", true);
    assertThat(map).hasSize(5);
    assertThat(map.keySet()).doesNotContain("message1", "message2");
    assertThat(map.keySet()).contains("message3", "message4", "message5", "message6", "message7");
  }

}