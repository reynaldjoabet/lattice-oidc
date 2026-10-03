package com.lattice.oidc.http;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;
import java.util.Map;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;

/** Jackson 3 helpers for the server's own JSON (not Authlete DTOs; see AuthleteJson). */
public final class Jsons {

  public static final JsonMapper MAPPER =
      JsonMapper.builder()
          .changeDefaultPropertyInclusion(
              incl ->
                  JsonInclude.Value.construct(
                      JsonInclude.Include.NON_NULL, JsonInclude.Include.NON_NULL))
          .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
          .build();

  private static final JsonMapper PRETTY =
      MAPPER.rebuild().enable(SerializationFeature.INDENT_OUTPUT).build();

  private Jsons() {}

  public static String write(Object value) {
    return MAPPER.writeValueAsString(value);
  }

  public static String pretty(Object value) {
    return PRETTY.writeValueAsString(value);
  }

  public static <T> T read(String json, Class<T> type) {
    return MAPPER.readValue(json, type);
  }

  public static Map<String, Object> readMap(String json) {
    return MAPPER.readValue(json, new TypeReference<Map<String, Object>>() {});
  }

  public static List<Object> readList(String json) {
    return MAPPER.readValue(json, new TypeReference<List<Object>>() {});
  }
}
