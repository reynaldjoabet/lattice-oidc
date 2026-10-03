package com.lattice.oidc.client;

import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.cfg.EnumFeature;
import tools.jackson.databind.json.JsonMapper;

/**
 * Jackson 3 mapping for Authlete DTOs.
 *
 * <p>The DTOs in authlete-java-common are field-based beans with fluent setters (designed for
 * Gson), so the mapper binds on fields only, ignores unknown properties for forward compatibility
 * with newer Authlete responses, and omits nulls from requests. Enums travel by {@code name()}
 * (Gson's convention); Jackson 3 would otherwise use {@code toString()}, which Authlete enums
 * override with lowercase values.
 */
public final class AuthleteJson {

  private static final JsonMapper MAPPER =
      JsonMapper.builder()
          .changeDefaultVisibility(
              v ->
                  v.withVisibility(PropertyAccessor.ALL, Visibility.NONE)
                      .withVisibility(PropertyAccessor.FIELD, Visibility.ANY))
          .changeDefaultPropertyInclusion(
              incl ->
                  JsonInclude.Value.construct(
                      JsonInclude.Include.NON_NULL, JsonInclude.Include.NON_NULL))
          .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
          .disable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
          .disable(EnumFeature.READ_ENUMS_USING_TO_STRING)
          .disable(EnumFeature.WRITE_ENUMS_USING_TO_STRING)
          .enable(EnumFeature.READ_UNKNOWN_ENUM_VALUES_AS_NULL)
          .build();

  private AuthleteJson() {}

  public static JsonMapper mapper() {
    return MAPPER;
  }
}
