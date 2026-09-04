package com.farmtohome.api.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FirebaseConfig {
  @Bean
  @ConditionalOnMissingBean(ObjectMapper.class)
  ObjectMapper legacyObjectMapper() {
    return new ObjectMapper().findAndRegisterModules();
  }
}
