package com.github.axfyz.sanidy.autoconfigure;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import com.github.axfyz.sanidy.config.SanidyProperties;
import com.github.axfyz.sanidy.validator.SanidyValidator;

@Configuration
@EnableConfigurationProperties(SanidyProperties.class)
public class SanidyAutoConfiguration {
    @Bean
    @ConditionalOnMissingBean
    public SanidyValidator sanidyValidator(SanidyProperties properties) {
        return new SanidyValidator(properties);
    }
}
