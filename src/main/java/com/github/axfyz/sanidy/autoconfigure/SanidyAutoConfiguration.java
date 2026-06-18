package com.github.axfyz.sanidy.autoconfigure;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import com.github.axfyz.sanidy.validator.SanidyValidator;

@Configuration
public class SanidyAutoConfiguration {
    @Bean
    @ConditionalOnMissingBean
    public SanidyValidator sanidyValidator() {
        return new SanidyValidator();
    }
}
