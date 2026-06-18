package com.github.axfyz.sanidy.autoconfigure;

import java.util.Collections;
import java.util.List;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import com.github.axfyz.sanidy.validator.SanidyValidator;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class SanidyWarmup implements ApplicationRunner {
    private final SanidyValidator validator;

    public SanidyWarmup(SanidyValidator validator) {
        this.validator = validator;
    }

    @Override
    public void run(ApplicationArguments args) {
        List<Class<?>> classes = dtoClasses();
        if (classes == null || classes.isEmpty()) {
            log.info("[SanidyWarmUp] no DTO registered, skipping");
            return;
        }
        validator.warmUp(classes.toArray(new Class<?>[0]));
    }

    protected List<Class<?>> dtoClasses() {
        return Collections.emptyList();
    }
}
