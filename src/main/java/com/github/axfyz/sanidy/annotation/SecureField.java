package com.github.axfyz.sanidy.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import com.github.axfyz.sanidy.enums.FieldType;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface SecureField {
    FieldType type();

    int min() default 0;

    int max() default Integer.MAX_VALUE;

    boolean required() default true;

    String[] allowedValues() default {};
}
