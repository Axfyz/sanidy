package com.github.axfyz.sanidy.validator;

import java.lang.reflect.Field;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;
import com.github.axfyz.sanidy.annotation.SecureField;
import com.github.axfyz.sanidy.exception.SanidyException;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class SanidyValidator {
    /**
     * Cache
     * Save result scan reflection
     */
    private final ConcurrentHashMap<Class<?>, List<FieldMetadata>> fieldCache = new ConcurrentHashMap<>();

    /**
     * Wrapper field & annotation
     */
    private static class FieldMetadata {
        final Field field;
        final SecureField annotation;

        FieldMetadata(Field field, SecureField annotation) {
            this.field = field;
            this.annotation = annotation;
        }
    }

    /**
     * WarmUp
     */
    public void warmUp(Class<?>... classes) {
        log.info("[Sandiy WarmUp] Start cached");
        for (Class<?> clazz : classes) {
            getFieldMetadata(clazz);
            log.info("[Sandiy WarmUp] Cache {}", clazz.getSimpleName());
        }
        log.info("[Sanidy WarmUp] Complete — {} class(es) cached", classes.length);
    }

    /**
     * Get from cache
     * If none scan first
     */
    private List<FieldMetadata> getFieldMetadata(Class<?> clazz) {
        return fieldCache.computeIfAbsent(clazz, this::scanFields);
    }

    /**
     * Scan reflection
     */
    private List<FieldMetadata> scanFields(Class<?> clazz) {
        List<FieldMetadata> result = new ArrayList<>();
        Class<?> current = clazz;

        while (current != null && current != Object.class) {
            for (Field field : current.getDeclaredFields()) {
                if (field.isAnnotationPresent(SecureField.class)) {
                    field.setAccessible(true);
                    result.add(new FieldMetadata(field, field.getAnnotation(SecureField.class)));
                }
            }
            current = current.getSuperclass();
        }

        return result;
    }

    /**
     * Pattern
     */
    private static final Pattern NUMERIC_ONLY = Pattern.compile("^[0-9]+$");
    private static final Pattern NAME_PATTERN = Pattern.compile("^[a-zA-Z\\s.,'\\-]+$");
    private static final Pattern ALPHANUMERIC = Pattern.compile("^[a-zA-Z0-9\\s]+$");
    private static final Pattern AMOUNT_PATTERN = Pattern.compile("^[0-9]+(\\.[0-9]{1,2})?$");
    private static final Pattern DATE_PATTERN = Pattern.compile("^\\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\\d|3[01])$");
    private static final Pattern EMAIL_PATTERN = Pattern
            .compile("^[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}$");
    private static final Pattern PHONE_PATTERN = Pattern.compile("^[0-9+\\-\\s]{7,20}$");

    /**
     * Blacklists
     */
    private static final List<String> SQL_KEYWORDS = Arrays.asList(
            "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION",
            "ALTER", "CREATE", "EXEC", "TRUNCATE", "--", "/*", "*/", "0x");

    private static final List<String> URL_SCHEMES = Arrays.asList(
            "http://", "https://", "ftp://", "file://",
            "dict://", "gopher://", "ldap://", "://");

    private static final List<String> XSS_PATTERNS = Arrays.asList(
            "<script", "javascript:", "onerror=", "onload=", "onclick=",
            "<iframe", "<svg", "alert(", "eval(", "document.cookie", "window.location");

    private static final List<String> BLOCKED_HOSTS = Arrays.asList();

    public void validate(Object obj) {
        if (obj == null) {
            throw new SanidyException("Request body must not be null");
        }

        // Load from cache
        List<FieldMetadata> fields = getFieldMetadata(obj.getClass());
        List<String> errors = new ArrayList<>();

        for (FieldMetadata metadata : fields) {
            try {
                Object value = metadata.field.get(obj);
                List<String> fieldErrors = validateField(
                        value,
                        metadata.field.getName(),
                        metadata.annotation);
                errors.addAll(fieldErrors);
            } catch (IllegalAccessException e) {
                errors.add(metadata.field.getName() + ": cannot access field");
            }
        }

        if (!errors.isEmpty()) {
            throw new SanidyException(String.join(" | ", errors));
        }
    }

    /**
     * Validate field
     */
    private List<String> validateField(Object value, String fieldName, SecureField annotation) {
        List<String> errors = new ArrayList<>();
        String strValue = value != null ? value.toString().trim() : null;

        // Check required
        if (strValue == null || strValue.isEmpty()) {
            if (annotation.required()) {
                errors.add(fieldName + ": must not be empty");
            }
            return errors; // stop, tidak perlu cek lanjut kalau kosong
        }

        // Check injection for all type
        errors.addAll(checkInjection(strValue, fieldName));
        if (!errors.isEmpty())
            return errors;

        // Check based type
        switch (annotation.type()) {
            case NUMERIC:
                if (!NUMERIC_ONLY.matcher(strValue).matches()) {
                    errors.add(fieldName + ": must be numeric only");
                } else {
                    errors.addAll(checkLength(strValue, fieldName, annotation.min(), annotation.max()));
                }
                break;

            case NAME:
                if (!NAME_PATTERN.matcher(strValue).matches()) {
                    errors.add(fieldName + ": invalid name format");
                } else {
                    errors.addAll(checkLength(strValue, fieldName, annotation.min(), annotation.max()));
                }
                break;

            case ALPHANUMERIC:
                if (!ALPHANUMERIC.matcher(strValue).matches()) {
                    errors.add(fieldName + ": alphanumeric only");
                } else {
                    errors.addAll(checkLength(strValue, fieldName, annotation.min(), annotation.max()));
                }
                break;

            case AMOUNT:
                if (!AMOUNT_PATTERN.matcher(strValue).matches()) {
                    errors.add(fieldName + ": invalid amount format");
                } else if (new BigDecimal(strValue).compareTo(BigDecimal.ZERO) <= 0) {
                    errors.add(fieldName + ": amount must be greater than 0");
                }
                break;

            case DATE:
                if (!DATE_PATTERN.matcher(strValue).matches()) {
                    errors.add(fieldName + ": invalid date format, use YYYY-MM-DD");
                }
                break;

            case EMAIL:
                if (!EMAIL_PATTERN.matcher(strValue.toLowerCase()).matches()) {
                    errors.add(fieldName + ": invalid email format");
                }
                break;

            case PHONE:
                if (!PHONE_PATTERN.matcher(strValue).matches()) {
                    errors.add(fieldName + ": invalid phone format");
                }
                break;

            case ENUM:
                List<String> allowed = Arrays.asList(annotation.allowedValues());
                if (allowed.isEmpty()) {
                    errors.add(fieldName + ": allowedValues must be defined for ENUM type");
                } else if (!allowed.contains(strValue)) {
                    errors.add(fieldName + ": must be one of: " + String.join(", ", allowed));
                }
                break;

            case FREE_TEXT:
                errors.addAll(checkLength(strValue, fieldName, annotation.min(), annotation.max()));
                break;

            default:
                errors.add(fieldName + ": unknown field type");
        }

        return errors;
    }

    /**
     * Check injection
     */
    private List<String> checkInjection(String value, String field) {
        List<String> errors = new ArrayList<>();
        String lower = value.toLowerCase();
        String upper = value.toUpperCase();

        // Check SSRF — URL scheme
        for (String scheme : URL_SCHEMES) {
            if (lower.contains(scheme)) {
                errors.add(field + ": URL input is not allowed");
                return errors; // stop, tidak perlu cek lanjut
            }
        }

        // Check SSRF — blocked host/IP
        for (String host : BLOCKED_HOSTS) {
            if (lower.contains(host)) {
                errors.add(field + ": internal address is not allowed");
                return errors;
            }
        }

        // Check SQL Injection
        for (String keyword : SQL_KEYWORDS) {
            if (upper.contains(keyword)) {
                errors.add(field + ": invalid input detected");
                return errors;
            }
        }

        // Check XSS
        for (String pattern : XSS_PATTERNS) {
            if (lower.contains(pattern)) {
                errors.add(field + ": invalid input detected");
                return errors;
            }
        }

        return errors;
    }

    /**
     * Check length field
     */
    private List<String> checkLength(String value, String field, int min, int max) {
        List<String> errors = new ArrayList<>();
        if (value.length() < min || value.length() > max) {
            errors.add(field + ": length must be between " + min + " and " + max);
        }
        return errors;
    }
}
