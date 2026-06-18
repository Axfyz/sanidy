package com.github.axfyz.sanidy.exception;

public class SanidyException extends RuntimeException {
    public SanidyException(String message) {
        super(message);
    }

    public SanidyException(String message, Throwable cause) {
        super(message, cause);
    }
}
