package com.github.axfyz.sanidy.validator;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import com.github.axfyz.sanidy.annotation.SecureField;
import com.github.axfyz.sanidy.enums.FieldType;

public class SanidyValidatorTest {
    private SanidyValidator validator;

    // DTO Test Acc
    static class TestAcc {
        @SecureField(type = FieldType.NUMERIC, min = 8, max = 10)
        String accNo;

        @SecureField(type = FieldType.NUMERIC, max = 4)
        String cardNo;

        TestAcc(String accNo, String cardNo) {
            this.accNo = accNo;
            this.cardNo = cardNo;
        }
    }

    // DTO Test Acc
    static class TestAcc2 {
        @SecureField(type = FieldType.NUMERIC, min = 8, max = 10)
        String accNo;

        @SecureField(type = FieldType.NUMERIC, max = 4)
        String cardNo;

        TestAcc2(String accNo, String cardNo) {
            this.accNo = accNo;
            this.cardNo = cardNo;
        }
    }

    @BeforeEach
    void setUp() {
        validator = new SanidyValidator();
        // WarmUp before test
        validator.warmUp(TestAcc.class, TestAcc2.class);
    }

    @Test
    void validInput() {
        assertDoesNotThrow(() -> validator.validate(new TestAcc("12345678", "1234")));
    }
}
