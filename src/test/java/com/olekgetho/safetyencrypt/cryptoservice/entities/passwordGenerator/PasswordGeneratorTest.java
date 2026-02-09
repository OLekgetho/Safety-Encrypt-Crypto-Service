package com.olekgetho.safetyencrypt.cryptoservice.entities.passwordGenerator;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PasswordGeneratorTest {

    @Test
    void testNoArgsConstructor() {
        PasswordGenerator passwordGenerator = new PasswordGenerator();
        assertNotNull(passwordGenerator);
        assertFalse(passwordGenerator.isIncludeSymbols());
    }

    @Test
    void testAllArgsConstructor() {
        PasswordGenerator passwordGenerator = new PasswordGenerator(12, true);
        assertNotNull(passwordGenerator);
        assertEquals(12, passwordGenerator.getLengthOfPassword());
        assertTrue(passwordGenerator.isIncludeSymbols());
    }

    @Test
    void testAllArgsConstructorWithSymbolsFalse() {
        PasswordGenerator passwordGenerator = new PasswordGenerator(8, false);
        assertNotNull(passwordGenerator);
        assertEquals(8, passwordGenerator.getLengthOfPassword());
        assertFalse(passwordGenerator.isIncludeSymbols());
    }

    @Test
    void testGettersAndSetters() {
        PasswordGenerator passwordGenerator = new PasswordGenerator();

        passwordGenerator.setLengthOfPassword(16);
        assertEquals(16, passwordGenerator.getLengthOfPassword());

        passwordGenerator.setIncludeSymbols(true);
        assertTrue(passwordGenerator.isIncludeSymbols());

        passwordGenerator.setIncludeSymbols(false);
        assertFalse(passwordGenerator.isIncludeSymbols());
    }

    @Test
    void testDefaultIncludeSymbolsValue() {
        PasswordGenerator passwordGenerator = new PasswordGenerator();
        assertFalse(passwordGenerator.isIncludeSymbols(),
            "Default value for includeSymbols should be false");
    }

    @Test
    void testSetLengthWithMinimumValue() {
        PasswordGenerator passwordGenerator = new PasswordGenerator();
        passwordGenerator.setLengthOfPassword(1);
        assertEquals(1, passwordGenerator.getLengthOfPassword());
    }

    @Test
    void testSetLengthWithLargeValue() {
        PasswordGenerator passwordGenerator = new PasswordGenerator();
        passwordGenerator.setLengthOfPassword(1000);
        assertEquals(1000, passwordGenerator.getLengthOfPassword());
    }

    @Test
    void testSetLengthWithZero() {
        PasswordGenerator passwordGenerator = new PasswordGenerator();
        passwordGenerator.setLengthOfPassword(0);
        assertEquals(0, passwordGenerator.getLengthOfPassword());
    }

    @Test
    void testSetLengthWithNegativeValue() {
        PasswordGenerator passwordGenerator = new PasswordGenerator();
        passwordGenerator.setLengthOfPassword(-5);
        assertEquals(-5, passwordGenerator.getLengthOfPassword());
    }

    @Test
    void testMultipleSettersInSequence() {
        PasswordGenerator passwordGenerator = new PasswordGenerator();

        passwordGenerator.setLengthOfPassword(10);
        passwordGenerator.setIncludeSymbols(true);
        assertEquals(10, passwordGenerator.getLengthOfPassword());
        assertTrue(passwordGenerator.isIncludeSymbols());

        passwordGenerator.setLengthOfPassword(20);
        passwordGenerator.setIncludeSymbols(false);
        assertEquals(20, passwordGenerator.getLengthOfPassword());
        assertFalse(passwordGenerator.isIncludeSymbols());
    }
}