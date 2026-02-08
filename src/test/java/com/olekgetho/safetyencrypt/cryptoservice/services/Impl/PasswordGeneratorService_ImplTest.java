package com.olekgetho.safetyencrypt.cryptoservice.services.Impl;

import com.olekgetho.safetyencrypt.cryptoservice.entities.passwordGenerator.PasswordGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class PasswordGeneratorService_ImplTest {

    private PasswordGeneratorService_Impl passwordGeneratorService;

    @BeforeEach
    void setUp() {
        passwordGeneratorService = new PasswordGeneratorService_Impl();
    }

    @Test
    void testGeneratePasswordWithoutSymbols() {
        PasswordGenerator config = new PasswordGenerator(12, false);
        String password = passwordGeneratorService.generatePassword(config);

        assertNotNull(password);
        assertEquals(12, password.length());

        // Verify only alphanumeric characters
        String expectedChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        for (char c : password.toCharArray()) {
            assertTrue(expectedChars.indexOf(c) >= 0,
                "Character '" + c + "' should be alphanumeric");
        }
    }

    @Test
    void testGeneratePasswordWithSymbols() {
        PasswordGenerator config = new PasswordGenerator(12, true);
        String password = passwordGeneratorService.generatePassword(config);

        assertNotNull(password);
        assertEquals(12, password.length());

        // Verify only alphanumeric and symbol characters
        String expectedChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
        for (char c : password.toCharArray()) {
            assertTrue(expectedChars.indexOf(c) >= 0,
                "Character '" + c + "' should be alphanumeric or symbol");
        }
    }

    @Test
    void testGeneratePasswordCorrectLength() {
        int[] lengths = {1, 5, 10, 20, 50, 100};
        for (int length : lengths) {
            PasswordGenerator config = new PasswordGenerator(length, false);
            String password = passwordGeneratorService.generatePassword(config);

            assertEquals(length, password.length(),
                "Password length should be " + length);
        }
    }

    @Test
    void testGeneratePasswordWithLengthOne() {
        PasswordGenerator config = new PasswordGenerator(1, false);
        String password = passwordGeneratorService.generatePassword(config);

        assertNotNull(password);
        assertEquals(1, password.length());

        String expectedChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        assertTrue(expectedChars.indexOf(password.charAt(0)) >= 0);
    }

    @Test
    void testGeneratePasswordWithLengthZero() {
        PasswordGenerator config = new PasswordGenerator(0, false);
        String password = passwordGeneratorService.generatePassword(config);

        assertNotNull(password);
        assertEquals(0, password.length());
        assertEquals("", password);
    }

    @Test
    void testGeneratePasswordRandomness() {
        PasswordGenerator config = new PasswordGenerator(20, false);
        Set<String> generatedPasswords = new HashSet<>();

        // Generate 100 passwords and verify they are different
        for (int i = 0; i < 100; i++) {
            String password = passwordGeneratorService.generatePassword(config);
            generatedPasswords.add(password);
        }

        // With SecureRandom and 20 character length from 62 char pool,
        // collision is extremely unlikely. Expect at least 99 unique passwords
        assertTrue(generatedPasswords.size() >= 99,
            "Generated passwords should be highly random and unique");
    }

    @Test
    void testGeneratePasswordSymbolsAreIncluded() {
        PasswordGenerator config = new PasswordGenerator(1000, true);
        String password = passwordGeneratorService.generatePassword(config);

        String symbols = "!@#$%^&*";
        boolean hasSymbol = false;
        for (char c : password.toCharArray()) {
            if (symbols.indexOf(c) >= 0) {
                hasSymbol = true;
                break;
            }
        }

        // With 1000 characters and 8 symbols out of 70 total chars,
        // probability of having at least one symbol is very high
        assertTrue(hasSymbol,
            "Password should contain at least one symbol when includeSymbols is true");
    }

    @Test
    void testGeneratePasswordOnlyValidSymbols() {
        PasswordGenerator config = new PasswordGenerator(100, true);
        String password = passwordGeneratorService.generatePassword(config);

        String validSymbols = "!@#$%^&*";
        String invalidSymbols = "()[]{}|\\/<>,.?;:'\"~`-_=+";

        for (char c : password.toCharArray()) {
            if (!Character.isLetterOrDigit(c)) {
                assertTrue(validSymbols.indexOf(c) >= 0,
                    "Symbol '" + c + "' should be one of: !@#$%^&*");
                assertFalse(invalidSymbols.indexOf(c) >= 0,
                    "Symbol '" + c + "' should not be included");
            }
        }
    }

    @Test
    void testGeneratePasswordWithoutSymbolsDoesNotContainSymbols() {
        PasswordGenerator config = new PasswordGenerator(1000, false);
        String password = passwordGeneratorService.generatePassword(config);

        String allSymbols = "!@#$%^&*()[]{}|\\/<>,.?;:'\"~`-_=+";
        for (char c : password.toCharArray()) {
            assertFalse(allSymbols.indexOf(c) >= 0,
                "Password should not contain any symbols when includeSymbols is false");
        }
    }

    @Test
    void testGeneratePasswordContainsUppercase() {
        PasswordGenerator config = new PasswordGenerator(100, false);
        String password = passwordGeneratorService.generatePassword(config);

        boolean hasUppercase = false;
        for (char c : password.toCharArray()) {
            if (Character.isUpperCase(c)) {
                hasUppercase = true;
                break;
            }
        }

        assertTrue(hasUppercase,
            "Password should contain at least one uppercase letter");
    }

    @Test
    void testGeneratePasswordContainsLowercase() {
        PasswordGenerator config = new PasswordGenerator(100, false);
        String password = passwordGeneratorService.generatePassword(config);

        boolean hasLowercase = false;
        for (char c : password.toCharArray()) {
            if (Character.isLowerCase(c)) {
                hasLowercase = true;
                break;
            }
        }

        assertTrue(hasLowercase,
            "Password should contain at least one lowercase letter");
    }

    @Test
    void testGeneratePasswordContainsDigit() {
        PasswordGenerator config = new PasswordGenerator(100, false);
        String password = passwordGeneratorService.generatePassword(config);

        boolean hasDigit = false;
        for (char c : password.toCharArray()) {
            if (Character.isDigit(c)) {
                hasDigit = true;
                break;
            }
        }

        assertTrue(hasDigit,
            "Password should contain at least one digit");
    }

    @Test
    void testGeneratePasswordDifferentEachTime() {
        PasswordGenerator config = new PasswordGenerator(16, false);
        String password1 = passwordGeneratorService.generatePassword(config);
        String password2 = passwordGeneratorService.generatePassword(config);
        String password3 = passwordGeneratorService.generatePassword(config);

        assertNotEquals(password1, password2,
            "Consecutive password generations should produce different results");
        assertNotEquals(password2, password3,
            "Consecutive password generations should produce different results");
        assertNotEquals(password1, password3,
            "Consecutive password generations should produce different results");
    }

    @Test
    void testGeneratePasswordWithLargeLength() {
        PasswordGenerator config = new PasswordGenerator(10000, false);
        String password = passwordGeneratorService.generatePassword(config);

        assertNotNull(password);
        assertEquals(10000, password.length());

        String expectedChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        for (char c : password.toCharArray()) {
            assertTrue(expectedChars.indexOf(c) >= 0);
        }
    }

    @Test
    void testGeneratePasswordCharacterDistribution() {
        // Test that SecureRandom provides good distribution
        PasswordGenerator config = new PasswordGenerator(1000, false);
        String password = passwordGeneratorService.generatePassword(config);

        int uppercaseCount = 0;
        int lowercaseCount = 0;
        int digitCount = 0;

        for (char c : password.toCharArray()) {
            if (Character.isUpperCase(c)) uppercaseCount++;
            else if (Character.isLowerCase(c)) lowercaseCount++;
            else if (Character.isDigit(c)) digitCount++;
        }

        // With 1000 characters from pool of 26+26+10=62 chars
        // Expected: ~419 uppercase, ~419 lowercase, ~162 digits
        // Allow 20% deviation from expected
        assertTrue(uppercaseCount > 300 && uppercaseCount < 550,
            "Uppercase distribution should be reasonable, got: " + uppercaseCount);
        assertTrue(lowercaseCount > 300 && lowercaseCount < 550,
            "Lowercase distribution should be reasonable, got: " + lowercaseCount);
        assertTrue(digitCount > 100 && digitCount < 250,
            "Digit distribution should be reasonable, got: " + digitCount);
    }

    @Test
    void testGeneratePasswordMultipleConfigsIndependence() {
        PasswordGenerator config1 = new PasswordGenerator(10, false);
        PasswordGenerator config2 = new PasswordGenerator(20, true);

        String password1 = passwordGeneratorService.generatePassword(config1);
        String password2 = passwordGeneratorService.generatePassword(config2);

        assertEquals(10, password1.length());
        assertEquals(20, password2.length());

        // Verify config1 password has no symbols
        String symbols = "!@#$%^&*";
        for (char c : password1.toCharArray()) {
            assertFalse(symbols.indexOf(c) >= 0);
        }
    }
}