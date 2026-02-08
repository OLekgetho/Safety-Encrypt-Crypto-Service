package com.olekgetho.safetyencrypt.cryptoservice.entities.hashing;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class HashingTextTest {

    @Test
    void testNoArgsConstructor() {
        HashingText hashingText = new HashingText();
        assertNotNull(hashingText);
        assertEquals(HashingAlgorithms.Argon2, hashingText.getHashingAlgorithms());
    }

    @Test
    void testAllArgsConstructor() {
        HashingText hashingText = new HashingText("Ofentse", HashingAlgorithms.Bcrypt);
        assertNotNull(hashingText);
        assertEquals("Ofentse", hashingText.getText());
        assertEquals(HashingAlgorithms.Bcrypt, hashingText.getHashingAlgorithms());
    }
}
