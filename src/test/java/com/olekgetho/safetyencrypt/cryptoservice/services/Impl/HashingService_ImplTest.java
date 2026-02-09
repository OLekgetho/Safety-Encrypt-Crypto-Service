package com.olekgetho.safetyencrypt.cryptoservice.services.Impl;

import com.olekgetho.safetyencrypt.cryptoservice.entities.hashing.BruteForce;
import com.olekgetho.safetyencrypt.cryptoservice.entities.hashing.HashingAlgorithms;
import com.olekgetho.safetyencrypt.cryptoservice.entities.hashing.HashingText;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;

public class HashingService_ImplTest {

    private HashingService_Impl hashingService_Impl;

    @BeforeEach
    void setUp() {
        hashingService_Impl = new HashingService_Impl();
    }

    @Test
    void testHashingTextWithBcrypt() {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder(12);
        HashingText hashingText = new HashingText("Ofentse", HashingAlgorithms.Bcrypt);
        String bcryptHashedText = hashingService_Impl.hashingText(hashingText);

        assertNotNull(bcryptHashedText);
        assertTrue(bCryptPasswordEncoder.matches(hashingText.getText(), bcryptHashedText));
    }

    @Test
    void testHashingTextWithArgon2() {
        Argon2PasswordEncoder argon2PasswordEncoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
        HashingText hashingText = new HashingText("Ofentse", HashingAlgorithms.Argon2);
        String argon2HashedText = hashingService_Impl.hashingText(hashingText);

        assertNotNull(argon2HashedText);
        assertTrue(argon2PasswordEncoder.matches(hashingText.getText(), argon2HashedText));
    }

    @Test
    void testHashingTextWithPBKDF2() {
        Pbkdf2PasswordEncoder pbkdf2PasswordEncoder = Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8();
        HashingText hashingText = new HashingText("Ofentse", HashingAlgorithms.PBKDF2);
        String pdkdf2HashedText = hashingService_Impl.hashingText(hashingText);

        assertNotNull(pdkdf2HashedText);
        assertTrue(pbkdf2PasswordEncoder.matches(hashingText.getText(), pdkdf2HashedText));
    }

    @Test
    void testHashingTestWithScrypt() {
        SCryptPasswordEncoder sCryptPasswordEncoder = SCryptPasswordEncoder.defaultsForSpringSecurity_v5_8();
        HashingText hashingText = new HashingText("Ofentse", HashingAlgorithms.scrypt);
        String scryptHashedText = hashingService_Impl.hashingText(hashingText);

        assertNotNull(scryptHashedText);
        assertTrue(sCryptPasswordEncoder.matches(hashingText.getText(), scryptHashedText));
    }

    @Test
    void testHashingTestWithBcryptButMatchWithArgon2() {
        Argon2PasswordEncoder argon2PasswordEncoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
        HashingText hashingText = new HashingText("Ofentse", HashingAlgorithms.Bcrypt);
        String bcryptHashedText = hashingService_Impl.hashingText(hashingText);

        assertFalse(argon2PasswordEncoder.matches(hashingText.getText(), bcryptHashedText));
    }

    @Test
    void testBruteForceEmptyFile() {
        String csvContent = """
                """;

        MockMultipartFile file = new MockMultipartFile(
                "file",
                "password.csv",
                "text/csv",
                csvContent.getBytes()
        );

        HashingText hashedText = new HashingText(
                "$100801$GPPG6dCaWxOIxvaRdbwm3w==$DEr5RUhcUCKOJhwuuXof+Ms/cPDvtmkaFk5kXIodLYQ=",
                HashingAlgorithms.scrypt);

        BruteForce attemptBrute = hashingService_Impl.bruteForcePassword(file,hashedText);
        assertEquals("File Empty", attemptBrute.getBruteforceText());
        assertFalse(attemptBrute.isBruteForceOutcome());

    }

    @Test
    void testBruteForceWithNoCorrectPassword() {
        String csvContent = """
        pass
        jumpcable
        lekgetho
        password
        Ofentse
        """;

        MockMultipartFile file = new MockMultipartFile(
                "file",
                "password.csv",
                "text/csv",
                csvContent.getBytes()
        );

        HashingText hashedText = new HashingText(
                "$100801$GPPG6dCaWxOIxvaRdbwm3w==$DEr5RUhcUCKOJhwuuXof+Ms/cPDvtmkaFk5kXIodLYQ=",
                HashingAlgorithms.scrypt);

        BruteForce attemptBruteForce = hashingService_Impl.bruteForcePassword(file, hashedText);

        assertEquals("No match found in the file", attemptBruteForce.getBruteforceText());
        assertFalse(attemptBruteForce.isBruteForceOutcome());
    }

    @Test
    void testBruteForceWithACorrectPassword() {
        String csvContent = """
        pass
        jumpcable
        lekgetho
        Password123
        password
        Ofentse
        """;


        MockMultipartFile file = new MockMultipartFile(
                "file",
                "password.csv",
                "text/csv",
                csvContent.getBytes()
        );

        HashingText hashedText = new HashingText(
                "$100801$jo7HT9wb4gOYhhWmkX7/0Q==$6Btj62q+kKopmyVEbzbfVSzJSlg++JYkFRxnoSprqac=",
                HashingAlgorithms.scrypt);

        BruteForce attemptBruteForce = hashingService_Impl.bruteForcePassword(file, hashedText);

        assertEquals("Password123", attemptBruteForce.getBruteforceText());
        assertTrue(attemptBruteForce.isBruteForceOutcome());

    }
}
