package com.olekgetho.safetyencrypt.cryptoservice.services.Impl;

import com.olekgetho.safetyencrypt.cryptoservice.entities.hashing.BruteForce;
import com.olekgetho.safetyencrypt.cryptoservice.entities.hashing.HashingAlgorithms;
import com.olekgetho.safetyencrypt.cryptoservice.entities.hashing.HashingText;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockMultipartFile;

import static org.junit.jupiter.api.Assertions.*;

public class BruteForceService_ImplTest {

    private BruteForceService_Impl bruteForceService_Impl;

    @BeforeEach
    void setUp() {
        bruteForceService_Impl = new BruteForceService_Impl();
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

        BruteForce attemptBrute = bruteForceService_Impl.bruteForcePassword(file,hashedText);
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

        BruteForce attemptBruteForce = bruteForceService_Impl.bruteForcePassword(file, hashedText);

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

        BruteForce attemptBruteForce = bruteForceService_Impl.bruteForcePassword(file, hashedText);

        assertEquals("Password123", attemptBruteForce.getBruteforceText());
        assertTrue(attemptBruteForce.isBruteForceOutcome());

    }
}
