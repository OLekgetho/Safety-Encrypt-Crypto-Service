package com.olekgetho.safetyencrypt.cryptoservice.services.Impl;

import com.olekgetho.safetyencrypt.cryptoservice.entities.hashing.BruteForce;
import com.olekgetho.safetyencrypt.cryptoservice.entities.hashing.HashingAlgorithms;
import com.olekgetho.safetyencrypt.cryptoservice.entities.hashing.HashingText;
import com.olekgetho.safetyencrypt.cryptoservice.services.HashingService;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

@Service
public class HashingService_Impl implements HashingService {

    @Override
    public String hashingText(HashingText hashingText) {
        String hashedText = "";

        if (hashingText.getHashingAlgorithms() == HashingAlgorithms.Bcrypt) {
            BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder(12);
            hashedText = bCryptPasswordEncoder.encode(hashingText.getText());
        }

        else if (hashingText.getHashingAlgorithms() == HashingAlgorithms.Argon2) {
            Argon2PasswordEncoder argon2PasswordEncoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
            hashedText = argon2PasswordEncoder.encode(hashingText.getText());
        }

        else if (hashingText.getHashingAlgorithms() == HashingAlgorithms.PBKDF2) {
            Pbkdf2PasswordEncoder pbkdf2PasswordEncoder = Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8();
            hashedText = pbkdf2PasswordEncoder.encode(hashingText.getText());
        }
        else {
            SCryptPasswordEncoder sCryptPasswordEncoder = SCryptPasswordEncoder.defaultsForSpringSecurity_v5_8();
            hashedText = sCryptPasswordEncoder.encode(hashingText.getText());
        }

        return hashedText;
    }

    @Override
    public BruteForce bruteForcePassword(MultipartFile csvFile, HashingText hashingText) {
        BruteForce outComeBruteForce = new BruteForce();

        if (csvFile.isEmpty()) {
            outComeBruteForce.setBruteforceText("File Empty");
            return outComeBruteForce;
        }
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(csvFile.getInputStream()
                , StandardCharsets.UTF_8))) {

            String line;
            while ((line = reader.readLine()) != null) {

                if (line.trim().isEmpty()) continue;

                BruteForce attempt = bruteForce(line, hashingText);

                if (attempt.isBruteForceOutcome()) {
                    return attempt;
                }
            }

            outComeBruteForce.setBruteforceText("No match found in the file");
            return outComeBruteForce;

        } catch (Exception e) {
            outComeBruteForce.setBruteForceOutcome(false);
            outComeBruteForce.setBruteforceText("Error processing file " + e.getMessage());
            return outComeBruteForce;
        }
    }

    private BruteForce bruteForce(String line, HashingText hashingText) {
        BruteForce bruteForceoutcome = new BruteForce();

        if (hashingText.getHashingAlgorithms() == HashingAlgorithms.Bcrypt) {
            BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder(12);
            if (bCryptPasswordEncoder.matches(line, hashingText.getText())) {
                bruteForceoutcome.setBruteForceOutcome(true);
                bruteForceoutcome.setBruteforceText(line);
            }
        } else if (hashingText.getHashingAlgorithms() == HashingAlgorithms.Argon2) {
            Argon2PasswordEncoder argon2PasswordEncoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
            if (argon2PasswordEncoder.matches(line, hashingText.getText())) {
                bruteForceoutcome.setBruteForceOutcome(true);
                bruteForceoutcome.setBruteforceText(line);
            }
        }
        else if (hashingText.getHashingAlgorithms() == HashingAlgorithms.PBKDF2) {
            Pbkdf2PasswordEncoder pbkdf2PasswordEncoder = Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8();
            if (pbkdf2PasswordEncoder.matches(line, hashingText.getText())) {
                bruteForceoutcome.setBruteForceOutcome(true);
                bruteForceoutcome.setBruteforceText(line);
            }
        }
        else {
            SCryptPasswordEncoder sCryptPasswordEncoder = SCryptPasswordEncoder.defaultsForSpringSecurity_v5_8();
            if (sCryptPasswordEncoder.matches(line, hashingText.getText())) {
                bruteForceoutcome.setBruteForceOutcome(true);
                bruteForceoutcome.setBruteforceText(line);
            }
        }

        return bruteForceoutcome;
    }


}
