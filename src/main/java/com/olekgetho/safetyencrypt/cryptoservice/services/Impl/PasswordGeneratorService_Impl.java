package com.olekgetho.safetyencrypt.cryptoservice.services.Impl;

import com.olekgetho.safetyencrypt.cryptoservice.entities.passwordGenerator.PasswordGenerator;
import com.olekgetho.safetyencrypt.cryptoservice.exceptions.NegativeOrZeroNotAllowedException;
import com.olekgetho.safetyencrypt.cryptoservice.services.PasswordGeneratorService;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;

@Service
public class PasswordGeneratorService_Impl implements PasswordGeneratorService {

    /**
     * Generate a random password composed of uppercase letters, lowercase letters, and digits,
     * optionally including symbols when configured.
     *
     * @param passwordGenerator configuration object providing the password length and whether to include symbols
     * @return the generated password string containing letters, digits, and symbols if enabled
     */
    @Override
    public String generatePassword(PasswordGenerator passwordGenerator) {

        if (passwordGenerator.getLengthOfPassword() <= 0) {
            throw new NegativeOrZeroNotAllowedException("Password Length must be greater than 0");
        }

        String pool = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        SecureRandom secureRandom = new SecureRandom();
        StringBuilder stringBuilder = new StringBuilder();

        if (passwordGenerator.isIncludeSymbols()) {
            pool += "!@#$%^&*";
        }

        for (int i = 0; i < passwordGenerator.getLengthOfPassword(); i++) {
            int index = secureRandom.nextInt(pool.length());
            stringBuilder.append(pool.charAt(index));
        }

        return stringBuilder.toString();

    }
}