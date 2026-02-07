package com.olekgetho.safetyencrypt.cryptoservice.services.Impl;

import com.olekgetho.safetyencrypt.cryptoservice.entities.passwordGenerator.PasswordGenerator;
import com.olekgetho.safetyencrypt.cryptoservice.services.PasswordGeneratorService;
import org.apache.commons.lang.RandomStringUtils;
import org.springframework.stereotype.Service;

@Service
public class PasswordGeneratorService_Impl implements PasswordGeneratorService {

    @Override
    public String generatePassword(PasswordGenerator passwordGenerator) {
        return RandomStringUtils.random(passwordGenerator.getLengthOfPassword()
                ,passwordGenerator.isIncludeLetters(), passwordGenerator.isIncludeNumbers());
    }
}
