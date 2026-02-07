package com.olekgetho.safetyencrypt.cryptoservice.services;

import com.olekgetho.safetyencrypt.cryptoservice.entities.passwordGenerator.PasswordGenerator;

public interface PasswordGeneratorService {
    String generatePassword(PasswordGenerator passwordGenerator);
}
