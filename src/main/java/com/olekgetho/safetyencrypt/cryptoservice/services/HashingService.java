package com.olekgetho.safetyencrypt.cryptoservice.services;

import com.olekgetho.safetyencrypt.cryptoservice.entities.hashing.HashingText;

public interface HashingService {
    String hashingText(HashingText hashingText);
}
