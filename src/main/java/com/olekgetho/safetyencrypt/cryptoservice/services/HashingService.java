package com.olekgetho.safetyencrypt.cryptoservice.services;

import com.olekgetho.safetyencrypt.cryptoservice.entities.hashing.BruteForce;
import com.olekgetho.safetyencrypt.cryptoservice.entities.hashing.HashingText;
import org.springframework.web.multipart.MultipartFile;

public interface HashingService {
    String hashingText(HashingText hashingText);
    BruteForce bruteForcePassword(MultipartFile csvFile, HashingText hashingText);
}
