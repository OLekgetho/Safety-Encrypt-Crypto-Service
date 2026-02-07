package com.olekgetho.safetyencrypt.cryptoservice.controller;

import com.olekgetho.safetyencrypt.cryptoservice.entities.hashing.BruteForce;
import com.olekgetho.safetyencrypt.cryptoservice.entities.hashing.HashingAlgorithms;
import com.olekgetho.safetyencrypt.cryptoservice.entities.hashing.HashingText;
import com.olekgetho.safetyencrypt.cryptoservice.services.HashingService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/text")
public class HashingController {
    private final HashingService hashingService;

    public HashingController(HashingService hashingService) {
        this.hashingService = hashingService;
    }

    @PostMapping("/hash")
    public ResponseEntity<String> hashingText(
           @Valid @RequestBody HashingText hashingText
    ) {
        return ResponseEntity.ok(hashingService.hashingText(hashingText));
    }

    @PostMapping("/upload-csv")
    public ResponseEntity<BruteForce> uploadCsvFileBrute(
            @RequestParam("file") MultipartFile file,
            @RequestParam("text") String text,
            @RequestParam("hashingAlgorithms") HashingAlgorithms hashingAlgorithms
            ) {

        HashingText hashingText = new HashingText(text, hashingAlgorithms);
        return ResponseEntity.ok(hashingService.bruteForcePassword(file, hashingText));
    }
}
