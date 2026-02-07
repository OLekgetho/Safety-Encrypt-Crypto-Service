package com.olekgetho.safetyencrypt.cryptoservice.controller;

import com.olekgetho.safetyencrypt.cryptoservice.entities.hashing.HashingText;
import com.olekgetho.safetyencrypt.cryptoservice.services.HashingService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
}
