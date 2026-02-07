package com.olekgetho.safetyencrypt.cryptoservice.controller;

import com.olekgetho.safetyencrypt.cryptoservice.entities.passwordGenerator.PasswordGenerator;
import com.olekgetho.safetyencrypt.cryptoservice.services.PasswordGeneratorService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/text")
public class PasswordGeneratorController {
    private final PasswordGeneratorService passwordGeneratorService;

    public PasswordGeneratorController(PasswordGeneratorService passwordGeneratorService) {
        this.passwordGeneratorService = passwordGeneratorService;
    }

    @PostMapping("passwordGenerator")
    public ResponseEntity<String> generatorPassword(
            @RequestBody PasswordGenerator passwordGenerator
            ) {
        return ResponseEntity.ok(passwordGeneratorService.generatePassword(passwordGenerator));
    }
}
