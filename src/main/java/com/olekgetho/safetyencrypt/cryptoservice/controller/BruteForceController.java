package com.olekgetho.safetyencrypt.cryptoservice.controller;

import com.olekgetho.safetyencrypt.cryptoservice.entities.hashing.BruteForce;
import com.olekgetho.safetyencrypt.cryptoservice.entities.hashing.HashingAlgorithms;
import com.olekgetho.safetyencrypt.cryptoservice.entities.hashing.HashingText;
import com.olekgetho.safetyencrypt.cryptoservice.services.BruteForceService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/text")
public class BruteForceController {
    private final BruteForceService bruteForceService;

    public BruteForceController(BruteForceService bruteForceService) {
        this.bruteForceService = bruteForceService;
    }


    @PostMapping("/bruteForce/upload-csv")
    public ResponseEntity<BruteForce> uploadCsvFileBrute(
            @RequestParam("file") MultipartFile file,
            @RequestParam("text") String text,
            @RequestParam("hashingAlgorithms") HashingAlgorithms hashingAlgorithms
    ) {
        if (file.isEmpty() || text.trim().isEmpty() || text.isBlank()) {
            BruteForce emptyFile = new BruteForce();
            emptyFile.setBruteforceText("File Empty or text is Blank");
            return ResponseEntity.badRequest().body(emptyFile);
        }

        HashingText hashingText = new HashingText(text, hashingAlgorithms);
        return ResponseEntity.ok(bruteForceService.bruteForcePassword(file, hashingText));
    }
}
