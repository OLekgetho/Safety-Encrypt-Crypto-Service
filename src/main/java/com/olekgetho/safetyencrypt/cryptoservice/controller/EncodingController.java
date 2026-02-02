package com.olekgetho.safetyencrypt.cryptoservice.controller;

import com.olekgetho.safetyencrypt.cryptoservice.entities.encoding.EncodingText;
import com.olekgetho.safetyencrypt.cryptoservice.services.EncodingService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/text")
public class EncodingController {
    private final EncodingService encodingService;

    public EncodingController(EncodingService encodingService) {
        this.encodingService = encodingService;
    }

    @PostMapping("/encode")
    public ResponseEntity<String> encodingText(
            @Valid @RequestBody EncodingText encodingText
    ) {
        return ResponseEntity.ok(encodingService.encodingText(encodingText));
    }

    @PostMapping("/decode")
    public ResponseEntity<String> decodingText(
            @Valid @RequestBody EncodingText encodingText
    ) {
        return ResponseEntity.ok(encodingService.decodeText(encodingText));
    }


}
