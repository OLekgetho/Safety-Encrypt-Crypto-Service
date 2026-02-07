package com.olekgetho.safetyencrypt.cryptoservice.entities.encryption;

import com.olekgetho.safetyencrypt.cryptoservice.entities.hashing.HashingAlgorithms;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Value;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class EncryptionText {

    @NonNull
    @Size(min = 3, max = 15, message = "Text must be between 3 and 15 characters")
    private String text;

    @Value("${default.encryptionalgo}")
    private EncryptionAlgorithms encryptionAlgorithms;
}
