package com.olekgetho.safetyencrypt.cryptoservice.entities.encoding;

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
public class EncodingText {

    @NonNull
    @Size(min = 3, max = 15, message = "Text must be between 3 and 15 characters")
    String text;

    @Value("${default.encodingalgo}")
    EncodingAlgorithms encodingAlg;
}
