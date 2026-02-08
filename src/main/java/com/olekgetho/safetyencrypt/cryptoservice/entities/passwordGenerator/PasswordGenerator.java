package com.olekgetho.safetyencrypt.cryptoservice.entities.passwordGenerator;

import jakarta.validation.constraints.Size;
import lombok.*;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Value;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class PasswordGenerator {

    @NonNull
    @Value("${default.passwordlength}")
    private int lengthOfPassword;

    private boolean includeSymbols = false;
}
