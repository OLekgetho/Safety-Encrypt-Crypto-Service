package com.olekgetho.safetyencrypt.cryptoservice.entities.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@NoArgsConstructor
@Setter
@Getter
public class ValidationErrorResponse {

    private String field;
    private String message;
}
