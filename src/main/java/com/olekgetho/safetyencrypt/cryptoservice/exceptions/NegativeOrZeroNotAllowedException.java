package com.olekgetho.safetyencrypt.cryptoservice.exceptions;

public class NegativeOrZeroNotAllowedException extends RuntimeException{

    public NegativeOrZeroNotAllowedException(String errorMessage) {
        super(errorMessage);
    }
}
