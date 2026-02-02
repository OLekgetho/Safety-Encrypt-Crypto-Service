package com.olekgetho.safetyencrypt.cryptoservice.exceptions;

import com.olekgetho.safetyencrypt.cryptoservice.entities.exception.ValidationErrorResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.List;
import java.util.stream.Collectors;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<List<ValidationErrorResponse>> handleValidationException(
            MethodArgumentNotValidException ex
    ) {
       List<ValidationErrorResponse> errors = ex.getBindingResult()
               .getFieldErrors()
               .stream()
               .map(err -> new ValidationErrorResponse(err.getField(), err.getDefaultMessage()))
               .collect(Collectors.toList());

       return ResponseEntity.badRequest().body(errors);
    }
}
