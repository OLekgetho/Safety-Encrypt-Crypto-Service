package com.olekgetho.safetyencrypt.cryptoservice.entities.hashing;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class BruteForce {
    boolean bruteForceOutcome = false;
    String bruteforceText;
}
