package com.olekgetho.safetyencrypt.cryptoservice.services.Impl;

import com.olekgetho.safetyencrypt.cryptoservice.entities.hashing.HashingAlgorithms;
import com.olekgetho.safetyencrypt.cryptoservice.entities.hashing.HashingText;
import com.olekgetho.safetyencrypt.cryptoservice.services.HashingService;
import org.apache.commons.lang.StringUtils;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.stereotype.Service;


@Service
public class HashingService_Impl implements HashingService {

    @Override
    public String hashingText(HashingText hashingText) {
        String hashedText = "";

        if (StringUtils.equals(hashingText.getHashingAlgorithms().toString(),
                HashingAlgorithms.Bcrypt.toString())) {
            BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder(12);
            hashedText = bCryptPasswordEncoder.encode(hashingText.getText());
        }

        else if (StringUtils.equals(hashingText.getHashingAlgorithms().toString(),
                HashingAlgorithms.Argon2.toString())) {
            Argon2PasswordEncoder argon2PasswordEncoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
            hashedText = argon2PasswordEncoder.encode(hashingText.getText());
        }

        else if (StringUtils.equals(hashingText.getHashingAlgorithms().toString(),
                HashingAlgorithms.PBKDF2.toString())) {
            Pbkdf2PasswordEncoder pbkdf2PasswordEncoder = Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8();
            hashedText = pbkdf2PasswordEncoder.encode(hashingText.getText());
        }
        else {
            SCryptPasswordEncoder sCryptPasswordEncoder = SCryptPasswordEncoder.defaultsForSpringSecurity_v5_8();
            hashedText = sCryptPasswordEncoder.encode(hashingText.getText());
        }

        return hashedText;
    }

}
