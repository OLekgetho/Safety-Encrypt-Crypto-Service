package com.olekgetho.safetyencrypt.cryptoservice.services;

import com.olekgetho.safetyencrypt.cryptoservice.entities.encoding.EncodingText;

public interface EncodingService {
    String encodingText(EncodingText encodingText);
    String decodeText(EncodingText encodingText);

}
