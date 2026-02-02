package com.olekgetho.safetyencrypt.cryptoservice.services.Impl;

import com.olekgetho.safetyencrypt.cryptoservice.entities.encoding.EncodingAlgorithms;
import com.olekgetho.safetyencrypt.cryptoservice.entities.encoding.EncodingText;
import com.olekgetho.safetyencrypt.cryptoservice.services.EncodingService;
import org.springframework.stereotype.Service;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HexFormat;

@Service
public class EncodingService_Impl implements EncodingService {

    @Override
    public String encodingText(EncodingText text) {
        String encodedText= "";
        byte[] textToByte = text.getText()
                .getBytes(StandardCharsets.UTF_8);

        if (text.getEncodingAlg().equals(EncodingAlgorithms.Base64)) {

            encodedText = Base64.getEncoder()
                    .encodeToString(textToByte);
        }

        else if (text.getEncodingAlg().equals(EncodingAlgorithms.URL)) {

            encodedText = URLEncoder.encode(text.getText(),
                    StandardCharsets.UTF_8);
        }

        else if (text.getEncodingAlg().equals(EncodingAlgorithms.HexString)) {

            encodedText = HexFormat.of().formatHex(textToByte);
        }

        return encodedText;
    }


    @Override
    public String decodeText(EncodingText encodedText) {
        String decodedText= "";

        if (encodedText.getEncodingAlg().equals(EncodingAlgorithms.Base64)) {
            byte[] decodedByte = Base64.getDecoder()
                    .decode(encodedText.getText());

            decodedText = new String(decodedByte, StandardCharsets.UTF_8);
        }

        else if (encodedText.getEncodingAlg().equals(EncodingAlgorithms.URL)) {

           decodedText = URLDecoder.decode(encodedText.getText(),
                   StandardCharsets.UTF_8);
        }

        else if (encodedText.getEncodingAlg().equals(EncodingAlgorithms.HexString)) {

            byte[] decodedByte = HexFormat.of().parseHex(encodedText.getText());

            decodedText = new String(decodedByte, StandardCharsets.UTF_8);
        }

        return decodedText;
    }
}
