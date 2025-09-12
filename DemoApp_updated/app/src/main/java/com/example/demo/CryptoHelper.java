package com.example.demo;

import android.util.Base64;

/**
 * A helper class exposing a simple Base64 encoding routine. This class
 * exists so that users can write their own Frida script to hook and log
 * method input/output for demonstration. Encoding uses NO_WRAP to avoid
 * line breaks in the output.
 */
public class CryptoHelper {
    /**
     * Encode the provided string as Base64 without any line breaks.
     *
     * @param input the plain text to encode
     * @return the Base64 representation of the input
     */
    public static String encodeBase64(String input) {
        return Base64.encodeToString(input.getBytes(), Base64.NO_WRAP);
    }
}
