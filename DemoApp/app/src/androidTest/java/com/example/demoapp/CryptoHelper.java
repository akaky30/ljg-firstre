package com.example.demoapp;

import android.util.Base64;

public class CryptoHelper {
    public static String encodeBase64(String input) {
        return Base64.encodeToString(input.getBytes(), Base64.NO_WRAP);
    }
}
