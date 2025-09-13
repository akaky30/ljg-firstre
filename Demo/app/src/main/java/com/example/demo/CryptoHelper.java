package com.example.demo;

import android.util.Base64;
import java.nio.charset.StandardCharsets;

public final class CryptoHelper {
    public static String b64encode(String input) {
        return Base64.encodeToString(
                input.getBytes(StandardCharsets.UTF_8),
                Base64.NO_WRAP
        );
    }

    public static String b64decode(String b64) {
        byte[] data = Base64.decode(b64, Base64.DEFAULT);
        return new String(data, StandardCharsets.UTF_8);
    }

    private CryptoHelper() {}
}
