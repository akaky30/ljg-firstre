package com.example.demo;

/**
 * Holds a hard‑coded JSON Web Token (JWT) for testing the
 * search_jwt_in_static_strings Frida template. The string uses the
 * standard three‑part JWT format (header.payload.signature) so that
 * the template's regular expression can detect it.
 */
public class TokenManager {
    public static String hardcodedJWT =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
            "eyJ1c2VyIjoiZGVtb3VzZXIifQ." +
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
}
