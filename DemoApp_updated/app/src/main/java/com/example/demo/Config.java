package com.example.demo;

/**
 * A simple configuration class used for testing the dump_class_string_fields
 * Frida template. It contains a few string fields that can be enumerated
 * and dumped at runtime. This class is not used directly in the app but
 * exists solely as a target for the hook.
 */
public class Config {
    // Non‑static string fields
    private String apiKey = "123456";
    private String secret = "abcdef";

    // A static string field to verify that static members are ignored by the
    // dump_class_string_fields template when targeting non‑static fields.
    public static String ENV = "production";
}
