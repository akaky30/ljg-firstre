package com.example.demo;

public final class TokenManager {
    // 演示用途的硬编码 JWT（便于“Search JWT in static strings”模板命中）
    private static final String JWT =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                    + "eyJzdWIiOiJkZW1vVXNlciIsImV4cCI6MTk5OTk5OTk5OX0."
                    + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    public static String getJwt() {
        return JWT;
    }

    public static String getAuthorizationHeader() {
        return "Bearer " + JWT;
    }

    private TokenManager() {}
}
