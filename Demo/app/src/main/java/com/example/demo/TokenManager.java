package com.example.demo;

/**
 * 演示用的硬编码 JWT；“Search JWT in static strings” 模板会在
 * 已加载类里找静态 String 并匹配形如 header.payload.signature 的 token。
 */
public final class TokenManager {
    // 私有静态常量也没问题（模板用反射 setAccessible(true) 可取值）
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
