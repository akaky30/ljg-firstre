package com.example.demo;

/**
 * 注意：为配合 "Dump class string fields（需类名）" 模板，
 * 这里必须有【实例字段】且至少有一个实例存活在堆上。
 * 因此提供 public static final Config LIVE = new Config();
 */
public final class Config {

    // ====== 静态常量（给普通业务/日志用，不影响 choose） ======
    public static final String APP_NAME = "DemoApp";
    public static final String API_BASE_URL = "https://httpbin.org";

    // ====== 非静态字符串字段（给 Java.choose 枚举并 dump） ======
    public final String secretSalt = "s3cr3t_SALT_2025";
    public final String featureFlag = "enable_demo_feature";
    public final String hardCodedPassword = "P@ssw0rd!";
    public final String[] magicWords = new String[]{"alpha", "bravo", "charlie"};

    // 暴露一个全局存活的实例，保证 Java.choose 一定能选到
    public static final Config LIVE = new Config();

    private Config() {}
}
