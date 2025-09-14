package com.example.demo;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.widget.Button;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Button btnNetwork = findViewById(R.id.btnToNetwork);
        Button btnPrefs   = findViewById(R.id.btnToPrefs);
        TextView tvEncoded = findViewById(R.id.tvEncoded);

        // --- 强制加载类 + 保证 Config 实例常驻（方便 Java.choose 命中） ---
        Log.d("Main", "APP_NAME=" + Config.APP_NAME);
        Log.d("Main", "API_BASE_URL=" + Config.API_BASE_URL);
        Log.d("Main", "LIVE.secretSalt=" + Config.LIVE.secretSalt);
        Log.d("Main", "JWT(preview)=" + TokenManager.getJwt());

        btnNetwork.setOnClickListener(v ->
                startActivity(new Intent(this, NetworkActivity.class)));

        btnPrefs.setOnClickListener(v ->
                startActivity(new Intent(this, PrefsActivity.class)));

        // Base64 示例（便于自定义脚本 hook）
        String encoded = CryptoHelper.b64encode("hello-frida");
        tvEncoded.setText("Base64 示例：\"hello-frida\" -> " + encoded);
    }
}
