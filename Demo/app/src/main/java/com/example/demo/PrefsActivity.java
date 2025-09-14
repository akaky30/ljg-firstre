package com.example.demo;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;

/**
 * 写入 + 读取 SharedPreferences。
 * 模板会 hook getString(...) 并打印 key/value。
 */
public class PrefsActivity extends AppCompatActivity {

    private static final String PREFS = "demo_prefs";
    private TextView tv;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_prefs);

        tv = findViewById(R.id.tvPrefsInfo);
        Button btnWrite = findViewById(R.id.btnPrefsWrite);
        Button btnRead  = findViewById(R.id.btnPrefsRead);

        btnWrite.setOnClickListener(v -> writePrefs());
        btnRead.setOnClickListener(v -> readPrefs());
    }

    private void writePrefs() {
        SharedPreferences sp = getSharedPreferences(PREFS, MODE_PRIVATE);
        sp.edit()
                .putString("username", "demo_user")
                .putString("token", TokenManager.getJwt())
                .putBoolean("isPremium", true)
                .apply();
        tv.setText("Written to SharedPreferences.\nusername=demo_user\nisPremium=true\ntoken=[hardcoded JWT]");
    }

    private void readPrefs() {
        SharedPreferences sp = getSharedPreferences(PREFS, MODE_PRIVATE);
        String username = sp.getString("username", "(none)");
        boolean premium = sp.getBoolean("isPremium", false);
        String token = sp.getString("token", "(none)");
        tv.setText("Read from SharedPreferences:\nusername=" + username
                + "\nisPremium=" + premium + "\ntoken=" + token);
    }
}
