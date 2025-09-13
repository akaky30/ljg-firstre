package com.example.demo;

import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Button btnNetwork = findViewById(R.id.btnToNetwork);
        Button btnPrefs = findViewById(R.id.btnToPrefs);
        TextView tvEncoded = findViewById(R.id.tvEncoded);

        btnNetwork.setOnClickListener(v ->
                startActivity(new Intent(this, NetworkActivity.class)));

        btnPrefs.setOnClickListener(v ->
                startActivity(new Intent(this, PrefsActivity.class)));

        // Base64 示例（便于自定义脚本 hook）
        String encoded = CryptoHelper.b64encode("hello-frida");
        tvEncoded.setText("Base64 示例：\"hello-frida\" -> " + encoded);
    }
}
