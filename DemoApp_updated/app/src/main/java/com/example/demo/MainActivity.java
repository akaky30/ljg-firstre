package com.example.demo;

import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import android.content.Intent;
import android.util.Log;

/**
 * The main entry point of the DemoApp. This activity presents a simple UI
 * with buttons that navigate to other activities used for demonstrating
 * Frida templates. It also exercises the CryptoHelper class so that
 * developers can test hooking a custom method via a user‑defined script.
 */
public class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Call our helper to encode a string. When a custom Frida script
        // hooks this method, it should log the input and output of
        // encodeBase64("hello_demo").
        String encoded = CryptoHelper.encodeBase64("hello_demo");
        Log.i("CryptoTest", "Encoded: " + encoded);

        // Button to launch network test for SSL pinning demonstration
        findViewById(R.id.btnNetwork).setOnClickListener(v -> {
            Intent intent = new Intent(this, NetworkActivity.class);
            startActivity(intent);
        });

        // Button to launch SharedPreferences test for dump demonstration
        findViewById(R.id.btnPrefs).setOnClickListener(v -> {
            Intent intent = new Intent(this, PrefsActivity.class);
            startActivity(intent);
        });
    }
}
