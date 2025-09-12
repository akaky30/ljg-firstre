package com.example.demo;

import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import android.content.SharedPreferences;
import android.util.Log;

/**
 * Activity used to demonstrate the sharedprefs_dump template. It writes a
 * token value to SharedPreferences and reads it back. When the Frida
 * template is active, the read operation will be intercepted and the key
 * along with its value will be printed by the script.
 */
public class PrefsActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_prefs);

        SharedPreferences prefs = getSharedPreferences("demo_prefs", MODE_PRIVATE);
        prefs.edit().putString("token", "demoToken123").apply();

        // Read the value back. When the sharedprefs_dump template is loaded,
        // this call should trigger a log entry with the key and its value.
        String token = prefs.getString("token", "default");
        Log.i("PrefsTest", "Loaded token=" + token);
    }
}
