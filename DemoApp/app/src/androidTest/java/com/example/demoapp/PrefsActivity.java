package com.example.demoapp;

import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.content.SharedPreferences;

public class PrefsActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        SharedPreferences prefs = getSharedPreferences("demo_prefs", MODE_PRIVATE);
        prefs.edit().putString("token", "demoToken123").apply();

        String token = prefs.getString("token", "default");
        Log.i("PrefsTest", "Loaded token=" + token);
    }
}
