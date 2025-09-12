package com.example.demoapp;

import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import okhttp3.*;

import java.io.IOException;

public class NetworkActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        OkHttpClient client = new OkHttpClient.Builder()
                .certificatePinner(new CertificatePinner.Builder()
                        .add("example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                        .build())
                .build();

        Request request = new Request.Builder()
                .url("https://example.com/api/data")
                .build();

        client.newCall(request).enqueue(new Callback() {
            @Override public void onFailure(Call call, IOException e) {
                Log.e("SSLTest", "Request failed: " + e.getMessage());
            }
            @Override public void onResponse(Call call, Response response) throws IOException {
                Log.i("SSLTest", "Response: " + response.body().string());
            }
        });
    }
}
