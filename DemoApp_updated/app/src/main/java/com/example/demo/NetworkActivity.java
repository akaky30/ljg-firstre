package com.example.demo;

import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.CertificatePinner;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import java.io.IOException;

/**
 * Activity used to exercise the SSL pinning bypass template. It makes a
 * network request to a hard‑coded host with an intentionally invalid
 * certificate pin so that, without Frida's hook, the call fails. When
 * the ssl_pinning_bypass template is active, the request should succeed
 * and its response will be logged.
 */
public class NetworkActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_network);

        // Configure OkHttpClient with a bogus certificate pin. This pin will
        // cause SSL validation to fail unless the Frida hook bypasses
        // certificate checks. Replace "example.com" with any host you
        // control or that you wish to test against.
        OkHttpClient client = new OkHttpClient.Builder()
                .certificatePinner(new CertificatePinner.Builder()
                        .add("example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                        .build())
                .build();

        Request request = new Request.Builder()
                .url("https://example.com/")
                .build();

        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                Log.e("SSLTest", "Request failed: " + e.getMessage());
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                String body = response.body() != null ? response.body().string() : "";
                Log.i("SSLTest", "Response: " + body);
            }
        });
    }
}
