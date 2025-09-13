package com.example.demo;

import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;

import java.io.IOException;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.CertificatePinner;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class NetworkActivity extends AppCompatActivity {

    private TextView tv;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_network);

        tv = findViewById(R.id.tvNetworkInfo);
        Button btn = findViewById(R.id.btnNetworkRequest);

        btn.setOnClickListener(v -> doRequest());
    }

    private void doRequest() {
        // 故意设置一条“错误”的证书 pin：未绕过时应失败；
        // 使用 Frida 的 SSL Pinning Bypass 模板后应能成功。
        String host = "httpbin.org";
        CertificatePinner pinner = new CertificatePinner.Builder()
                .add(host, "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                .build();

        OkHttpClient client = new OkHttpClient.Builder()
                .certificatePinner(pinner)
                .build();

        Request req = new Request.Builder()
                .url(Config.API_BASE_URL + "/get")
                .header("Authorization", TokenManager.getAuthorizationHeader())
                .build();

        tv.setText("Requesting " + req.url() + " ...");

        client.newCall(req).enqueue(new Callback() {
            @Override public void onFailure(Call call, IOException e) {
                runOnUiThread(() ->
                        tv.setText("Request failed (expected before bypass):\n" + e));
            }

            @Override public void onResponse(Call call, Response response) throws IOException {
                String body = response.body() != null ? response.body().string() : "(no body)";
                runOnUiThread(() ->
                        tv.setText("Request succeeded (after bypass):\n" + body));
            }
        });
    }
}
