package com.example.demo;

import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;

import java.io.IOException;
import java.util.Objects;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.CertificatePinner;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

/**
 * 进入页面后点击按钮：
 * 1) 先发 GET（让 URL 日志模板看到）
 * 2) 再发 POST，携带 body（让 RequestBody/base64 模板看到）
 * 同时设置“错误的 pin”，便于验证 SSL Pinning Bypass。
 */
public class NetworkActivity extends AppCompatActivity {

    private TextView tv;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_network);

        tv = findViewById(R.id.tvNetworkInfo);
        Button btn = findViewById(R.id.btnNetworkRequest);

        btn.setOnClickListener(v -> doRequests());
    }

    private OkHttpClient buildClientWithBadPin() {
        String host = "httpbin.org";
        CertificatePinner pinner = new CertificatePinner.Builder()
                // 故意错误 pin：未绕过时应失败；绕过后成功
                .add(host, "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                .build();

        return new OkHttpClient.Builder()
                .certificatePinner(pinner)
                .build();
    }

    private void doRequests() {
        OkHttpClient client = buildClientWithBadPin();

        // -------- GET：触发 URL 日志 ----------
        Request getReq = new Request.Builder()
                .url(Config.API_BASE_URL + "/get")
                .header("Authorization", TokenManager.getAuthorizationHeader())
                .build();

        tv.setText("GET " + getReq.url() + " ...\n");

        client.newCall(getReq).enqueue(new Callback() {
            @Override public void onFailure(Call call, IOException e) {
                runOnUiThread(() ->
                        tv.append("GET failed (expected before pin-bypass):\n" + e + "\n\n"));
            }

            @Override public void onResponse(Call call, Response response) throws IOException {
                String body = response.body() != null ? response.body().string() : "(no body)";
                runOnUiThread(() ->
                        tv.append("GET succeeded (after bypass):\n" + body + "\n\n"));
                response.close();
            }
        });

        // -------- POST：触发 RequestBody/base64 ----------
        MediaType form = MediaType.parse("application/x-www-form-urlencoded");
        String formText = "msg=" + CryptoHelper.b64encode("hi-frida")
                + "&jwt=" + TokenManager.getJwt();

        RequestBody postBody = RequestBody.create(formText, form);

        Request postReq = new Request.Builder()
                .url(Config.API_BASE_URL + "/post")
                .post(postBody)
                .build();

        tv.append("POST " + postReq.url() + " ...\n");

        client.newCall(postReq).enqueue(new Callback() {
            @Override public void onFailure(Call call, IOException e) {
                runOnUiThread(() ->
                        tv.append("POST failed (expected before pin-bypass):\n" + e + "\n"));
            }

            @Override public void onResponse(Call call, Response response) throws IOException {
                String body = response.body() != null ? response.body().string() : "(no body)";
                runOnUiThread(() ->
                        tv.append("POST succeeded (after bypass):\n" + body + "\n"));
                response.close();
            }
        });
    }
}
