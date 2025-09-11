package com.example.demo;

import android.content.Intent;
import android.os.AsyncTask;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import org.json.JSONObject;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class LoginActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        EditText username = findViewById(R.id.username);
        EditText password = findViewById(R.id.password);
        Button loginBtn = findViewById(R.id.loginBtn);

        loginBtn.setOnClickListener(v -> {
            String u = username.getText().toString();
            String p = password.getText().toString();
            if (u.isEmpty() || p.isEmpty()) {
                Toast.makeText(this, "请输入用户名和密码", Toast.LENGTH_SHORT).show();
                return;
            }
            // 发起请求到本地 Flask Mock Server（请根据你的主机 IP 修改 URL）
            String api = "http://10.0.2.2:5000/login"; // 10.0.2.2 指向宿主机的 localhost（Android emulator）
            new LoginTask(api, u, p).execute();
        });
    }

    static class LoginTask extends AsyncTask<Void, Void, Boolean> {
        String api, user, pass;
        String respText = "";

        LoginTask(String api, String user, String pass) {
            this.api = api; this.user = user; this.pass = pass;
        }

        @Override
        protected Boolean doInBackground(Void... voids) {
            try {
                URL url = new URL(api);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
                conn.setDoOutput(true);
                JSONObject obj = new JSONObject();
                obj.put("username", user);
                obj.put("password", pass);
                byte[] out = obj.toString().getBytes("UTF-8");
                OutputStream os = conn.getOutputStream();
                os.write(out);
                os.flush();
                int code = conn.getResponseCode();
                respText = "" + code;
                conn.disconnect();
                return code == 200;
            } catch (Exception e) {
                respText = e.toString();
                return false;
            }
        }

        @Override
        protected void onPostExecute(Boolean ok) {
            // no-op: handled by activity (simplified)
        }
    }
}