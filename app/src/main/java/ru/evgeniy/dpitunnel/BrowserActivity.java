package ru.evgeniy.dpitunnel;

import android.annotation.TargetApi;
import android.app.ActivityManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Bitmap;
import android.net.Proxy;
import android.os.Build;
import android.os.Bundle;
import android.preference.PreferenceManager;
import androidx.collection.ArrayMap;
import androidx.appcompat.app.AppCompatActivity;
import android.util.Log;
import android.view.KeyEvent;
import android.view.View;
import android.webkit.WebResourceRequest;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.ProgressBar;
import android.widget.Toast;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BrowserActivity extends AppCompatActivity {

    private WebView browserWebview;
    private ImageButton browserBackButton;
    private EditText browserEditText;
    private ProgressBar progressBar;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_browser);

        if(!isServiceRunning(NativeService.class)) {
            Toast.makeText(this, getString(R.string.please_run_service), Toast.LENGTH_SHORT).show();
            finish();
        }

        // Find layout elements
        browserWebview = findViewById(R.id.browser_webview);
        browserBackButton = findViewById(R.id.browser_back_button);
        browserEditText = findViewById(R.id.browser_edit_text);
        progressBar = findViewById(R.id.browser_progress_bar);

        // Initialize buttons
        browserBackButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                finish();
            }
        });

        // Initialize edittext
        browserEditText.setOnKeyListener(new View.OnKeyListener() {
            @Override
            public boolean onKey(View v, int keyCode, KeyEvent event) {
                if ((event.getAction() == KeyEvent.ACTION_DOWN) && (keyCode == KeyEvent.KEYCODE_ENTER)) {

                    // Check if input string is url
                    String urlPattern = "https?://(www.)?[-a-zA-Z0-9@:%._+~#=]{1,256}.[a-zA-Z0-9()]{1,6}\\b([-a-zA-Z0-9()@:%_+.~#?&//=]*)";
                    if(isStringMatch(browserEditText.getText().toString(), urlPattern)) {
                        browserWebview.loadUrl(browserEditText.getText().toString());
                    } else {
                        String url = "https://searx.info/?q=" + browserEditText.getText().toString().replace(" ", "+");
                        browserWebview.loadUrl(url);
                        browserEditText.setText(url);
                    }

                    return true;
                }

                return false;
            }
        });

        // Set webview client
        browserWebview.setWebViewClient(new BrowserWebViewClient());

        // Enable zoom
        browserWebview.getSettings().setSupportZoom(true);
        browserWebview.getSettings().setBuiltInZoomControls(true);
        browserWebview.getSettings().setDisplayZoomControls(false);

        // Set DPI Tunnel proxy
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        setProxy(browserWebview, "127.0.0.1", Integer.valueOf(prefs.getString("other_bind_port", "8080")), "");

        // Enable javascript
        browserWebview.getSettings().setJavaScriptEnabled(true);

        // Load start page
        browserWebview.loadUrl("https://searx.info");
    }

    private static boolean setProxy(WebView webView, String host, int port, String exclusion) {
        String log_tag = "Java/BrowserActivity/setProxy";

        Context appContext = webView.getContext().getApplicationContext();
        System.setProperty("http.proxyHost", host);
        System.setProperty("http.proxyPort", port + "");
        System.setProperty("http.nonProxyHosts", exclusion);
        System.setProperty("https.proxyHost", host);
        System.setProperty("https.proxyPort", port + "");
        System.setProperty("https.nonProxyHosts", exclusion);
        try {
            Class applictionCls = appContext.getClass();
            Field loadedApkField = applictionCls.getField("mLoadedApk");
            loadedApkField.setAccessible(true);
            Object loadedApk = loadedApkField.get(appContext);
            Class loadedApkCls = Class.forName("android.app.LoadedApk");
            Field receiversField = loadedApkCls.getDeclaredField("mReceivers");
            receiversField.setAccessible(true);
            ArrayMap receivers = (ArrayMap) receiversField.get(loadedApk);
            for (Object receiverMap : receivers.values()) {
                for (Object rec : ((ArrayMap) receiverMap).keySet()) {
                    Class clazz = rec.getClass();
                    if (clazz.getName().contains("ProxyChangeListener")) {
                        Method onReceiveMethod = clazz.getDeclaredMethod("onReceive", Context.class, Intent.class);
                        Intent intent = new Intent(Proxy.PROXY_CHANGE_ACTION);
                        onReceiveMethod.invoke(rec, appContext, intent);
                    }
                }
            }
        } catch (Exception e) {
            Log.e(log_tag, "Failed to set proxy for WebView");
            e.printStackTrace();
            return false;
        }
        return true;
    }

    private static boolean isStringMatch(String s, String pattern) {
        try {
            Pattern patt = Pattern.compile(pattern);
            Matcher matcher = patt.matcher(s);
            return matcher.matches();
        } catch (RuntimeException e) {
            return false;
        }
    }

    private boolean isServiceRunning(Class<?> serviceClass) {
        ActivityManager manager = (ActivityManager) getSystemService(Context.ACTIVITY_SERVICE);
        for (ActivityManager.RunningServiceInfo service : manager.getRunningServices(Integer.MAX_VALUE)) {
            if (serviceClass.getName().equals(service.service.getClassName())) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void onBackPressed() {
        if(browserWebview.canGoBack()) {
            browserWebview.goBack();
        } else {
            super.onBackPressed();
        }
    }

    private class BrowserWebViewClient extends WebViewClient {

        // Show progress bar
        @Override
        public void onPageStarted(WebView view, String url, Bitmap favicon) {
            super.onPageStarted(view, url, favicon);
            progressBar.setVisibility(View.VISIBLE);
            browserEditText.setText(url);
        }

        // For new devices
        @TargetApi(Build.VERSION_CODES.N)
        @Override
        public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
            view.loadUrl(request.getUrl().toString());
            return true;
        }

        // For old devices
        @Override
        public boolean shouldOverrideUrlLoading(WebView view, String url) {
            view.loadUrl(url);
            return true;
        }

        // Hide progress bar
        @Override
        public void onPageFinished(WebView view, String url) {
            super.onPageFinished(view, url);
            progressBar.setVisibility(View.GONE);
        }
    }
}
