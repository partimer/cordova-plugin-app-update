package com.vaenow.appupdate.android;

import android.AuthenticationOptions;
import android.app.AlertDialog;
import android.content.Context;
import android.os.Environment;
import android.os.Handler;
import android.widget.ProgressBar;
import android.util.Base64;
import org.json.JSONObject;
import org.json.JSONException;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;

import 	java.nio.charset.StandardCharsets;


import java.security.cert.CertificateFactory;
import java.security.cert.Certificate;
import java.io.BufferedInputStream;
import javax.net.ssl.TrustManagerFactory;
import java.security.KeyStore;
import javax.net.ssl.SSLContext;
import android.content.res.Resources;
import java.security.cert.X509Certificate;
import android.app.Activity;
import javax.net.ssl.HttpsURLConnection;

public class HttpsMaker {
    public static HttpsURLConnection openHttpsConnection(String path, Context mContext) throws Exception {
        // Get resource id
        int trusted_id = mContext.getResources().getIdentifier("trusted_roots", "raw", mContext.getPackageName());

        // Load CAs from an InputStream
        // (could be from a resource or ByteArrayInputStream or ...)
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        // From res/raw/trusted_roots
        InputStream caInput = new BufferedInputStream(mContext.getResources().openRawResource(trusted_id));
        Certificate ca;
        try {
          ca = cf.generateCertificate(caInput);
          System.out.println("ca=" + ((X509Certificate) ca).getSubjectDN());
        } finally {
          caInput.close();
        }

        // Create a KeyStore containing our trusted CAs
        String keyStoreType = KeyStore.getDefaultType();
        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(null, null);
        keyStore.setCertificateEntry("ca", ca);

        // Create a TrustManager that trusts the CAs in our KeyStore
        String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
        tmf.init(keyStore);

        // Create an SSLContext that uses our TrustManager
        SSLContext context = SSLContext.getInstance("Default");
        context.init(null, tmf.getTrustManagers(), null);

        URL url = new URL(path);
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();//利用HttpURLConnection对象,我们可以从网络中获取网页数据.

        // Associate with Apps trust store
        conn.setSSLSocketFactory(context.getSocketFactory());
        return conn;
    }
}
