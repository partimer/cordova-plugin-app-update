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
import java.security.SecureRandom;

import java.util.Arrays;
/*
import android.app.DownloadManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.security.NetworkSecurityPolicy;
import android.security.net.config.ApplicationConfig;
import java.security.GeneralSecurityException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import com.android.internal.util.ArrayUtils;
*/
/*
import com.google.android.gms.security.ProviderInstaller;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.common.GooglePlayServicesNotAvailableException;
import com.google.android.gms.common.GooglePlayServicesRepairableException;
import com.google.android.gms.common.GooglePlayServicesUtil;
*/

public class HttpsMaker {
    public static HttpURLConnection openHttpsConnection(String path, Context mContext) throws Exception {
/*        
        // Ensure upto date      
        try {
            ProviderInstaller.installIfNeeded(mContext);
        } catch (GooglePlayServicesRepairableException e) {
            // Thrown when Google Play Services is not installed, up-to-date, or enabled
            // Show dialog to allow users to install, update, or otherwise enable Google Play services.
            GooglePlayServicesUtil.getErrorDialog(e.getConnectionStatusCode(), callingActivity, 0);
        } catch (GooglePlayServicesNotAvailableException e) {
            Log.e("SecurityException", "Google Play Services not available.");
        }
  */      
        // Get resource id
        int trusted_id = mContext.getResources().getIdentifier("trusted_roots", "raw", mContext.getPackageName());

        // Create a KeyStore containing our trusted CAs
        String keyStoreType = KeyStore.getDefaultType();
        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(null, null);
        
        // Load CAs from an InputStream
        // (could be from a resource or ByteArrayInputStream or ...)
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        // From res/raw/trusted_roots
        InputStream caInput = new BufferedInputStream(mContext.getResources().openRawResource(trusted_id));
        Certificate ca;
        System.out.println("Processing trusted_roots for x509...");
        try {
            int certCount = 0;
            while(caInput.available() > 0){
                ca = cf.generateCertificate(caInput);
                System.out.println("x509 ca"+String.valueOf(certCount)+"=" + ((X509Certificate) ca).getSubjectDN());
                keyStore.setCertificateEntry("ca"+String.valueOf(certCount++), ca);
            }
        } finally {
          caInput.close();
        }



        // Create a TrustManager that trusts the CAs in our KeyStore
        String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
        tmf.init(keyStore);

        // Create an SSLContext that uses our TrustManager
        SSLContext context = SSLContext.getInstance("TLSv1.2");
        context.init(null, tmf.getTrustManagers(), new SecureRandom());

        URL url = new URL(path);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();//利用HttpURLConnection对象,我们可以从网络中获取网页数据.

        // Associate with Apps trust store
        if( conn instanceof HttpsURLConnection) {
            ((HttpsURLConnection) conn).setSSLSocketFactory(context.getSocketFactory());
            System.out.println("x509 getSupportedCipherSuites="+Arrays.toString(context.getSocketFactory().getSupportedCipherSuites()) );
            System.out.println("x509 getDefaultCipherSuites="+Arrays.toString(context.getSocketFactory().getDefaultCipherSuites()) );
        }
        return conn;
    }
    /*
    @Override
    public SSLContext getSSLContextForPackage(Context context, String packageName)
            throws GeneralSecurityException {
        ApplicationConfig appConfig;
        try {
            appConfig = NetworkSecurityPolicy.getApplicationConfigForPackage(context, packageName);
        } catch (NameNotFoundException e) {
            // Unknown package -- fallback to the default SSLContext
            return SSLContext.getDefault();
        }
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[] {appConfig.getTrustManager()}, null);
        return ctx;
    }
    */
}

