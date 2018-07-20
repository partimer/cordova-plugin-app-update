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

import java.util.Arrays;
import java.io.BufferedInputStream;
import android.app.Activity;
import android.content.res.Resources;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.SecureRandom;
import java.security.PrivateKey;
import java.security.PublicKey;

import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.security.KeyChainException;
import java.security.Principal;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509ExtendedKeyManager;

import android.net.Uri;
import android.net.Uri.Builder;


import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaPreferences;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.CordovaInterface;

import com.android.mail.utils.LogUtils;

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
/*
import android.security.NetworkSecurityPolicy;
import android.security.net.config.ApplicationConfig;
import android.content.pm.PackageManager.NameNotFoundException;
import java.security.GeneralSecurityException;
*/
public class HttpsMaker implements KeyChainAliasCallback {
    public static final String SP_KEY_ALIAS = "SP_KEY_ALIAS";
    public static CordovaWebView webView;
    public static CordovaInterface cordova;
    protected static CordovaPreferences preferences;
    
    public static void initialize ( CordovaWebView webViewP, CordovaInterface cordovaP, CordovaPreferences preferencesP) {
        webView = webViewP;
        cordova = cordovaP;
        preferences =preferencesP;
    }
    
    @Override
    public void alias(String alias) {
        /*
        try {
            if (alias != null) {
                SharedPreferences.Editor edt = mPreferences.edit();
                edt.putString(SP_KEY_ALIAS, alias);
                edt.apply();
                PrivateKey pk = KeyChain.getPrivateKey(mContext, alias);
                X509Certificate[] cert = KeyChain.getCertificateChain(mContext, alias);
                mRequest.proceed(pk, cert);
            } else {
                mRequest.proceed(null, null);
            }
        } catch (KeyChainException e) {
            String errorText = "Failed to load certificates";
            Toast.makeText(mContext, errorText, Toast.LENGTH_SHORT).show();
            Log.e(TAG, errorText, e);
        } catch (InterruptedException e) {
            String errorText = "InterruptedException while loading certificates";
            Toast.makeText(mContext, errorText, Toast.LENGTH_SHORT).show();
            Log.e(TAG, errorText, e);
        }
        */
        System.out.println("x509 alias callback" );
    } 
    /*
    public static SSLContext getSSLContextForPackage(Context context, String packageName)
            throws GeneralSecurityException {
        ApplicationConfig appConfig;
        try {
            appConfig = NetworkSecurityPolicy.getApplicationConfigForPackage(context, packageName);
        } catch (NameNotFoundException e) {
            // Unknown package -- fallback to the default SSLContext
            return SSLContext.getDefault();
        }
        SSLContext ctx = SSLContext.getInstance("TLSv1.2");
        ctx.init(null, new TrustManager[] {appConfig.getTrustManager()}, null);
        return ctx;
    }
    */
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

        // Client Keys
        /*
        SharedPreferences sp = PreferenceManager.getDefaultSharedPreferences(cordova.getActivity());
        //final KeyChainAliasCallback callback = new AliasCallback(cordova.getActivity(), request);
        final String alias = sp.getString(SP_KEY_ALIAS, null);

        KeyChain.choosePrivateKeyAlias(this, this, // Callback
            new String[] {"RSA", "DSA"}, // Any key types.
            null, // Any issuers.
            Uri.parse(path), // Full URI
            DEFAULT_ALIAS);
        */
        /*
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        KeyManager[] km = kmf.getKeyManagers();
        
        SharedPreferences sp = PreferenceManager.getDefaultSharedPreferences(cordova.getActivity());
        final String alias = sp.getString(SP_KEY_ALIAS, null);
        
        PrivateKey pk = KeyChain.getPrivateKey(mContext, alias);
        X509Certificate[] cert = KeyChain.getCertificateChain(mContext, alias);
        
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        */
        /*
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        //KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        KeyStore ks = KeyStore.getInstance("PKCS12");
        kmf.init(ks, "".toCharArray());
        */
        SharedPreferences sp = PreferenceManager.getDefaultSharedPreferences(cordova.getActivity());
        final String alias = sp.getString(SP_KEY_ALIAS, null);
        KeyManager keyManager = null;
        try {
            keyManager = SSLUtils.KeyChainKeyManager.fromAlias(mContext, alias);
        } catch (Exception e) {
            System.out.println("x509 CertificateException loading Client Key Manager" );
            e.printStackTrace();
        }
        
        
        // Create an SSLContext that uses our TrustManager
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        //context.init(null, tmf.getTrustManagers(), new SecureRandom());
        sslContext.init(new KeyManager[]{keyManager}, null, null);
        
        /*
        SSLContext context = HttpsMaker.getSSLContextForPackage(mContext, mContext.getPackageName());
        */
        URL url = new URL(path);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();//利用HttpURLConnection对象,我们可以从网络中获取网页数据.

        // Associate with Apps trust store
        if( conn instanceof HttpsURLConnection) {
            ((HttpsURLConnection) conn).setSSLSocketFactory(sslContext.getSocketFactory());
            System.out.println("x509 getSupportedCipherSuites="+Arrays.toString(sslContext.getSocketFactory().getSupportedCipherSuites()) );
            System.out.println("x509 getDefaultCipherSuites="+Arrays.toString(sslContext.getSocketFactory().getDefaultCipherSuites()) );
        }
        return conn;
    }
    
    private static abstract class StubKeyManager extends X509ExtendedKeyManager {
        @Override public abstract String chooseClientAlias(
                String[] keyTypes, Principal[] issuers, Socket socket);

        @Override public abstract X509Certificate[] getCertificateChain(String alias);

        @Override public abstract PrivateKey getPrivateKey(String alias);


        // The following methods are unused.

        @Override
        public final String chooseServerAlias(
                String keyType, Principal[] issuers, Socket socket) {
            // not a client SSLSocket callback
            throw new UnsupportedOperationException();
        }

        @Override
        public final String[] getClientAliases(String keyType, Principal[] issuers) {
            // not a client SSLSocket callback
            throw new UnsupportedOperationException();
        }

        @Override
        public final String[] getServerAliases(String keyType, Principal[] issuers) {
            // not a client SSLSocket callback
            throw new UnsupportedOperationException();
        }
    }
/**
     * A {@link KeyManager} that reads uses credentials stored in the system {@link KeyChain}.
     */
    public static class KeyChainKeyManager extends StubKeyManager {
        private final String mClientAlias;
        private final X509Certificate[] mCertificateChain;
        private final PrivateKey mPrivateKey;

        /**
         * Builds an instance of a KeyChainKeyManager using the given certificate alias.
         * If for any reason retrieval of the credentials from the system {@link KeyChain} fails,
         * a {@code null} value will be returned.
         */
        public static KeyChainKeyManager fromAlias(Context context, String alias)
                throws CertificateException {
            X509Certificate[] certificateChain;
            try {
                certificateChain = KeyChain.getCertificateChain(context, alias);
            } catch (KeyChainException e) {
                logError(alias, "certificate chain", e);
                throw new CertificateException(e);
            } catch (InterruptedException e) {
                logError(alias, "certificate chain", e);
                throw new CertificateException(e);
            }

            PrivateKey privateKey;
            try {
                privateKey = KeyChain.getPrivateKey(context, alias);
            } catch (KeyChainException e) {
                logError(alias, "private key", e);
                throw new CertificateException(e);
            } catch (InterruptedException e) {
                logError(alias, "private key", e);
                throw new CertificateException(e);
            } 

            if (certificateChain == null || privateKey == null) {
                throw new CertificateException("Can't access certificate from keystore");
            }
            try {
                certificateChain = KeyChain.getCertificateChain(context, alias);
                
            } catch (Exception e) {
                e.printStackTrace();
            }
            return new KeyChainKeyManager(alias, certificateChain, privateKey);
        }
        
        private static void logError(String alias, String type, Exception ex) {
            // Avoid logging PII when explicit logging is not on.
            if (LOG_ENABLED) {
                LogUtils.e(TAG, "Unable to retrieve " + type + " for [" + alias + "] due to " + ex);
            } else {
                LogUtils.e(TAG, "Unable to retrieve " + type + " due to " + ex);
            }
        }
        
        private KeyChainKeyManager(
                String clientAlias, X509Certificate[] certificateChain, PrivateKey privateKey) {
            mClientAlias = clientAlias;
            mCertificateChain = certificateChain;
            mPrivateKey = privateKey;
        }


        @Override
        public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
            if (LOG_ENABLED) {
                LogUtils.i(TAG, "Requesting a client cert alias for " + Arrays.toString(keyTypes));
            }
            return mClientAlias;
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            if (LOG_ENABLED) {
                LogUtils.i(TAG, "Requesting a client certificate chain for alias [" + alias + "]");
            }
            return mCertificateChain;
        }

        @Override
        public PrivateKey getPrivateKey(String alias) {
            if (LOG_ENABLED) {
                LogUtils.i(TAG, "Requesting a client private key for alias [" + alias + "]");
            }
            return mPrivateKey;
        }
}    
}

