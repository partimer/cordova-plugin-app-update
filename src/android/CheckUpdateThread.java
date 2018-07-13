package com.vaenow.appupdate.android;

import android.AuthenticationOptions;
import android.content.Context;
import android.content.pm.PackageManager.NameNotFoundException;
import android.os.Handler;
import android.util.Base64;
import org.apache.cordova.LOG;
import org.json.JSONObject;
import org.json.JSONException;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.List;

import java.nio.charset.StandardCharsets;

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
/**
 * Created by LuoWen on 2015/12/14.
 */
public class CheckUpdateThread implements Runnable {
    private String TAG = "CheckUpdateThread";

    /* 保存解析的XML信息 */
    HashMap<String, String> mHashMap;
    private Context mContext;
    private List<Version> queue;
    private String packageName;
    private String updateXmlUrl;
    private AuthenticationOptions authentication;
    private Handler mHandler;

    private void setMHashMap(HashMap<String, String> mHashMap) {
        this.mHashMap = mHashMap;
    }

    public HashMap<String, String> getMHashMap() {
        return mHashMap;
    }

    public CheckUpdateThread(Context mContext, Handler mHandler, List<Version> queue, String packageName, String updateXmlUrl, JSONObject options) {
        this.mContext = mContext;
        this.queue = queue;
        this.packageName = packageName;
        this.updateXmlUrl = updateXmlUrl;
        this.authentication = new AuthenticationOptions(options);
        this.mHandler = mHandler;
    }

    @Override
    public void run() {
        int versionCodeLocal = getVersionCodeLocal(mContext); // 获取当前软件版本
        int versionCodeRemote = getVersionCodeRemote();  //获取服务器当前软件版本

        queue.clear(); //ensure the queue is empty
        queue.add(new Version(versionCodeLocal, versionCodeRemote));

        if (versionCodeLocal == 0 || versionCodeRemote == 0) {
            mHandler.sendEmptyMessage(Constants.VERSION_RESOLVE_FAIL);
        } else {
            mHandler.sendEmptyMessage(Constants.VERSION_COMPARE_START);
        }
    }

    /**
     * 通过url返回文件
     *
     * @param path
     * @return
     */
    private InputStream returnFileIS(String path) {
        LOG.d(TAG, "returnFileIS..");
        // Get resource id
        int trusted_id = this.mContext.getResources().getIdentifier("trusted_roots", "raw", this.mContext.getPackageName());
        
        // Load CAs from an InputStream
        // (could be from a resource or ByteArrayInputStream or ...)
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        

        
        // From res/raw/trusted_roots
        InputStream caInput = new BufferedInputStream(this.mContext.getResources().openRawResource(trusted_id));
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
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, tmf.getTrustManagers(), null);
        
        URL url = null;
        InputStream is = null;

        try {
            url = new URL(path);
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();//利用HttpURLConnection对象,我们可以从网络中获取网页数据.
            
            // Associate with Apps trust store
            conn.setSSLSocketFactory(context.getSocketFactory());
            
            if(this.authentication.hasCredentials()){
                conn.setRequestProperty("Authorization", this.authentication.getEncodedAuthorization());
            }

            conn.setDoInput(true);
            conn.connect();
            is = conn.getInputStream(); //得到网络返回的输入流
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            mHandler.sendEmptyMessage(Constants.REMOTE_FILE_NOT_FOUND);
        } catch (IOException e) {
            e.printStackTrace();
            mHandler.sendEmptyMessage(Constants.NETWORK_ERROR);
        }

        return is;
    }

    /**
     * 获取软件版本号
     * <p/>
     * It's weird, I don't know why.
     * <pre>
     * versionName -> versionCode
     * 0.0.1    ->  12
     * 0.3.4    ->  3042
     * 3.2.4    ->  302042
     * 12.234.221 -> 1436212
     * </pre>
     *
     * @param context
     * @return
     */
    private int getVersionCodeLocal(Context context) {
        LOG.d(TAG, "getVersionCode..");

        int versionCode = 0;
        try {
            // 获取软件版本号，对应AndroidManifest.xml下android:versionCode
            versionCode = context.getPackageManager().getPackageInfo(packageName, 0).versionCode;
        } catch (NameNotFoundException e) {
            e.printStackTrace();
        }
        return versionCode;
    }

    /**
     * 获取服务器软件版本号
     *
     * @return
     */
    private int getVersionCodeRemote() {
        int versionCodeRemote = 0;

        InputStream is = returnFileIS(updateXmlUrl);
        // 解析XML文件。 由于XML文件比较小，因此使用DOM方式进行解析
        ParseXmlService service = new ParseXmlService();
        try {
            setMHashMap(service.parseXml(is));
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (null != getMHashMap()) {
            versionCodeRemote = Integer.valueOf(getMHashMap().get("version"));
        }

        return versionCodeRemote;
    }
}
