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

/**
 * 下载文件线程
 */
public class DownloadApkThread implements Runnable {
    private String TAG = "DownloadApkThread";

    /* 保存解析的XML信息 */
    HashMap<String, String> mHashMap;
    /* 下载保存路径 */
    private String mSavePath;
    /* 记录进度条数量 */
    private int progress;
    /* 是否取消更新 */
    private boolean cancelUpdate = false;
    private AlertDialog mDownloadDialog;
    private DownloadHandler downloadHandler;
    private Handler mHandler;
    private AuthenticationOptions authentication;
    private Context mContext;

    public DownloadApkThread(Context mContext, Handler mHandler, ProgressBar mProgress, AlertDialog mDownloadDialog, HashMap<String, String> mHashMap, JSONObject options) {
        this.mDownloadDialog = mDownloadDialog;
        this.mHashMap = mHashMap;
        this.mHandler = mHandler;
        this.authentication = new AuthenticationOptions(options);

        this.mSavePath = Environment.getExternalStorageDirectory() + "/" + "download"; // SD Path
        this.downloadHandler = new DownloadHandler(mContext, mProgress, mDownloadDialog, this.mSavePath, mHashMap);
        
        this.mContext = mContext;
    }


    @Override
    public void run() {
        downloadAndInstall();
        // 取消下载对话框显示
        // mDownloadDialog.dismiss();
    }

    public void cancelBuildUpdate() {
        this.cancelUpdate = true;
    }

    private void downloadAndInstall() {
        try {
            // 判断SD卡是否存在，并且是否具有读写权限
            if (Environment.getExternalStorageState().equals(Environment.MEDIA_MOUNTED)) {
                
                // Coomon variables for the loop
                HttpURLConnection conn;
                boolean redirect = false;
                String url = this.mHashMap.get("url");
                String cookies = "";
                
                
                // Loop until the redirect is resolved
                do {
                    System.out.println( "Opening connection to "+url );
                    
                    conn = HttpsMaker.openHttpsConnection(url, this.mContext);
                    
                    // Setup header
                    if(this.authentication.hasCredentials()){
                        conn.setRequestProperty("Authorization", this.authentication.getEncodedAuthorization());
                    }

                                            
                    //conn.setRequestProperty("Cookie", cookies);
                    //conn.addRequestProperty("Accept-Language", "en-US,en;q=0.8");
                    conn.addRequestProperty("User-Agent", "Android_Java_CordovaCheckAppUpdate");
                    //conn.addRequestProperty("Referer", "google.com");
                    
                    // Attempt to open a connection
                    conn.setDoInput(true);
                    conn.connect();
                    
                    // normally, 3xx is redirect
                    int status = conn.getResponseCode();
                    
                    redirect = false;
                    if (status != HttpURLConnection.HTTP_OK) {
                        if (status == HttpURLConnection.HTTP_MOVED_TEMP
                            || status == HttpURLConnection.HTTP_MOVED_PERM
                            || status == HttpURLConnection.HTTP_SEE_OTHER)
                            redirect = true;
                    }

                    System.out.println("Response Code ... " + status);
                    
                    // Check fields need to be updated prior to looping
                    if (redirect) {

                        // get redirect url from "location" header field
                        url = conn.getHeaderField("Location");

                        // get the cookie if need, for login
                        cookies = conn.getHeaderField("Set-Cookie");

                        System.out.println("Redirect to URL : " + url);
                    }
                    
                    // Loop again if we have been redirected
                } while(redirect);
                
                // 获取文件大小
                int length = conn.getContentLength();
                // 创建输入流
                InputStream is = conn.getInputStream();

                File file = new File(mSavePath);
                // 判断文件目录是否存在
                if (!file.exists()) {
                    file.mkdir();
                }
                File apkFile = new File(mSavePath, mHashMap.get("name")+".apk");
                FileOutputStream fos = new FileOutputStream(apkFile);
                int count = 0;
                // 缓存
                byte buf[] = new byte[1024];

                // 写入到文件中
                do {
                    int numread = is.read(buf);
                    count += numread;
                    // 计算进度条位置
                    progress = (int) (((float) count / length) * 100);
                    downloadHandler.updateProgress(progress);
                    // 更新进度
                    downloadHandler.sendEmptyMessage(Constants.DOWNLOAD);
                    if (numread <= 0) {
                        // 下载完成
                        downloadHandler.sendEmptyMessage(Constants.DOWNLOAD_FINISH);
                        mHandler.sendEmptyMessage(Constants.DOWNLOAD_FINISH);
                        break;
                    }
                    // 写入文件
                    fos.write(buf, 0, numread);
                } while (!cancelUpdate);// 点击取消就停止下载.
                fos.close();
                is.close();
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }catch (Exception e) {
            e.printStackTrace();
        }

    }
}
