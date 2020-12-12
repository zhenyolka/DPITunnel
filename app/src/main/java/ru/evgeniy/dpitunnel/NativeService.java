package ru.evgeniy.dpitunnel;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.IBinder;
import android.preference.PreferenceManager;
import android.support.v4.app.NotificationCompat;
import android.util.Log;

import java.io.DataOutputStream;

public class NativeService extends Service {

    private SharedPreferences prefs;
    private static int FOREGROUND_ID = 97456;
    public static final String CHANNEL_ID = "DPITunnelChannel";

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    NativeThread nativeThread = new NativeThread();
    @Override
    public void onCreate() {
        String log_tag = "Java/NativeService/onCreate";

        // Start foreground service
        createNotificationChannel();

        // Add intent to start activity on notification click
        Intent intent1 = new Intent(this, MainActivity.class);
        PendingIntent pendingIntent = PendingIntent.getActivity(this, 0,
                intent1, PendingIntent.FLAG_UPDATE_CURRENT);

        // Build notification
        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle(getText(R.string.app_name))
                .setContentText(getText(R.string.service_is_running))
                .setSmallIcon(R.mipmap.ic_notification_logo)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .setStyle(new NotificationCompat.DecoratedCustomViewStyle());

        // Set intent
        builder.setContentIntent(pendingIntent);

        Notification notification = builder.build();

        // Show notification
        startForeground(FOREGROUND_ID, notification);

        prefs = PreferenceManager.getDefaultSharedPreferences(this);

        // Start native code
        nativeThread.start();

        // Set http_proxy settings if need
        if(prefs.getBoolean("other_proxy_setting", false)) {
            try {
                Process su = Runtime.getRuntime().exec("su");
                DataOutputStream outputStream = new DataOutputStream(su.getOutputStream());

                outputStream.writeBytes("settings put global http_proxy 127.0.0.1:" + prefs.getString("other_bind_port", null) + "\n");
                outputStream.flush();

                outputStream.writeBytes("exit\n");
                outputStream.flush();

                su.waitFor();
            } catch (Exception e) {
                Log.e(log_tag, "Failed to set http_proxy global settings");
            }
        }

        // Inform app what service is started
        Intent broadCastIntent = new Intent();
        broadCastIntent.setAction("LOGO_BUTTON_ON");
        sendBroadcast(broadCastIntent);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId)
    {
        createNotificationChannel();

        // Add intent to start activity on notification click
        Intent intent1 = new Intent(this, MainActivity.class);
        PendingIntent pendingIntent = PendingIntent.getActivity(this, 0,
                intent1, PendingIntent.FLAG_UPDATE_CURRENT);

        // Build notification
        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle(getText(R.string.app_name))
                .setContentText(getText(R.string.service_is_running))
                .setSmallIcon(R.mipmap.ic_notification_logo)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .setStyle(new NotificationCompat.DecoratedCustomViewStyle());

        // Set intent
        builder.setContentIntent(pendingIntent);

        Notification notification = builder.build();

        // Show notification
        startForeground(FOREGROUND_ID, notification);

        return START_NOT_STICKY;
    }


    private class NativeThread extends Thread{
        String log_tag = "Java/NativeService/nativeThread";

        @Override
        public void run() {
            if(init(PreferenceManager.getDefaultSharedPreferences(NativeService.this), getFilesDir().toString()) == -1)
            {
                Log.e(log_tag, "Init failure");
                NativeService.this.stopSelf();
                return;
            }

            acceptClientCycle();
        }

        public void quit() {
            deInit();
        }
    }

    @Override
    public void onDestroy() {
        String log_tag = "Java/NativeService/onDestroy";

        // Unset http_proxy settings if need
        if(prefs.getBoolean("other_proxy_setting", false)) {
            try {
                Process su = Runtime.getRuntime().exec("su");
                DataOutputStream outputStream = new DataOutputStream(su.getOutputStream());

                outputStream.writeBytes("settings put global http_proxy :0\n");
                outputStream.flush();

                outputStream.writeBytes("exit\n");
                outputStream.flush();

                su.waitFor();
            } catch (Exception e) {
                Log.e(log_tag, "Failed to unset http_proxy global settings");
            }
        }

        nativeThread.quit();

        // Inform app what service is stopped
        Intent broadCastIntent = new Intent();
        broadCastIntent.setAction("LOGO_BUTTON_OFF");
        sendBroadcast(broadCastIntent);
    }

    private void createNotificationChannel()
    {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
        {
            CharSequence name = CHANNEL_ID;
            String description = CHANNEL_ID;
            int importance = NotificationManager.IMPORTANCE_LOW;
            NotificationChannel channel = new NotificationChannel(CHANNEL_ID, name, importance);
            channel.setDescription(description);

            NotificationManager notificationManager = getSystemService(NotificationManager.class);
            notificationManager.createNotificationChannel(channel);
        }
    }

    static {
        System.loadLibrary("dpi-bypass");
    }

    public native int init(SharedPreferences prefs, String appData);
    public native void acceptClientCycle();
    public native void deInit();
}
