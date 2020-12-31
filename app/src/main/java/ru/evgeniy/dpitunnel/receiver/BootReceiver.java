package ru.evgeniy.dpitunnel.receiver;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;

import ru.evgeniy.dpitunnel.MainActivity;

public class BootReceiver extends BroadcastReceiver {

    public void onReceive(Context context, Intent intent) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);

        // Run DPITunnel only if we received ACTION_BOOT_COMPLETED Intent and
        // user set "Start service on system boot" setting
        if (Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction()) && prefs.getBoolean("other_start_on_boot", false)) {
            Intent intent1 = new Intent(context.getApplicationContext(), MainActivity.class);
            intent1.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            intent1.putExtra("ON_BOOT", true);
            context.startActivity(intent1);
        }
    }
}
