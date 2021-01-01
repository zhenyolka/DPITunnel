package ru.evgeniy.dpitunnel.fragment

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.preference.PreferenceManager
import kotlinx.coroutines.*
import ru.evgeniy.dpitunnel.R
import ru.evgeniy.dpitunnel.TutorialActivity
import java.io.DataInputStream
import java.io.DataOutputStream

class RootSlide: Fragment() {
    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        val view = inflater.inflate(R.layout.fragment_slide_root, container, false)
        view.findViewById<Button>(R.id.grant_root_button)
                .setOnClickListener{
                    CoroutineScope(Dispatchers.Main).launch {
                        val result = withContext(Dispatchers.IO) {
                            checkRootAccess()
                        }
                        if(!result) {
                            Toast.makeText(activity, R.string.grant_root_rights_fail, Toast.LENGTH_SHORT).show()
                        }
                        else {
                            Toast.makeText(activity, R.string.grant_root_rights_success, Toast.LENGTH_SHORT).show()
                            with(PreferenceManager.getDefaultSharedPreferences(context).edit()){
                                putBoolean("other_vpn_setting", false)
                                putBoolean("other_proxy_setting", true)
                                apply()
                            }
                            (activity as TutorialActivity).goToNextSlide()
                        }
                    }
                }
        return view
    }

    fun checkRootAccess(): Boolean {
        var retval = false
        val suProcess: Process
        try {
            suProcess = Runtime.getRuntime().exec("su")
            val os = DataOutputStream(suProcess.outputStream)
            val osRes = DataInputStream(suProcess.inputStream)
            if (null != os && null != osRes) {
                // Getting the id of the current user to check if this is root
                os.writeBytes("id\n")
                os.flush()
                val currUid: String = osRes.readLine()
                var exitSu = false
                if (null == currUid) {
                    retval = false
                    exitSu = false
                } else if (true == currUid.contains("uid=0")) {
                    retval = true
                    exitSu = true
                } else {
                    retval = false
                    exitSu = true
                }
                if (exitSu) {
                    os.writeBytes("exit\n")
                    os.flush()
                }
            }
        } catch (e: Exception) {
            // Can't get root !
            // Probably broken pipe exception on trying to write to output stream (os) after su failed, meaning that the device is not rooted
            retval = false
        }
        return retval
    }
}