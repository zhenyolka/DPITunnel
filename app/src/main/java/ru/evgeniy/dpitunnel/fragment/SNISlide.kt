package ru.evgeniy.dpitunnel.fragment

import android.os.Bundle
import android.text.method.LinkMovementMethod
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.fragment.app.Fragment
import ru.evgeniy.dpitunnel.R

class SNISlide: Fragment() {
    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        val view = inflater.inflate(R.layout.fragment_slide_sni, container, false)

        val sniSlideText: TextView = view.findViewById(R.id.sni_overview_text)
        sniSlideText.movementMethod = LinkMovementMethod.getInstance()

        return view
    }
}