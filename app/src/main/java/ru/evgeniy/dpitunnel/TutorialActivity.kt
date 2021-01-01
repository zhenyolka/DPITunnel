package ru.evgeniy.dpitunnel

import android.os.Bundle
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import com.github.appintro.AppIntro
import com.github.appintro.AppIntroFragment
import ru.evgeniy.dpitunnel.fragment.RootSlide
import ru.evgeniy.dpitunnel.fragment.SNISlide

class TutorialActivity : AppIntro() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        showStatusBar(true)
        isSkipButtonEnabled = false

        // Info slide
        addSlide(AppIntroFragment.newInstance(
                imageDrawable = R.mipmap.ic_launcher,
                description = getString(R.string.about_dpitunnel),
                descriptionColor = ContextCompat.getColor(applicationContext, R.color.introTextColor),
                descriptionTypefaceFontRes = R.font.samsungone,
                backgroundColor = ContextCompat.getColor(applicationContext, R.color.colorAccent)))

        // Root slide
        addSlide(RootSlide())

        // SNI slide
        addSlide(SNISlide())
    }

    fun goToNextSlide(): Unit = super.goToNextSlide(false)

    override fun onDonePressed(currentFragment: Fragment?) {
        super.onDonePressed(currentFragment)
        finish()
    }
}