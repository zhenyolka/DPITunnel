package ru.evgeniy.dpitunnel;

import androidx.appcompat.app.AppCompatActivity;

import android.animation.Animator;
import android.animation.AnimatorInflater;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.os.Bundle;
import android.text.Html;
import android.text.method.LinkMovementMethod;
import android.widget.ImageButton;
import android.widget.TextView;

public class AboutActivity extends AppCompatActivity {

    private ImageButton aboutBackButton;
    private TextView authorName;
    private TextView githubLink;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_about);

        // Find layout elements
        aboutBackButton = findViewById(R.id.about_back_button);
        authorName = findViewById(R.id.author);
        githubLink = findViewById(R.id.github_link);

        // Set listeners
        aboutBackButton.setOnClickListener(v -> finish());

        // Make link clickable
        githubLink.setMovementMethod(LinkMovementMethod.getInstance());

        // Load animation
        AnimatorSet anim = (AnimatorSet) AnimatorInflater.loadAnimator(this, R.animator.flipping);
        anim.setTarget(authorName);
        anim.addListener(new AnimatorListenerAdapter() {

            private boolean mCanceled;

            @Override
            public void onAnimationStart(Animator animation) {
                mCanceled = false;
            }

            @Override
            public void onAnimationCancel(Animator animation) {
                mCanceled = true;
            }

            @Override
            public void onAnimationEnd(Animator animation) {
                if (!mCanceled) {
                    animation.start();
                }
            }

        });
        anim.start();
    }
}