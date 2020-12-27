package ru.evgeniy.dpitunnel;

import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;
import android.view.View;
import android.widget.ImageButton;

public class SettingsActivity extends AppCompatActivity {

    private ImageButton settingsBackButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_settings);

        // Set custom theme
        setTheme(R.style.SettingsFragmentStyle);

        // Find layout elements
        settingsBackButton = findViewById(R.id.settings_back_button);

        // Set listeners
        settingsBackButton.setOnClickListener(v -> finish());

        // Load settings fragment
        getSupportFragmentManager()
                .beginTransaction()
                .replace(R.id.settings_fragment, new SettingsFragment())
                .commit();
    }
}
