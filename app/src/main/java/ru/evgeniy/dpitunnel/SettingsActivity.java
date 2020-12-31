package ru.evgeniy.dpitunnel;

import android.content.Intent;
import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;
import ru.evgeniy.dpitunnel.fragment.SettingsFragment;

import android.widget.ImageButton;

public class SettingsActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_settings);

        // Set custom theme
        setTheme(R.style.SettingsFragmentStyle);

        // Find layout elements
        ImageButton settingsBackButton = findViewById(R.id.settings_back_button);
        ImageButton settingsAboutButton = findViewById(R.id.settings_about_button);

        // Set listeners
        settingsBackButton.setOnClickListener(v -> finish());
        settingsAboutButton.setOnClickListener(v -> startActivity(
                new Intent(SettingsActivity.this, AboutActivity.class)));

        // Load settings fragment
        getSupportFragmentManager()
                .beginTransaction()
                .replace(R.id.settings_fragment, new SettingsFragment())
                .commit();
    }
}
