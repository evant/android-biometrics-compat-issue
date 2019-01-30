package me.tatarka.biometricscompatissue

import androidx.biometric.BiometricPrompt
import android.os.Build
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.widget.Toast
import kotlinx.android.synthetic.main.activity_main.*
import java.util.concurrent.Executors

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        text.text = "Api: " + Build.VERSION.SDK_INT

        button.setOnClickListener {
            BiometricPrompt(
                this,
                Executors.newSingleThreadExecutor(),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        Handler(Looper.getMainLooper()).post {
                            Toast.makeText(this@MainActivity, errString, Toast.LENGTH_LONG).show()
                        }
                    }
                }).authenticate(
                BiometricPrompt.PromptInfo.Builder()
                    .setTitle("Title")
                    .setDescription("Description")
                    .setNegativeButtonText("Cancel")
                    .build()
            )
        }
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        Log.d("MainActivity", "hasFocus: $hasFocus")
    }

    override fun onPause() {
        super.onPause()
        Log.d("MainActivity", "On Pause")
    }

    override fun onResume() {
        super.onResume()
        Log.d("MainActivity", "On Resume")
    }
}
