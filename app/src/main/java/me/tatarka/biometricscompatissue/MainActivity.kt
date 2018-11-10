package me.tatarka.biometricscompatissue

import android.os.Build
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import androidx.biometrics.BiometricPrompt
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
}
