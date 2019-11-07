package me.tatarka.biometricssample

import android.os.Build
import android.os.Bundle
import android.util.Base64
import android.view.View
import android.view.ViewTreeObserver
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import kotlinx.android.synthetic.main.activity_main.*
import kotlinx.coroutines.launch
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        text.text = "Api: " + Build.VERSION.SDK_INT

        button.setOnClickListener {
            showBiometricPrompt()
        }

        encrypt.setOnClickListener {
            lifecycleScope.launch {
                val encryptedData = encrypt(data.text.toString().toByteArray())
                encrypted.text = Base64.encodeToString(encryptedData, 0)
            }
        }
    }

    override fun onResume() {
        super.onResume()

        // canAuthenticate() will only check for fingerprint enrollment before api 29. This means it
        // might cause a false-negative on certain devices that have other forms of secure biometrics.
        // Some options for handling this are:
        // - Ignore the problem
        // - Don't check canAuthenticate() and handle errors showing the prompt instead.
        // - Copy and paste the androidx biometric source into your app and force it to only use
        //   FingerprintManager pre api 28.
        if (BiometricManager.from(this).canAuthenticate() == BiometricManager.BIOMETRIC_SUCCESS) {

            // Showing the biometrics prompt will be ignored if the app does not have focus. You may
            // think that this will always be the case if you are resumed, it is not.
            if (hasWindowFocus()) {
                showBiometricPrompt()
            } else {
                window.decorView.viewTreeObserver.addOnWindowFocusChangeListener(object :
                    ViewTreeObserver.OnWindowFocusChangeListener {
                    override fun onWindowFocusChanged(hasFocus: Boolean) {
                        window.decorView.viewTreeObserver.removeOnWindowFocusChangeListener(this)
                        showBiometricPrompt()
                    }
                })
            }
        }
    }

    private fun showProgress(shown: Boolean) {
        progress.visibility = if (shown) View.VISIBLE else View.INVISIBLE
    }

    private fun showBiometricPrompt() {
        // The coroutine stuff is to make sure crypto is preformed on a background thread while the
        // prompt is shown on the main thread.
        lifecycleScope.launch {
            try {
                val decryptedData = decrypt(Base64.decode(encrypted.text.toString(), 0)) { cipher ->
                    // On api 28 if the user is locked out of biometrics from too many failed
                    // attempts there will be a long delay before getting the error back. So the
                    // user isn't confused as to what is going on, show a loading indicator.
                    if (Build.VERSION.SDK_INT == 28) {
                        showProgress(true)

                        // The only way to tell that the prompt is shown is to listen to the window
                        // losing focus events.
                        window.decorView.viewTreeObserver.addOnWindowFocusChangeListener(object :
                            ViewTreeObserver.OnWindowFocusChangeListener {
                            override fun onWindowFocusChanged(hasFocus: Boolean) {
                                window.decorView.viewTreeObserver.removeOnWindowFocusChangeListener(
                                    this
                                )
                                showProgress(false)
                            }
                        })
                    }

                    suspendCoroutine { continuation ->
                        BiometricPrompt(
                            this@MainActivity,
                            // Run callbacks on the main thread
                            ContextCompat.getMainExecutor(this@MainActivity),
                            object : BiometricPrompt.AuthenticationCallback() {
                                private var authenticationFailed = false

                                override fun onAuthenticationError(
                                    errorCode: Int,
                                    errString: CharSequence
                                ) {
                                    val shouldShow =
                                        !isCancel(errorCode) && !authenticationFailed
                                    continuation.resumeWithException(
                                        BiometricException(
                                            errorCode,
                                            errString,
                                            shouldShow
                                        )
                                    )
                                }

                                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                                    continuation.resume(result.cryptoObject!!.cipher!!)
                                }

                                override fun onAuthenticationFailed() {
                                    // This means the dialog was shown, so we don't want to show the
                                    // error again ourselves
                                    authenticationFailed = true
                                }

                                /**
                                 * If the prompt was canceled we don't want to show an error ourselves
                                 */
                                fun isCancel(errorCode: Int) =
                                    errorCode == BiometricPrompt.ERROR_CANCELED
                                            || errorCode == BiometricPrompt.ERROR_USER_CANCELED
                                            || errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON

                            }).authenticate(
                            BiometricPrompt.PromptInfo.Builder()
                                .setTitle("Title")
                                .setDescription("Description")
                                .setNegativeButtonText("Cancel")
                                .build(),
                            // A CryptoObject is required to ensure 'secure' biometrics. Even if you don't need to
                            // unlock what you pass here, you need to pass something or the device may use a
                            // different weaker form of biometrics.
                            BiometricPrompt.CryptoObject(cipher)
                        )
                    }
                }
                decrypted.text = String(decryptedData)
            } catch (e: BiometricException) {
                // Hide the previously shown loading indicator if there's an error.
                if (Build.VERSION.SDK_INT == 28) {
                    showProgress(false)
                }
                if (e.shouldShow) {
                    AlertDialog.Builder(this@MainActivity)
                        .setTitle("Biometrics Error")
                        .setMessage(e.errString)
                        .setPositiveButton("Ok", null)
                        .show()
                }
            }
        }
    }
}

class BiometricException(
    val code: Int,
    val errString: CharSequence,
    /**
     * If true, we need to show the error to the user.
     */
    val shouldShow: Boolean
) : Exception("$errString ($code)")
