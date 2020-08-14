package me.tatarka.biometricssample

import android.content.Context
import android.os.Build
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import android.view.View
import android.view.ViewTreeObserver
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import kotlinx.android.synthetic.main.activity_main.*
import kotlinx.coroutines.launch
import java.security.GeneralSecurityException
import java.security.InvalidAlgorithmParameterException
import java.security.KeyException
import java.security.KeyStore
import javax.crypto.KeyGenerator
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
                try {
                    val encryptedData = encrypt(data.text.toString().toByteArray())
                    encrypted.text = Base64.encodeToString(encryptedData, 0)
                } catch (e: GeneralSecurityException) {
                    AlertDialog.Builder(this@MainActivity)
                        .setTitle("Biometrics Error")
                        .setMessage(e.message)
                        .setPositiveButton("Ok", null)
                        .show()
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()

        if (canSecurelyAuthenticate(applicationContext)) {
            // Showing the biometrics prompt will be ignored if the app does not have focus. You may
            // think that this will always be the case if you are resumed, it is not.
            if (hasWindowFocus()) {
                showBiometricPrompt()
            } else {
                window.decorView.viewTreeObserver.addOnWindowFocusChangeListener(object :
                    ViewTreeObserver.OnWindowFocusChangeListener {
                    override fun onWindowFocusChanged(hasFocus: Boolean) {
                        if (hasFocus) {
                            window.decorView.viewTreeObserver.removeOnWindowFocusChangeListener(
                                this
                            )
                            showBiometricPrompt()
                        }
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
                                if (!hasFocus) {
                                    window.decorView.viewTreeObserver.removeOnWindowFocusChangeListener(
                                        this
                                    )
                                    showProgress(false)
                                }
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
                                 * If the prompt was canceled by the user we don't want to show an error ourselves
                                 */
                                fun isCancel(errorCode: Int) =
                                    errorCode == BiometricPrompt.ERROR_USER_CANCELED
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
            } catch (e: GeneralSecurityException) {
                AlertDialog.Builder(this@MainActivity)
                    .setTitle("Biometrics Error")
                    .setMessage(e.message)
                    .setPositiveButton("Ok", null)
                    .show()
            }
        }
    }
}

/**
 * Checks if we can securely authenticate, i.e. we have secure biometrics hardware and the user can
 * enroll. [androidx.biometric.BiometricManager.canAuthenticate] is insufficient for this because
 * on api 29+ it checks for any form of biometrics, not just ones that are 'secure', so we can
 * get a false-positive.
 */
private fun canSecurelyAuthenticate(context: Context): Boolean {
    if (Build.VERSION.SDK_INT < 23) {
        return false
    }
    try {
        val keystore = KeyStore.getInstance("AndroidKeyStore")
        KeyGenerator.getInstance("AES", keystore.provider)
            .init(
                KeyGenParameterSpec.Builder("DUMMY_KEY_ALIAS", KeyProperties.PURPOSE_DECRYPT)
                    .setUserAuthenticationRequired(true)
                    .build()
            )
        // On API 24 & 25 regardless of enrollment, as well as devices on API < 29 that have other
        // forms of biometrics enrolled eg. Samsung's iris scan, the above will not throw, but
        // BiometricPrompt will still throw an error when shown. Check the biometric manager as a fallback.
        return BiometricManager.from(context).canAuthenticate() == BIOMETRIC_SUCCESS
    } catch (e: InvalidAlgorithmParameterException) {
        // expected error if user isn't enrolled in secure biometrics
        return false
    } catch (e: Exception) {
        // Log unexpected errors, though if there's an issue with the keystore we probably can't use
        // biometrics anyway.
        Log.w("BiometricSample", e)
        return false
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
