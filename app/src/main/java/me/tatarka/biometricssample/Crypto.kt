package me.tatarka.biometricssample

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.nio.ByteBuffer
import java.security.*
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

/*
    Asymmetric encryption using key wrapping with RSA and AES. This allows you to encrypt data
    without asking for biometrics, while requiring it to decrypt.
*/

private val KEY_ALIAS = "key"
private val AES_KEY_SIZE = 128
private val AES_CIPHER = "AES/GCM/NoPadding"
// The device ui freezes while the key is being generated (yes even though it's on a background thread),
// this is as big as we can go before its very noticeable.
private val RSA_KEY_SIZE = 1024
private val RSA_CIPHER = "RSA/ECB/OAEPWithSHA-512AndMGF1Padding"

private val keyStore by lazy(LazyThreadSafetyMode.NONE) {
    KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
}

private val aesCipher by lazy(LazyThreadSafetyMode.NONE) {
    Cipher.getInstance(AES_CIPHER)
}

private val rsaCipher by lazy(LazyThreadSafetyMode.NONE) {
    Cipher.getInstance(RSA_CIPHER)
}

/**
 * Generate a symmetric AES key
 */
private fun createKey() = KeyGenerator.getInstance("AES").apply { init(AES_KEY_SIZE) }.generateKey()

/**
 * Generate an asymmetric RSA key pair
 */
private fun createKeyPair(keyStore: KeyStore) =
    KeyPairGenerator.getInstance("RSA", keyStore.provider).apply {
        initialize(
            KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_DECRYPT)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .setKeySize(RSA_KEY_SIZE)
                .setUserAuthenticationRequired(true)
                .build()
        )
    }.generateKeyPair()

/**
 * Gets an RSA cipher, applying work-arounds for bugs on api 23.
 */
private fun rsaCipher(keyStore: KeyStore, opmode: Int) = rsaCipher.apply {
    /*
        A known bug in the Android 6.0 (API Level 23) implementation of Bouncy Castle
        RSA OAEP causes the cipher to default to an SHA-1 certificate, making the SHA-256
        certificate of the public key incompatible
                To work around this issue, explicitly provide a new OAEP specification upon
        initialization
        https://code.google.com/p/android/issues/detail?id=197719
    */
    val spec =
        OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)
    val key = if (opmode == Cipher.WRAP_MODE) {
        val publicKey = publicKey(keyStore)
        /*
            A known bug in Android 6.0 (API Level 23) causes user authentication-related
            authorizations to be enforced even for public keys
            To work around this issue, extract the public key material to use outside of
            the Android Keystore
            http://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.html
          */
        KeyFactory.getInstance(publicKey.algorithm)
            .generatePublic(X509EncodedKeySpec(publicKey.encoded))
    } else {
        privateKey(keyStore)
    }
    init(opmode, key, spec)
}

/**
 * Gets or creates the RSA public key
 */
private fun publicKey(keyStore: KeyStore): PublicKey {
    if (keyStore.containsAlias(KEY_ALIAS)) {
        val certificate = keyStore.getCertificate(KEY_ALIAS)
        if (certificate != null) {
            return certificate.publicKey
        } else {
            keyStore.deleteEntry(KEY_ALIAS)
        }
    }
    return createKeyPair(keyStore).public
}

/**
 * Gets or creates the RSA private key
 */
private fun privateKey(keyStore: KeyStore): PrivateKey {
    if (keyStore.containsAlias(KEY_ALIAS)) {
        val key = try {
            keyStore.getKey(KEY_ALIAS, null)
        } catch (e: GeneralSecurityException) {
            keyStore.deleteEntry(KEY_ALIAS)
            throw GeneralSecurityException(e)
        }
        if (key is PrivateKey) {
            return key
        } else {
            keyStore.deleteEntry(KEY_ALIAS)
        }
    }
    return createKeyPair(keyStore).private
}

/**
 * Encrypts the given input. This does not require the user to unlock the key with biometrics as
 * only the public key is used.
 */
suspend fun encrypt(input: ByteArray): ByteArray {
    return withContext(Dispatchers.IO) {
        // RSA(key) + iv + AES(key, input)
        val key = createKey()
        val (encryptedInput, iv) = aesCipher.run {
            init(Cipher.ENCRYPT_MODE, key)
            doFinal(input) to iv
        }
        val cipher = rsaCipher(keyStore, Cipher.WRAP_MODE)
        val encryptedKey = cipher.wrap(key)
        val output =
            ByteBuffer.allocate(4 + encryptedKey.size + 4 + iv.size + encryptedInput.size).apply {
                putInt(encryptedKey.size)
                put(encryptedKey)
                putInt(iv.size)
                put(iv)
                put(encryptedInput)
            }
        output.array()
    }
}

/**
 * Decrypts the given input. The authenticator callback should unlock the cipher by prompting the
 * user for biometrics.
 */
suspend fun decrypt(input: ByteArray, authenticator: suspend (Cipher) -> Cipher): ByteArray {
    return withContext(Dispatchers.IO) {
        val lockedCipher = rsaCipher(keyStore, Cipher.UNWRAP_MODE)
        val cipher = withContext(Dispatchers.Main) { authenticator(lockedCipher) }
        // No data to decrypt
        if (input.isEmpty()) {
            return@withContext ByteArray(0)
        }
        ByteBuffer.wrap(input).run {
            val keyLength = getInt()
            val encryptedKey = ByteArray(keyLength).also { get(it) }
            val ivLength = getInt()
            val iv = ByteArray(ivLength).also { get(it) }
            val encryptedOutput =
                ByteArray(input.size - keyLength - 4 - ivLength - 4).also { get(it) }
            val aesKey = cipher.unwrap(encryptedKey, "AES", Cipher.SECRET_KEY)
            aesCipher.apply { init(Cipher.DECRYPT_MODE, aesKey, GCMParameterSpec(128, iv)) }
                .doFinal(encryptedOutput)
        }
    }
}

