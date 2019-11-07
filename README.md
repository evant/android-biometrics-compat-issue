# Biometric Sample

A sample implementation of the androidx biometric compat lib with all the workarounds needed for a
production app. [MainActivity.kt](app/src/main/java/me/tatarka/biometricssample/MainActivity.kt)
includes the logic to show the biometric prompt both at startup and on the click of a button.
[Cyrpto.kt](app/src/main/java/me/tatarka/biometricssample/Crypto.kt) handles encrypting and
decrypting data using asymmetric encryption. Both are heavily commented.