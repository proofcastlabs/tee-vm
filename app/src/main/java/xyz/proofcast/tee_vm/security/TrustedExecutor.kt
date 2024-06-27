package xyz.proofcast.tee_vm.security

import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Log
import xyz.proofcast.tee_vm.security.Utils.Companion.fromHexString
import xyz.proofcast.tee_vm.security.Utils.Companion.toCbor
import xyz.proofcast.tee_vm.security.Utils.Companion.toHexString
import org.bouncycastle.asn1.x9.ECNamedCurveTable
import org.bouncycastle.crypto.generators.ECKeyPairGenerator

import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECKeyGenerationParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.jcajce.provider.digest.Keccak
import org.web3j.crypto.ECKeyPair
import org.web3j.crypto.Sign
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.Key
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

class TrustedExecutor(private val db: SharedPreferences, private val isStrongboxBacked: Boolean) {
    private val TAG = this.javaClass.name
    private val ETHEREUM_MSG_PREFIX = byteArrayOf(25)
            .plus("Ethereum Signed Message:\n".toByteArray())
    private val androidKeyStore = "AndroidKeyStore"
    private val ALIAS_ANDROID_ATTESTATION_KEY = "xyz.proofcast.tee_vm.ecdsa"
    private val ALIAS_ANDROID_SECRET_KEY = "xyz.proofcast.tee_vm.aes"
    private val PREFIX_SECP256K1_KEY = "xyz.proofcast.tee_vm.secp256k1"
    private val PREFERENCES_PRIVATE_KEY = "$PREFIX_SECP256K1_KEY.PrivateKey"
    private val PREFERENCES_PUBLIC_KEY = "$PREFIX_SECP256K1_KEY.PublicKey"
    private val CIPHER_TRANSFORMATION = "AES/GCM/NoPadding"

    val pubKey = null

    val proofType = if (isStrongboxBacked) "strongbox" else "android"

    init {
        maybeGenerateSecretKey()
        maybeGenerateSigningKey()
        Log.i(TAG, "Trusted environment initialized!")
    }

    private fun generateSigningKey(alias: String) {
        val generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                androidKeyStore
            )
        val secp256r1 = ECGenParameterSpec("secp256r1")
        val attestationChallenge = "xyz.proofcast.tee_vm.android".toByteArray(StandardCharsets.UTF_8)
        val purposes = KeyProperties.PURPOSE_SIGN.or(KeyProperties.PURPOSE_VERIFY)
        val spec = KeyGenParameterSpec.Builder(alias, purposes)
            .setAlgorithmParameterSpec(secp256r1)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(false)
            .setIsStrongBoxBacked(isStrongboxBacked)
            .setAttestationChallenge(attestationChallenge)
            .build()
        generator.initialize(spec)
        generator.generateKeyPair()
        Log.d(TAG, "New key pair with alias '$alias' created")
    }


    private fun generateSecretKey(alias: String) {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, androidKeyStore)
        val purposes = KeyProperties.PURPOSE_ENCRYPT.or(KeyProperties.PURPOSE_DECRYPT)
        val spec = KeyGenParameterSpec.Builder(alias, purposes)
            .setKeySize(128)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setIsStrongBoxBacked(isStrongboxBacked)
            .build()
        generator.init(spec)
        Log.i(TAG, "Secret key generated (strongbox: $isStrongboxBacked)")
        val key = generator.generateKey()
        val factory = SecretKeyFactory.getInstance(key.getAlgorithm(), androidKeyStore)
        val info: KeyInfo = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
        Log.d(TAG, "New AES key generated with alias: $alias")
        Log.d(TAG, "Is inside secure hardware? " + info.isInsideSecureHardware())

        generateSecp256k1Key()
    }

    fun generateSecp256k1Key() {
            val curve = ECNamedCurveTable.getByName("secp256k1")
            val domainParams = ECDomainParameters(
                curve.curve,
                curve.g,
                curve.n,
                curve.h,
                curve.seed
            )

            val secureRandom = SecureRandom()
            val keyParams = ECKeyGenerationParameters(domainParams, secureRandom)
            val generator = ECKeyPairGenerator()
            generator.init(keyParams)
            val keyPair = generator.generateKeyPair()

            val privateKey = keyPair.private as ECPrivateKeyParameters
            val publicKey = keyPair.public as ECPublicKeyParameters

            with (db.edit()) {
                val encryptedPrivateKey = encrypt(privateKey.d.toByteArray()).toHexString()
                val clearPublicKey = publicKey.q.getEncoded(false).toHexString()
                putString(PREFERENCES_PRIVATE_KEY, encryptedPrivateKey)
                putString(PREFERENCES_PUBLIC_KEY, clearPublicKey)
                commit()
            }
        Log.i(TAG,"New secp256k1 key pair stored successfully into app preferences")
    }

    fun getSecp256k1PublicKey(): ByteArray {
        return db.getString(PREFERENCES_PUBLIC_KEY, null)!!.fromHexString()
    }

    fun keccak256(message: ByteArray): ByteArray {
        val keccak256 = Keccak.Digest256()
        keccak256.update(message)
        return keccak256.digest()
    }
    fun signWithSecp256k1PrivateKey(message: ByteArray): ByteArray {
        val privateKey = BigInteger(decrypt(db.getString(PREFERENCES_PRIVATE_KEY, null)!!.fromHexString()))
        val publicKey = Sign.publicKeyFromPrivate(privateKey)
        val keyPair = ECKeyPair(privateKey, publicKey)
        val needToHash = false
        val signature = Sign.signMessage(message, keyPair, needToHash)

        return signature.r
            .plus(signature.s)
            .plus(signature.v)
    }

    fun getEIP191SignedData(data: ByteArray): ByteArray {
        val dataLength = data.size.toString().toByteArray()
        return keccak256(
            ETHEREUM_MSG_PREFIX
                .plus(dataLength)
                .plus(data)
        )
    }

    fun getAddress(): ByteArray {
        val pubKey = getSecp256k1PublicKey()
        val pubKeyWithoutPrefix = pubKey.sliceArray(IntRange(1, pubKey.size - 1))
        val hash = keccak256(pubKeyWithoutPrefix)
        return hash.sliceArray(IntRange(hash.size - 20, hash.size - 1))
    }

    fun getSecp256k1Attestation(): ByteArray {
        val pubKey = db.getString(PREFERENCES_PUBLIC_KEY, null)!!.fromHexString()
        return signWithAttestationKey(pubKey)
    }

    private fun getSecretKey(alias: String): Key {
        val ks = KeyStore.getInstance(androidKeyStore).apply { load(null) }
        return ks.getKey(alias, null)
    }

    private fun encrypt(data: ByteArray, alias: String = ALIAS_ANDROID_SECRET_KEY): ByteArray {
        val key = getSecretKey(alias)
        val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        val encryptedData = cipher.doFinal(data)

        val result = ByteArray(iv.size + encryptedData.size)
        var k = 0
        for (b in iv) { result[k++] = b }
        for (b in encryptedData) { result[k++] = b }

        return result
    }

    private fun decrypt(data: ByteArray, alias: String = ALIAS_ANDROID_SECRET_KEY): ByteArray {
        val key = getSecretKey(alias)
        val iv = ByteArray(12)
        val encryptedData = ByteArray(data.size - iv.size)

        // Extracting iv and the encrypted data
        for (i in iv.indices) { iv[i] = data[i] }
        var i = iv.size
        for (k in encryptedData.indices) { encryptedData[k] = data[i++] }

        val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
        val spec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.DECRYPT_MODE, key, spec)

        return cipher.doFinal(encryptedData)
    }

    private fun maybeGenerateSecretKey(alias: String = ALIAS_ANDROID_SECRET_KEY) {
        val ks = KeyStore.getInstance(androidKeyStore)
            .apply { load(null) }
        if (!ks.containsAlias(alias)) {
            generateSecretKey(alias)
        }
    }

    private fun maybeGenerateSigningKey(alias: String = ALIAS_ANDROID_ATTESTATION_KEY): KeyStore {
        val ks = KeyStore.getInstance(androidKeyStore).apply { load(null) }

        if (!ks.containsAlias(alias)) {
            generateSigningKey(alias)
        }

        return ks
    }

    private fun getPrivateKey(alias: String): PrivateKey? {
        val ks = maybeGenerateSigningKey(alias)
        val entry = ks.getEntry(alias, null)
        if (entry !is KeyStore.PrivateKeyEntry) {
            Log.w(TAG, "Not an instance of a PrivateKeyEntry '$alias'")
            return null
        }

        return entry.privateKey
    }

    fun getPublicKey(alias: String): PublicKey {
        val ks = maybeGenerateSigningKey(alias)
        return ks.getCertificate(alias).publicKey
    }

    fun sign(alias: String, data: ByteArray): ByteArray {
        val privateKey = getPrivateKey(alias)
        return Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey)
            update(data)
            sign()
        }
    }

    fun getCertificateAttestation(alias: String): ByteArray {
        val ks = maybeGenerateSigningKey(alias)
        val certificateChain = ks.getCertificateChain(alias)
        val leaf = certificateChain[0].encoded
        val intermediate = certificateChain[1].encoded
        val root = certificateChain[2].encoded

        return AttestationCertificate(leaf, intermediate, root).toCbor()
    }

    fun getAttestationKeyPublicKey() = getPublicKey(ALIAS_ANDROID_ATTESTATION_KEY)
    fun getCertificateAttestation() = getCertificateAttestation(ALIAS_ANDROID_ATTESTATION_KEY)
    fun signWithAttestationKey(data: ByteArray) = sign(ALIAS_ANDROID_ATTESTATION_KEY, data)


}