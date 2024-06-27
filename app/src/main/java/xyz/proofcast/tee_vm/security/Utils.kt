package xyz.proofcast.tee_vm.security

import android.content.Context
import android.util.Base64
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import xyz.proofcast.tee_vm.data.Proof
import org.apache.commons.codec.binary.Hex
import java.io.FileInputStream
import java.security.DigestInputStream
import java.security.MessageDigest

class Utils {
    companion object {
        fun getAppSHA256Digest(context: Context) : ByteArray {
            val inputStream = FileInputStream(context.packageCodePath)
            val messageDigest = MessageDigest.getInstance("SHA-256")
            val digestInputStream = DigestInputStream(inputStream, messageDigest)
            val buffer = ByteArray(2048)
            while (digestInputStream.read(buffer) != -1) {
                //
            }
            digestInputStream.close()
            return messageDigest.digest()
        }

        fun ByteArray.toHexString(): String = Hex.encodeHexString(this)

        fun String.fromHexString(): ByteArray = Hex.decodeHex(this)

        fun ByteArray.toBase64String(): String = Base64.encodeToString(this, Base64.NO_WRAP)

        fun Proof.toJson(): String = Json.encodeToString(this)
        fun AttestationCertificate.toJson(): String = Json.encodeToString(this)
        fun AttestationCertificate.toCbor(): ByteArray = Cbor.encodeToByteArray(this)
    }
}