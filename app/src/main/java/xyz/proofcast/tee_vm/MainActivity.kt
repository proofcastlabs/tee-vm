package xyz.proofcast.tee_vm

import android.content.Context
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import kotlinx.coroutines.runBlocking
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import io.ktor.client.*
import io.ktor.client.plugins.websocket.*
import io.ktor.http.*
import io.ktor.websocket.*
import xyz.proofcast.tee_vm.data.ProofAndroid
import xyz.proofcast.tee_vm.data.Proof
import xyz.proofcast.tee_vm.data.ProofAndroidValue
import xyz.proofcast.tee_vm.security.TrustedExecutor
import xyz.proofcast.tee_vm.security.Utils.Companion.toHexString
import xyz.proofcast.tee_vm.security.Utils.Companion.toJson
import java.lang.Exception

class MainActivity : AppCompatActivity() {

    /**
     * A native method that is implemented by the 'tee_vm' native library,
     * which is packaged with this application.
     */
    external fun runVM(input: String): String

    private val isStrongboxBacked = false
    private var client: HttpClient? = null
    private var tee: TrustedExecutor? = null

    val TAG = "[Main]"

    init {
        System.loadLibrary("tee_vm")
    }

    private fun getProof(result: ByteArray): String {
        Log.d(TAG, "Getting proof using address: ${tee!!.getAddress().toHexString()}")
        val type = tee!!.proofType
        val statement = result.toString(StandardCharsets.UTF_8)
        val sha256 = MessageDigest.getInstance("SHA-256")
        val commitment = sha256.digest(result)
        val signature = tee!!.signWithSecp256k1PrivateKey(commitment).toHexString()
        val publicKey = tee!!.getSecp256k1PublicKey().toHexString()
        val attestedPublicKey = tee!!.getSecp256k1Attestation().toHexString()
        val certChain = tee!!.getCertificateAttestation().toHexString()
        val value = ProofAndroidValue(
            commitment.toHexString(),
            signature,
            publicKey,
            attestedPublicKey,
            certChain
        )
        val proof = ProofAndroid(type, value)
        return Proof(statement, proof).toJson()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
//        setContentView(R.layout.activity_main)

        val db = getPreferences(Context.MODE_PRIVATE)
        tee = TrustedExecutor(db, isStrongboxBacked)
        client = HttpClient { install(WebSockets) }

        Log.v("Debug Log", "Init")
        val result = runVM("/storage/emulated/0/binary.elf")
        Log.v("Debug Log", result)
        getProof(result.toByteArray())
//        runBlocking {
//            client!!.webSocket(
//                method = HttpMethod.Get,
//                host = "127.0.0.1",
//                port = 3000,
//            ) {
//                Log.i(TAG, "Websocket connected")
//                while (true) {
//                    val request = incoming.receive() as? Frame.Text ?: continue
//                    val txt = request.readText()
//                    Log.v("Debug Log", "cycling")
//                    val resp = try {
//                        val result = runVM("/storage/emulated/0/binary.elf")
//                        Log.v(result, "Log")
//                        getProof(result.toByteArray())
//                    } catch(e: Exception) {
//                        val errMsg = "teeVM failed"
//                        Log.e(TAG,errMsg, e)
//                        "{\"error\": \"$errMsg\"}"
//                    }
//                    send(resp)
//                    Log.i(TAG, "Sent!")
//                }
//            }
//        }

        client!!.close()
        Log.i(TAG, "Websocket connection closed!")
    }

    override fun onStop() {
        super.onStop()
        client!!.close()
    }
}