package xyz.proofcast.tee_vm.data
import kotlinx.serialization.Serializable

@Serializable
data class ProofAndroidValue(
    val commitment: String,
    val signature: String,
    val publicKey: String,
    val attestedPublicKey: String,
    val certificateChain: String,
)