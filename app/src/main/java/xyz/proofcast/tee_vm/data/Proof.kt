package xyz.proofcast.tee_vm.data

import kotlinx.serialization.Serializable

@Serializable
data class Proof(
    val statement: String,
    val proof: ProofAndroid,
)