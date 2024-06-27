package xyz.proofcast.tee_vm.security

import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString

@Serializable
data class AttestationCertificate(
    val leaf: ByteArray,
    val intermediate: ByteArray,
    val root: ByteArray,
)