package com.wireguard.android.backend

import com.wireguard.util.NonNullForAll

/**
 * A subclass of [Exception] that encapsulates the reasons for a failure originating in
 * implementations of [Backend].
 */
@NonNullForAll
class BackendException(
    val reason: Reason,
    vararg format: Any
) : Exception() {

    val format: Array<out Any> = format

    /**
     * Enum class containing all known reasons for why a [BackendException] might be thrown.
     */
    enum class Reason {
        INVALID_SPLIT_TUNNEL_CONFIGURATION,
        UNKNOWN_KERNEL_MODULE_NAME,
        WG_QUICK_CONFIG_ERROR_CODE,
        TUNNEL_MISSING_CONFIG,
        VPN_NOT_AUTHORIZED,
        UNABLE_TO_START_VPN,
        TUN_CREATION_ERROR,
        GO_ACTIVATION_ERROR_CODE,
        DNS_RESOLUTION_FAILURE,
        TUNNEL_NOT_ACTIVE,
        VPN_SERVICE_NOT_INITIALIZED
    }
}
