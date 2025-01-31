/*
 * Copyright © 2017-2023 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.crypto;

import com.wireguard.util.NonNullForAll;

/**
 * Represents an immutable Curve25519 key pair as used by WireGuard.
 */
@NonNullForAll
public final class KeyPair {
    private final Key privateKey;
    private final Key publicKey;

    /**
     * Creates a key pair using a newly-generated private key.
     */
    public KeyPair() {
        this(Key.generatePrivateKey());
    }

    /**
     * Creates a key pair using an existing private key.
     *
     * @param privateKey a private key, used to derive the public key
     */
    public KeyPair(final Key privateKey) {
        this.privateKey = privateKey;
        this.publicKey = Key.generatePublicKey(privateKey);
    }

    /**
     * @return the private key
     */
    public Key getPrivateKey() {
        return privateKey;
    }

    /**
     * @return the public key
     */
    public Key getPublicKey() {
        return publicKey;
    }
}
