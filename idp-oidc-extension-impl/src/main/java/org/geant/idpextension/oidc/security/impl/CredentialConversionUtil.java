/*
 * GÉANT BSD Software License
 *
 * Copyright (c) 2017 - 2020, GÉANT
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 * disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 * following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the GÉANT nor the names of its contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * Disclaimer:
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.geant.idpextension.oidc.security.impl;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import javax.annotation.Nonnull;

import org.geant.security.jwk.JWKCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

/**
 * Generic tool methods related to converting {@link Credential} to JWK.
 */
public final class CredentialConversionUtil {

    /**
     * Resolves kid from key name. If there is no key name and the credential is JWK, the kid is read from JWK.
     * 
     * @return key names or null if not found.
     */
    public static String resolveKid(@Nonnull final Credential credential) {
        if (credential.getKeyNames() != null) {
            for (String keyName : credential.getKeyNames()) {
                return keyName;
            }
        }
        if (credential instanceof JWKCredential) {
            return ((JWKCredential) credential).getKid();
        }
        return null;
    }

    /**
     * Resolves KeyUse parameter from credential.
     * 
     * @param credential credential to resolve KeyUse of
     * @return KeyUse of credential
     */
    public static KeyUse resolveKeyUse(final Credential credential) {
        if (credential == null || credential.getUsageType() == null) {
            return null;
        }
        if (credential.getUsageType().equals(UsageType.SIGNING)) {
            return KeyUse.SIGNATURE;
        }
        if (credential.getUsageType().equals(UsageType.ENCRYPTION)) {
            return KeyUse.ENCRYPTION;
        }
        return null;
    }

    /**
     * Converts credential to JWK. Only RSA and EC keys supported.
     * 
     * @param credential to convert.
     * @return credential as JWK.
     */
    public static JWK credentialToKey(final Credential credential) {
        if (credential == null || credential.getPublicKey() == null) {
            return null;
        }
        final String algorithm = credential.getPublicKey().getAlgorithm();
        if ("RSA".equals(algorithm)) {
            return new RSAKey.Builder((RSAPublicKey) credential.getPublicKey()).keyUse(resolveKeyUse(credential))
                    .keyID(resolveKid(credential)).build();
        }
        if ("EC".equals(algorithm)) {
            return new ECKey.Builder(Curve.forECParameterSpec(((ECPublicKey) credential.getPublicKey()).getParams()),
                    (ECPublicKey) credential.getPublicKey()).keyUse(resolveKeyUse(credential))
                    .keyID(resolveKid(credential)).build();
        }
        return null;
    }
    
}
