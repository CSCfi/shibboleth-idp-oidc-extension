/*
 * Copyright (c) 2017 - 2020, GÉANT
 *
 * Licensed under the Apache License, Version 2.0 (the “License”); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an “AS IS” BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
    

    /**
     * Converts JWK key usage type to OpenSAML usage type.
     * 
     * @param jwk containing usage type. Must not be null.
     * @return usage type.
     */
    public static UsageType getUsageType(@Nonnull final JWK jwk) {
        if (KeyUse.ENCRYPTION.equals(jwk.getKeyUse())) {
            return UsageType.ENCRYPTION;
        }
        if (KeyUse.SIGNATURE.equals(jwk.getKeyUse())) {
            return UsageType.SIGNING;
        }
        return UsageType.UNSPECIFIED;
    }
    
}
