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
import java.util.Iterator;

import javax.annotation.Nonnull;

import org.geant.security.jwk.JWKCredential;
import org.opensaml.profile.action.EventIds;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;

/**
 * Generic utility class for helping JWT signature validation.
 */
public class JWTSignatureValidationUtil {

    /** Class logger. */
    @Nonnull
    private static Logger log = LoggerFactory.getLogger(JWTSignatureValidationUtil.class);

    private JWTSignatureValidationUtil() {

    }

    /**
     * Validates the signature of the given JWT using the given security parameters context. If the validation fails for
     * any reason, including insufficient prequisities in the context, an event identifier is returned. Successful
     * validation produces null result.
     * 
     * @param secParamCtx The {@link SecurityParametersContext} to use for signature validation.
     * @param signedJwt The signed JWT to be validated.
     * @param invalidJwtEventId The event identifier describing the invalid JWT.
     * @return
     */
    public static String validateSignature(final SecurityParametersContext secParamCtx, final SignedJWT signedJwt,
            final String invalidJwtEventId) {
        if (secParamCtx == null) {
            log.error("No security parameters context is available");
            return EventIds.INVALID_SEC_CFG;
        }
        if (secParamCtx.getSignatureSigningParameters() == null
                || !(secParamCtx.getSignatureSigningParameters() instanceof OIDCSignatureValidationParameters)) {
            log.error("No signature validation credentials available");
            return EventIds.INVALID_SEC_CFG;
        }
        final OIDCSignatureValidationParameters signatureValidationParameters =
                (OIDCSignatureValidationParameters) secParamCtx.getSignatureSigningParameters();
        final Algorithm algorithm = signedJwt.getHeader().getAlgorithm();
        final Iterator<?> it = signatureValidationParameters.getValidationCredentials().iterator();
        boolean verified = false;
        while (it.hasNext()) {
            final JWKCredential credential = (JWKCredential) it.next();
            if (!algorithm.equals(credential.getAlgorithm())) {
                log.debug("Credential alg {} not matching jwt header alg {}", credential.getAlgorithm().getName(),
                        algorithm.getName());
                if (it.hasNext()) {
                    log.debug("Unable to validate given JWT with credential, picking next key");
                    continue;
                } else {
                    log.error("Unable to validate given JWT with any of the credentials");
                    return invalidJwtEventId;
                }
            }
            JWSVerifier verifier = null;
            try {
                if (JWSAlgorithm.Family.HMAC_SHA.contains(algorithm)) {
                    verifier = new MACVerifier(credential.getSecretKey());
                }
                if (JWSAlgorithm.Family.RSA.contains(algorithm)) {
                    verifier = new RSASSAVerifier((RSAPublicKey) credential.getPublicKey());
                }
                if (JWSAlgorithm.Family.EC.contains(algorithm)) {
                    verifier = new ECDSAVerifier((ECPublicKey) credential.getPublicKey());
                }
                if (verifier == null) {
                    log.error("No verifier for given JWT for alg {}", algorithm.getName());
                    return EventIds.INVALID_SEC_CFG;
                }
                if (!signedJwt.verify(verifier)) {
                    if (it.hasNext()) {
                        log.debug("Unable to validate given JWT with credential, picking next key");
                        continue;
                    } else {
                        log.error("Unable to validate given JWT with any of the credentials");
                        return invalidJwtEventId;
                    }
                }
                verified = true;
                log.debug("JWT {} verified using algorithm {} and key {}", signedJwt.serialize(), algorithm.getName(),
                        credential.getKid());
                break;
            } catch (JOSEException e) {
                if (it.hasNext()) {
                    log.debug("Unable to validate given JWT with credential, {}, picking next key", e.getMessage());
                } else {
                    log.error("Unable to validate given JWT with any of the credentials, {}", e.getMessage());
                    return invalidJwtEventId;
                }
            }
        }
        if (!verified) {
            // This is executed only if there was no credentials (which should not happen).
            log.error("Unable to validate given JWT signature");
            return EventIds.INVALID_SEC_CFG;
        }
        return null;
    }

}
