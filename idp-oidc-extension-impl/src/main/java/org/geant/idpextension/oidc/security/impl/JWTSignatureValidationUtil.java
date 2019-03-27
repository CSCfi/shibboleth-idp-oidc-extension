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
import java.util.Iterator;

import javax.annotation.Nonnull;

import org.opensaml.profile.action.EventIds;
import org.opensaml.security.credential.Credential;
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
     * Validates the signature of the given JWT using the given security parameters context. If the validation fails
     * for any reason, including insufficient prequisities in the context, an event identifier is returned. Successful
     * validation produces null result.
     * 
     * @param secParamCtx The {@link SecurityParametersContext} to use for signature validation.
     * @param signedJwt The signed JWT to be validated.
     * @param invalidJwtEventId The event identifier describing the invalid JWT.
     * @return
     */
    public static String validateSignature(final SecurityParametersContext secParamCtx,
            final SignedJWT signedJwt, final String invalidJwtEventId) {
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
        if (!signatureValidationParameters.getSignatureAlgorithm().equals(algorithm.getName())) {
            log.error("Given JWT signed with algorithm {} but the registered algorithm is {}",
                    algorithm.getName(),
                    signatureValidationParameters.getSignatureAlgorithm());
            return invalidJwtEventId;
        }

        
        final Iterator<?> it = signatureValidationParameters.getValidationCredentials().iterator();
        boolean verified = false;
        while (it.hasNext()) {
            final Credential credential = (Credential) it.next();
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
                break;
            } catch (JOSEException e) {
                if (it.hasNext()) {
                    log.debug("Unable to validate given JWT with credential, {}, picking next key", 
                            e.getMessage());
                } else {
                    log.error("Unable to validate given JWT with any of the credentials, {}",
                            e.getMessage());
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
