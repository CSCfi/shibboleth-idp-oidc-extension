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

package org.geant.idpextension.oidc.profile.impl;

import java.security.interfaces.ECPrivateKey;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.geant.security.jwk.JWKCredential;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.security.credential.Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Abstract action for signing JWT. The extending class is expected to set claims set by implementing
 * {@link getClaimsSetToSign}. The signed jwt is received by extending class by implementing method
 * {@link setSignedJWT}.
 */
@SuppressWarnings("rawtypes")
public abstract class AbstractSignJWTAction extends AbstractOIDCSigningResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(AbstractSignJWTAction.class);

    /** resolved credential. */
    private Credential credential;

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        if (!super.doPreExecute(profileRequestContext)) {
            return false;
        }
        credential = signatureSigningParameters.getSigningCredential();
        return true;
    }

    /**
     * Returns correct implementation of signer based on algorithm type.
     * 
     * @param jwsAlgorithm JWS algorithm
     * @return signer for algorithm and private key
     * @throws JOSEException if algorithm cannot be supported
     */
    private JWSSigner getSigner(Algorithm jwsAlgorithm) throws JOSEException {
        if (JWSAlgorithm.Family.EC.contains(jwsAlgorithm)) {
            return new ECDSASigner((ECPrivateKey) credential.getPrivateKey());
        }
        if (JWSAlgorithm.Family.RSA.contains(jwsAlgorithm)) {
            return new RSASSASigner(credential.getPrivateKey());
        }
        if (JWSAlgorithm.Family.HMAC_SHA.contains(jwsAlgorithm)) {
            return new MACSigner(credential.getSecretKey());
        }
        throw new JOSEException("Unsupported algorithm " + jwsAlgorithm.getName());
    }

    /**
     * Resolves kid from key name. If there is no key name and the credential is JWK, the kid is read from JWK.
     * 
     * @return key names or null if not found.
     */
    private String resolveKid() {
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
     * Resolves JWS algorithm from signature signing parameters.
     * 
     * @return JWS algorithm
     */
    protected JWSAlgorithm resolveAlgorithm() {

        JWSAlgorithm algorithm = new JWSAlgorithm(signatureSigningParameters.getSignatureAlgorithm());
        if (credential instanceof JWKCredential) {
            if (!algorithm.equals(((JWKCredential) credential).getAlgorithm())) {
                log.warn("{} Signature signing algorithm {} differs from JWK algorithm {}", getLogPrefix(),
                        algorithm.getName(), ((JWKCredential) credential).getAlgorithm());
            }
        }
        log.debug("{} Algorithm resolved {}", getLogPrefix(), algorithm.getName());
        return algorithm;
    }

    /**
     * Called with signed JWT as parameter.
     * 
     * @param jwt signed JWT.
     */
    protected abstract void setSignedJWT(@Nullable SignedJWT jwt);

    /**
     * Called to get claim set to sign.
     * 
     * @return claim set to sign
     */
    protected abstract @Nonnull JWTClaimsSet getClaimsSetToSign();

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        SignedJWT jwt = null;
        Algorithm jwsAlgorithm = resolveAlgorithm();
        String kid = resolveKid();
        JWTClaimsSet jwtClaimSet = getClaimsSetToSign();
        if (jwtClaimSet == null) {
            log.debug("Claim set is null, nothing to do");
            return;
        }
        try {
            JWSSigner signer = getSigner(jwsAlgorithm);
            jwt = new SignedJWT(new JWSHeader.Builder(new JWSAlgorithm(jwsAlgorithm.getName())).keyID(kid).build(),
                    jwtClaimSet);
            jwt.sign(signer);
        } catch (JOSEException e) {
            log.error("{} Error signing claim set: {}", getLogPrefix(), e.getMessage());
            ActionSupport.buildEvent(profileRequestContext, EventIds.UNABLE_TO_SIGN);
            return;
        }
        setSignedJWT(jwt);
    }

}