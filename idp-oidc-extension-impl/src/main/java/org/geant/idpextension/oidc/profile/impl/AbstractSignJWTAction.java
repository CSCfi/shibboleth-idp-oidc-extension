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

package org.geant.idpextension.oidc.profile.impl;

import java.security.interfaces.ECPrivateKey;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.geant.idpextension.oidc.security.impl.CredentialConversionUtil;
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
     * Resolves JWS algorithm from signature signing parameters.
     * 
     * @return JWS algorithm
     */
    protected JWSAlgorithm resolveAlgorithm() {

        JWSAlgorithm algorithm = new JWSAlgorithm(signatureSigningParameters.getSignatureAlgorithm());
        if (credential instanceof JWKCredential) {
            if (!algorithm.equals(((JWKCredential) credential).getAlgorithm())) {
                log.debug("{} Signature signing algorithm {} differs from JWK algorithm {}", getLogPrefix(),
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
        JWTClaimsSet jwtClaimSet = getClaimsSetToSign();
        if (jwtClaimSet == null) {
            log.debug("Claim set is null, nothing to do");
            return;
        }
        try {
            Algorithm jwsAlgorithm = resolveAlgorithm();
            JWSSigner signer = getSigner(jwsAlgorithm);
            jwt = new SignedJWT(new JWSHeader.Builder(new JWSAlgorithm(jwsAlgorithm.getName()))
                    .keyID(CredentialConversionUtil.resolveKid(credential)).build(), jwtClaimSet);
            jwt.sign(signer);
        } catch (JOSEException e) {
            log.error("{} Error signing claim set: {}", getLogPrefix(), e.getMessage());
            ActionSupport.buildEvent(profileRequestContext, EventIds.UNABLE_TO_SIGN);
            return;
        }
        setSignedJWT(jwt);
    }

}