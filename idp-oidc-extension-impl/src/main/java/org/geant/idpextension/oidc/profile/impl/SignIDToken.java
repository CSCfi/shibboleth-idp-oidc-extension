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

import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.geant.security.jwk.JWKCredential;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;

import org.opensaml.xmlsec.context.SecurityParametersContext;

/**
 * Action that signs {@link IDTokenClaimsSet}.
 *
 */
@SuppressWarnings("rawtypes")
public class SignIDToken extends AbstractOIDCAuthenticationResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(SignIDToken.class);

    /** resolved credential. */
    Credential credential;

    /**
     * Strategy used to locate the {@link SecurityParametersContext} to use for
     * signing.
     */
    @Nonnull
    private Function<ProfileRequestContext, SecurityParametersContext> securityParametersLookupStrategy;

    /** The signature signing parameters. */
    @Nullable
    private SignatureSigningParameters signatureSigningParameters;

    /** Constructor. */
    public SignIDToken() {
        securityParametersLookupStrategy = new ChildContextLookup<>(SecurityParametersContext.class);
    }

    /**
     * Set the strategy used to locate the {@link SecurityParametersContext} to
     * use.
     * 
     * @param strategy
     *            lookup strategy
     */
    public void setSecurityParametersLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, SecurityParametersContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        securityParametersLookupStrategy = Constraint.isNotNull(strategy,
                "SecurityParameterContext lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        if (!super.doPreExecute(profileRequestContext)) {
            return false;
        }

        final SecurityParametersContext secParamCtx = securityParametersLookupStrategy.apply(profileRequestContext);
        if (secParamCtx == null) {
            log.debug("{} Will not sign id token because no security parameters context is available", getLogPrefix());
            return false;
        }

        signatureSigningParameters = secParamCtx.getSignatureSigningParameters();
        if (signatureSigningParameters == null || signatureSigningParameters.getSigningCredential() == null) {
            log.debug("{} Will not sign id token because no signature signing credentials available", getLogPrefix());
            return false;
        }
        credential = signatureSigningParameters.getSigningCredential();

        if (getOidcResponseContext().getIDToken() == null) {
            log.error("{} No id token available", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;
        }
        return true;
    }

    /**
     * Returns correct implementation of signer based on algorithm type.
     * 
     * @param jwsAlgorithm
     *            JWS algorithm
     * @param key
     *            private key used
     * @return signer for algorithm and private key
     * @throws JOSEException
     *             if algorithm cannot be supported
     */
    private JWSSigner getSigner(Algorithm jwsAlgorithm, PrivateKey key) throws JOSEException {
        if (JWSAlgorithm.Family.EC.contains(jwsAlgorithm)) {
            return new ECDSASigner((ECPrivateKey) key);
        }
        if (JWSAlgorithm.Family.RSA.contains(jwsAlgorithm)) {
            return new RSASSASigner(key);
        }
        throw new JOSEException("Unsupported algorithm " + jwsAlgorithm.getName());
    }

    /**
     * Resolves kid from key name. First key name is treated as kid.
     * 
     * @param credential
     *            with key names.
     * @return key names or null if not found.
     */
    private String resolveKidFromKeyName(Credential credential) {
        if (credential.getKeyNames() != null) {
            // if the key is not jwk, we use first key name if available
            for (String keyName : credential.getKeyNames()) {
                return keyName;
            }
        }
        return null;
    }

    /**
     * Resolves JWSAlgorithm from privatekey type. All RSA keys are treated as
     * RS256 and all EC keys are treaded as ES256.
     * 
     * @param credential
     *            with private key.
     * @return RS256,ES256 or null if undetermined.
     */
    private JWSAlgorithm resolveAlgorithm(Credential credential) {
        // We check if the key is either RSA or EC
        if (credential.getPrivateKey().getAlgorithm().equals("RSA")) {
            return JWSAlgorithm.RS256;
        } else if (credential.getPrivateKey().getAlgorithm().equals("EC")) {
            return JWSAlgorithm.ES256;
        }
        return null;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        Algorithm jwsAlgorithm = null;
        SignedJWT jwt = null;
        String kid = null;

        if (credential instanceof JWKCredential) {
            // We are lucky and JWKCredential is used
            kid = ((JWKCredential) credential).getKid();
            jwsAlgorithm = ((JWKCredential) credential).getAlgorithm();
        } else {
            // We set the first key name as kid if it is found.
            kid = resolveKidFromKeyName(credential);
            jwsAlgorithm = resolveAlgorithm(credential);
            if (jwsAlgorithm == null) {
                log.error("{} Unable to sign id token, algorthmn not supported: {}", getLogPrefix(), credential
                        .getPrivateKey().getAlgorithm());
                ActionSupport.buildEvent(profileRequestContext, EventIds.UNABLE_TO_SIGN);
                return;
            }
        }

        try {
            JWSSigner signer = getSigner(jwsAlgorithm, credential.getPrivateKey());
            jwt = new SignedJWT(new JWSHeader.Builder(new JWSAlgorithm(jwsAlgorithm.getName())).keyID(kid).build(),
                    getOidcResponseContext().getIDToken().toJWTClaimsSet());
            jwt.sign(signer);
        } catch (ParseException e) {
            log.error("{} Error parsing claimset: {}", getLogPrefix(), e.getMessage());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return;
        } catch (JOSEException e) {
            log.error("{} Error signing id token: {}", getLogPrefix(), e.getMessage());
            ActionSupport.buildEvent(profileRequestContext, EventIds.UNABLE_TO_SIGN);
            return;
        }
        getOidcResponseContext().setSignedIDToken(jwt);
        log.debug("{} signed id token stored to context", getLogPrefix());

    }

}