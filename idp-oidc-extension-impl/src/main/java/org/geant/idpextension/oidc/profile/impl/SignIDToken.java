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

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
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

    // TODO: Configuration option for signing parameter is missing.
    /** JWS algorithm used to sign token. */
    private JWSAlgorithm jwsAlgorithm = JWSAlgorithm.RS256;

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
        if (signatureSigningParameters == null) {
            log.debug("{} Will not sign id token because no signature signing parameters available", getLogPrefix());
            return false;
        }

        if (getOidcResponseContext().getIDToken() == null) {
            log.error("{} No id token available", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;
        }
        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        SignedJWT jwt = null;
        String keyId = null;
        if (signatureSigningParameters.getSigningCredential().getKeyNames() != null) {
            for (String keyName : signatureSigningParameters.getSigningCredential().getKeyNames()) {
                keyId = keyName;
                break;
            }
        }
        try {
            jwt = new SignedJWT(new JWSHeader.Builder(jwsAlgorithm).keyID(keyId).build(), getOidcResponseContext()
                    .getIDToken().toJWTClaimsSet());

        } catch (ParseException e) {
            log.error("{} Error parsing claimset: {}", getLogPrefix(), e.getMessage());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return;
        }
        try {
            jwt.sign(new RSASSASigner(signatureSigningParameters.getSigningCredential().getPrivateKey()));
        } catch (JOSEException e) {
            log.error("{} Error signing id token: {}", getLogPrefix(), e.getMessage());
            ActionSupport.buildEvent(profileRequestContext, EventIds.UNABLE_TO_SIGN);
            return;
        }
        getOidcResponseContext().setSignedIDToken(jwt);
        log.debug("{} signed id token stored to context", getLogPrefix());

    }

}