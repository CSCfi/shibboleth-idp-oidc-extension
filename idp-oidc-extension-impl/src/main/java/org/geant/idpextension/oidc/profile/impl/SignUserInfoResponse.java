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

import org.geant.idpextension.oidc.profile.context.navigate.DefaultUserInfoSigningAlgLookupFunction;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Function;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Action that signs {@link UserInfo} and sets it to {@link OidcResponseContext#getSignedIDToken}. Actions fails
 * silently if signing is not requested.
 */
public class SignUserInfoResponse extends AbstractSignJWTAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(SignUserInfoResponse.class);

    /** token claims set to sign. */
    private JWTClaimsSet userInfoClaims;

    /** algorithm used for signing response. */
    private JWSAlgorithm algorithm;

    /** Strategy used to determine user info response signing algorithm. */
    @SuppressWarnings("rawtypes")
    @Nonnull
    private Function<ProfileRequestContext, JWSAlgorithm> userInfoSigAlgStrategy;

    /**
     * Constructor.
     */
    public SignUserInfoResponse() {
        userInfoSigAlgStrategy = new DefaultUserInfoSigningAlgLookupFunction();
    }

    /**
     * Set the strategy used to user info signing algorithm lookup strategy.
     * 
     * @param strategy lookup strategy
     */
    public void setUserInfoSigningAlgLookupStrategy(
            @SuppressWarnings("rawtypes") @Nonnull final Function<ProfileRequestContext, JWSAlgorithm> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        userInfoSigAlgStrategy =
                Constraint.isNotNull(strategy, "User Info Signing Algorithm lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected boolean
            doPreExecute(@SuppressWarnings("rawtypes") @Nonnull final ProfileRequestContext profileRequestContext) {
        algorithm = userInfoSigAlgStrategy.apply(profileRequestContext);
        if (algorithm == null) {
            return false;
        }
        if (!super.doPreExecute(profileRequestContext)) {
            if (algorithm != null) {
                log.warn("{} unable to sign userinfo response, requested algorithm is {}", getLogPrefix(),
                        algorithm.getName());
            }
            return false;
        }
        final JWSAlgorithm algConfigured = resolveAlgorithm();
        if (!algorithm.equals(algConfigured)) {
            log.error("{} unable to sign userinfo response, requested algorithm is {} and configured is {}",
                    getLogPrefix(), algorithm, algConfigured.getName());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_SEC_CFG);
            return false;
        }
        if (getOidcResponseContext().getUserInfo() == null) {
            log.error("{} No userinfo available", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;
        }
        try {
            userInfoClaims = getOidcResponseContext().getUserInfo().toJWTClaimsSet();
        } catch (ParseException e) {
            log.error("{} userinfo parsing failed {}", getLogPrefix(), e.getMessage());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;
        }
        return true;
    }

    /**
     * Sets user info claims as input for signing.
     * 
     * @return user info claims.
     */
    @Override
    protected JWTClaimsSet getClaimsSetToSign() {
        return userInfoClaims;
    }

    /**
     * Set signed user info to response context.
     * 
     * @param jwt signed user info response.
     */
    @Override
    protected void setSignedJWT(SignedJWT jwt) {
       getOidcResponseContext().setSignedToken(jwt);
    }

}