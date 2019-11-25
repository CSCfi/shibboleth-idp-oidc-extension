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
 * Action that signs {@link UserInfo} and sets it to {@link OidcResponseContext#getProcessedToken}. Actions fails
 * silently if signing is not requested.
 */
public class SignUserInfoResponse extends AbstractSignJWTAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(SignUserInfoResponse.class);

    /** token claims set to sign. */
    private JWTClaimsSet userInfoClaims;
    
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
        if (!super.doPreExecute(profileRequestContext) || userInfoSigAlgStrategy.apply(profileRequestContext) == null) {
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
        getOidcResponseContext().setProcessedToken(jwt);
    }

}