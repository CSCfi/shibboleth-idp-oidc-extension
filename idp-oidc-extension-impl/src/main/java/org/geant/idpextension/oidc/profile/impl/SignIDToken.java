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
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;

/**
 * Action that signs {@link IDTokenClaimsSet} and sets it to {@link OidcResponseContext#getProcessedToken}. Actions fails
 * silently if there are no signing parameters available.
 */
public class SignIDToken extends AbstractSignJWTAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(SignIDToken.class);

    /** token claims set to sign. */
    private JWTClaimsSet idTokenClaims;

    /** {@inheritDoc} */
    @Override
    protected boolean
            doPreExecute(@SuppressWarnings("rawtypes") @Nonnull final ProfileRequestContext profileRequestContext) {

        if (!super.doPreExecute(profileRequestContext)) {
            return false;
        }
        if (getOidcResponseContext().getIDToken() == null) {
            log.error("{} No id token available", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;
        }
        try {
            idTokenClaims = getOidcResponseContext().getIDToken().toJWTClaimsSet();
        } catch (ParseException e) {
            log.error("{} id token parsing failed {}", getLogPrefix(), e.getMessage());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;
        }
        return true;
    }

    /**
     * Sets id token claims as input for signing.
     * 
     * @return id token claims.
     */
    @Override
    protected JWTClaimsSet getClaimsSetToSign() {
        return idTokenClaims;
    }

    /**
     * Set signed id token to response context.
     * 
     * @param jwt signed id token.
     */
    @Override
    protected void setSignedJWT(SignedJWT jwt) {
        getOidcResponseContext().setProcessedToken(jwt);

    }

}