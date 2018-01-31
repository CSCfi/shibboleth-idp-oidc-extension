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

import net.shibboleth.idp.profile.config.ProfileConfiguration;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.geant.idpextension.oidc.config.OIDCCoreProtocolConfiguration;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

/**
 * Action that forms outbound message based on token request and response
 * context. Formed message is set to
 * {@link ProfileRequestContext#getOutboundMessageContext()}.
 *
 *
 * NOTE! Very preliminary copy-paste implementation. WILL CHANGE!
 *
 */
@SuppressWarnings("rawtypes")
public class FormOutboundTokenResponseMessage extends AbstractOIDCTokenResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(FormOutboundTokenResponseMessage.class);

    /** if id token should be signed or not. */
    private boolean signedToken = true;

    /** access token for response. */
    private AccessToken accessToken;

    /** Strategy function to lookup RelyingPartyContext. */
    @Nonnull
    private Function<ProfileRequestContext, RelyingPartyContext> relyingPartyContextLookupStrategy;

    /** Default constructor. */
    public FormOutboundTokenResponseMessage() {
        relyingPartyContextLookupStrategy = new ChildContextLookup<>(RelyingPartyContext.class);

    }

    /**
     * Set the lookup strategy to use to locate the {@link RelyingPartyContext}.
     * 
     * @param strategy
     *            lookup function to use
     */
    public void setRelyingPartyContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, RelyingPartyContext> strategy) {

        relyingPartyContextLookupStrategy = Constraint.isNotNull(strategy,
                "RelyingPartyContext lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        if (!super.doPreExecute(profileRequestContext)) {
            log.error("{} pre-execute failed", getLogPrefix());
            return false;
        }
        final RelyingPartyContext rpc = relyingPartyContextLookupStrategy.apply(profileRequestContext);
        if (rpc != null) {
            final ProfileConfiguration pc = rpc.getProfileConfig();
            if (pc != null && pc instanceof OIDCCoreProtocolConfiguration) {
                signedToken = ((OIDCCoreProtocolConfiguration) pc).getSignIDTokens().apply(profileRequestContext);
            }
        }
        accessToken = getOidcResponseContext().getAccessToken();
        if (accessToken == null) {
            log.error("{} unable to provide access token (required)", getLogPrefix());
            // TODO: set error parameters to produce oidc error response
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        return true;
    }

    /**
     * Returns signed (preferred) or non signed id token. Returns null if signed
     * token is expected but not available.
     * 
     * @return id token.
     */
    private JWT getIdToken() {
        JWT jwt = getOidcResponseContext().getSignedIDToken();
        if (!signedToken) {
            try {
                jwt = new PlainJWT(getOidcResponseContext().getIDToken().toJWTClaimsSet());
            } catch (ParseException e) {
                log.error("{} error parsing claimset", getLogPrefix());
            }
        }

        return jwt;
    }

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        TokenResponse resp;
        if (getOidcResponseContext().getErrorCode() != null) {
            resp = new TokenErrorResponse(new ErrorObject(getOidcResponseContext().getErrorCode(),
                    getOidcResponseContext().getErrorDescription()));
        } else {
            JWT idToken = getIdToken();
            if (idToken == null) {
                log.error("{} unable to provide id token (required)", getLogPrefix());
                // TODO: set error parameters to produce oidc error response
                ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
                return;
            }
            // TODO: refresh token handling is missing totally
            // TODO: refactoring..has duplicate functionality to
            // FormOutboundAuthenticationResponseMessage..
            resp = new OIDCTokenResponse(new OIDCTokens(idToken, accessToken, null/* RefreshToken refreshToken */));
        }
        ((MessageContext) getOidcResponseContext().getParent()).setMessage(resp);
    }
}