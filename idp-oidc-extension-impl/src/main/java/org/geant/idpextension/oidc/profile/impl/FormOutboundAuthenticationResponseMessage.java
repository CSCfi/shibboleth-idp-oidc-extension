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
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;

/**
 * Action that forms outbound message based on request and response context.
 * Formed message is set to
 * {@link ProfileRequestContext#getOutboundMessageContext()}.
 * 
 * 
 *
 */
@SuppressWarnings("rawtypes")
public class FormOutboundAuthenticationResponseMessage extends AbstractOIDCAuthenticationResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(FormOutboundAuthenticationResponseMessage.class);

    /** if id token should be signed or not. */
    private boolean signedToken = true;

    /** Strategy function to lookup RelyingPartyContext. */
    @Nonnull
    private Function<ProfileRequestContext, RelyingPartyContext> relyingPartyContextLookupStrategy;

    /** Default constructor. */
    public FormOutboundAuthenticationResponseMessage() {
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
        if (jwt == null && !signedToken) {
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
        if (getOidcResponseContext().getRedirectURI() == null) {
            log.error("{} redirect uri must be validated to form response", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return;
        }
        AuthenticationResponse resp = null;
        if (getOidcResponseContext().getErrorCode() != null) {
            resp = new AuthenticationErrorResponse(getOidcResponseContext().getRedirectURI(),
                    new ErrorObject(getOidcResponseContext().getErrorCode(),
                            getOidcResponseContext().getErrorDescription()),
                    getAuthenticationRequest().getState(), getAuthenticationRequest().getResponseMode());
            log.debug("constructed response:" + ((AuthenticationErrorResponse) resp).toURI());
        } else {
            // TODO: change this to use client metadata
            if (getAuthenticationRequest().getResponseType().impliesImplicitFlow()) {
                JWT idToken = getIdToken();
                if (idToken == null) {
                    log.error("{} unable to provide id token (required)", getLogPrefix());
                    ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
                    return;
                }
                // TODO: We return now bare auth code without sign and crypto.
                // Replace with signed and encrypted code.
                resp = new AuthenticationSuccessResponse(getOidcResponseContext().getRedirectURI(),
                        getOidcResponseContext().getAuthzCodeClaims() == null ? null
                                : new AuthorizationCode(
                                        new PlainJWT(getOidcResponseContext().getAuthzCodeClaims()).serialize()),
                        getIdToken(), null, getAuthenticationRequest().getState(), null,
                        getAuthenticationRequest().getResponseMode());
                log.debug("constructed response:" + ((AuthenticationSuccessResponse) resp).toURI());
            }
        }
        if (resp == null) {
            /**
             * We support now only forming implicit response.
             */
            log.error("{} unsupported response type {}", getLogPrefix(),
                    getAuthenticationRequest().getResponseType().toString());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
            return;
        }
        ((MessageContext) getOidcResponseContext().getParent()).setMessage(resp);
    }
}