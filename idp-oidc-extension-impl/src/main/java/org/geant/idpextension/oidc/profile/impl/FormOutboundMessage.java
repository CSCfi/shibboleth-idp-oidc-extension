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

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jwt.PlainJWT;
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
public class FormOutboundMessage extends AbstractOIDCResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(FormOutboundMessage.class);

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
            resp = new AuthenticationErrorResponse(getOidcResponseContext().getRedirectURI(), new ErrorObject(
                    getOidcResponseContext().getErrorCode(), getOidcResponseContext().getErrorDescription()),
                    getAuthenticationRequest().getState(), getAuthenticationRequest().getResponseMode());
            log.debug("constructed response:" + ((AuthenticationErrorResponse) resp).toURI());
        } else {
            /**
             * 
             * We support now only forming implicit response.
             * 
             * 
             * TODO: idtoken signing is mandatory. We are missing that step
             * still. We create a plain jwt here. Replace with fetching a signed
             * jwt from context
             */
            if (getAuthenticationRequest().getResponseType().impliesImplicitFlow()) {
                try {
                    resp = new AuthenticationSuccessResponse(getOidcResponseContext().getRedirectURI(), null,
                            new PlainJWT(getOidcResponseContext().getIDToken().toJWTClaimsSet()), null,
                            getAuthenticationRequest().getState(), null, getAuthenticationRequest().getResponseMode());
                    log.debug("constructed response:" + ((AuthenticationSuccessResponse) resp).toURI());
                } catch (ParseException e) {
                    log.error("{} jwt parsing failed {}", getLogPrefix(), e.getMessage());
                    ActionSupport.buildEvent(profileRequestContext, EventIds.UNABLE_TO_ENCODE);
                    return;
                }
            }
        }
        if (resp == null) {
            //TODO: We should have this check BEFORE and form oidc error response in the case of unsupported FLOW..
            //This may be left in place as a final check.
            log.error("{} unsupported response type {}", getLogPrefix(), getAuthenticationRequest().getResponseType()
                    .toString());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
            return;
        }
        ((MessageContext)getOidcResponseContext().getParent()).setMessage(resp);
    }
}