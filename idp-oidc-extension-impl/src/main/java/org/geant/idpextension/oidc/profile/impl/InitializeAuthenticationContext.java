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

import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.profile.AbstractProfileAction;
import org.opensaml.profile.action.ActionSupport;

import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Prompt;

/**
 * An action that creates an {@link AuthenticationContext} and attaches it to
 * the current {@link ProfileRequestContext}.
 * 
 * <p>
 * If the incoming message is a OIDC {@link AuthnRequest}, then basic
 * authentication policy (IsPassive, ForceAuthn) is interpreted from the request
 * max_age and prompt parameters. If the incoming message has login_hint
 * parameter the value of it is placed to hinted name.
 * </p>
 * 
 * 
 */
@SuppressWarnings("rawtypes")
public class InitializeAuthenticationContext extends AbstractProfileAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(InitializeAuthenticationContext.class);

    /** OIDC Authentication request. */
    private AuthenticationRequest request;

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        if (!super.doPreExecute(profileRequestContext)) {
            log.error("{} pre-execute failed", getLogPrefix());
            return false;
        }
        if (profileRequestContext.getInboundMessageContext() == null) {
            log.error("{} Unable to locate inbound message context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;
        }
        Object message = profileRequestContext.getInboundMessageContext().getMessage();

        if (message == null || !(message instanceof AuthenticationRequest)) {
            log.error("{} Unable to locate inbound message", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;
        }
        request = (AuthenticationRequest) message;
        return true;

    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        log.debug("{} Initializing authentication context", getLogPrefix());
        final AuthenticationContext authnCtx = new AuthenticationContext();
        /*
         * TODO: This is a shortcut. We should compare the value to possible
         * existing authentication result.
         */
        authnCtx.setForceAuthn(request.getMaxAge() == 0);
        if (request.getPrompt() != null) {
            authnCtx.setIsPassive(request.getPrompt().contains(Prompt.Type.NONE));
        }
        if (request.getLoginHint() != null) {
            authnCtx.setHintedName(request.getLoginHint());
        }
        profileRequestContext.addSubcontext(authnCtx, true);
        log.debug("{} Created authentication context: {}", getLogPrefix(), authnCtx);
    }

}