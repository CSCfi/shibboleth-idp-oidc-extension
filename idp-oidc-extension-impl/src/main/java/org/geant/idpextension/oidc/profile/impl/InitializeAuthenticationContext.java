/*
 * Licensed to the University Corporation for Advanced Internet Development,
 * Inc. (UCAID) under one or more contributor license agreements.  See the
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache
 * License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.geant.idpextension.oidc.profile.impl;

import javax.annotation.Nonnull;

import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.ActionSupport;
import net.shibboleth.idp.profile.IdPEventIds;

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
 * max_age and prompt parameters.
 * </p>
 * 
 * 
 */
@SuppressWarnings("rawtypes")
public class InitializeAuthenticationContext extends AbstractProfileAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(InitializeAuthenticationContext.class);

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        log.debug("{} Initializing authentication context", getLogPrefix());
        final AuthenticationContext authnCtx = new AuthenticationContext();
        if (profileRequestContext.getInboundMessageContext() == null) {
            log.debug("{} Unable to locate inbound message context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_PROFILE_CONFIG);
            return;
        }
        if (profileRequestContext.getInboundMessageContext().getMessage() == null) {
            log.debug("{} Unable to locate inbound message", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_PROFILE_CONFIG);
            return;
        }
        Object request = profileRequestContext.getInboundMessageContext().getMessage();
        if (request != null && request instanceof AuthenticationRequest) {
            log.debug("Initializing authentication context using oidc request parameters");
            authnCtx.setForceAuthn(((AuthenticationRequest) request).getMaxAge() == 0);
            authnCtx.setIsPassive(((AuthenticationRequest) request).getPrompt().contains(Prompt.Type.NONE));
        }

        final AuthenticationContext initialAuthnContext = profileRequestContext
                .getSubcontext(AuthenticationContext.class);
        if (initialAuthnContext != null) {
            authnCtx.setInitialAuthenticationResult(initialAuthnContext.getAuthenticationResult());
        }

        profileRequestContext.addSubcontext(authnCtx, true);

        log.debug("{} Created authentication context: {}", getLogPrefix(), authnCtx);
    }

}