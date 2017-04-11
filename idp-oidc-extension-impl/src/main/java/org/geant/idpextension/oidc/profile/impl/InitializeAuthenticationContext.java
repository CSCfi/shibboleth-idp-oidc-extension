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