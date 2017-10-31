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

import org.geant.idpextension.oidc.messaging.context.OIDCClientRegistrationResponseContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationRequest;

import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Abstract action for populating data from the {@link ClientRegistrationRequest} message to the 
 * {@link OIDCClientRegistrationResponseContext}.
 */
@SuppressWarnings("rawtypes")
public abstract class AbstractOIDCClientRegistrationResponseAction extends AbstractProfileAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(AbstractOIDCClientRegistrationResponseAction.class);

    /**
     * Strategy used to locate the {@link OIDCClientRegistrationResponseContext} associated with a given 
     * {@link MessageContext}.
     */
    @Nonnull private Function<MessageContext,OIDCClientRegistrationResponseContext> oidcResponseContextLookupStrategy;

    /** The OIDCClientRegistrationResponseContext to populate metadata to. */
    @Nullable private OIDCClientRegistrationResponseContext oidcResponseCtx;

    /** The ClientRegistrationRequest to populate metadata from. */
    @Nullable private ClientRegistrationRequest request;
    
    /** Constructor. */
    public AbstractOIDCClientRegistrationResponseAction() {
        oidcResponseContextLookupStrategy = new ChildContextLookup<>(OIDCClientRegistrationResponseContext.class);
    }

    /**
     * Set the strategy used to locate the {@link OIDCClientRegistrationResponseContext} associated with a given
     * {@link MessageContext}.
     * 
     * @param strategy strategy used to locate the {@link OIDCClientRegistrationResponseContext} associated with a 
     *         given {@link MessageContext}
     */
    public void setOidcResponseContextLookupStrategy(
            @Nonnull final Function<MessageContext,OIDCClientRegistrationResponseContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        
        oidcResponseContextLookupStrategy = Constraint.isNotNull(strategy,
                "OIDCClientRegistrationResponseContext lookup strategy cannot be null");
    }
    
    /**
     * Get the OIDCClientRegistrationResponseContext to populate metadata to.
     * @return The OIDCClientRegistrationResponseContext to populate metadata to.
     */
    protected OIDCClientRegistrationResponseContext getOidcClientRegistrationResponseContext() {
        return oidcResponseCtx;
    }
    
    /**
     * Get the ClientRegistrationRequest to populate metadata from.
     * @return The ClientRegistrationRequest to populate metadata from.
     */
    protected ClientRegistrationRequest getOidcClientRegistrationRequest() {
        return request;
    }
    
    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        
        if (!super.doPreExecute(profileRequestContext)) {
            return false;
        }
        if (profileRequestContext.getInboundMessageContext() == null) {
            log.debug("{} No inbound message context associated with this profile request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;            
        }
        Object message = profileRequestContext.getInboundMessageContext().getMessage();
        if (message == null || !(message instanceof ClientRegistrationRequest)) {
            log.debug("{} No inbound message associated with this profile request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;                        
        }
        request = (ClientRegistrationRequest) message;

        if (profileRequestContext.getOutboundMessageContext() == null) {
            log.debug("{} No outbound message context associated with this profile request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;            
        }

        oidcResponseCtx = oidcResponseContextLookupStrategy.apply(profileRequestContext.getOutboundMessageContext());
        if (oidcResponseCtx == null) {
            log.debug("{} No OIDC client registration response context associated with this profile request", 
                    getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;            
        }

        return true;
    }

}
