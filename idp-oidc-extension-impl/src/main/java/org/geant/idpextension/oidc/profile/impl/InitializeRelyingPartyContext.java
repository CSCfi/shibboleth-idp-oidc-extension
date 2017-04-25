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

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.profile.context.navigate.InboundMessageContextLookup;

import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.IdPEventIds;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.google.common.base.Functions;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;

/**
 * Action that adds a {@link RelyingPartyContext} to the current
 * {@link ProfileRequestContext} tree via a creation function.
 * 
 * @event {@link EventIds#INVALID_MSG_CTX}
 * @event {@link EventIds#INVALID_PROFILE_CTX}
 * @event {@link IdPEventIds#INVALID_RELYING_PARTY_CTX}
 * @post ProfileRequestContext.getSubcontext(RelyingPartyContext.class) != null
 *       with relying party id set.
 */
@SuppressWarnings("rawtypes")
public class InitializeRelyingPartyContext extends AbstractProfileAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(InitializeRelyingPartyContext.class);

    /** OIDC Authentication request. */
    private AuthenticationRequest request;

    /** Strategy that will return or create a {@link RelyingPartyContext}. */
    @Nonnull
    private Function<ProfileRequestContext, RelyingPartyContext> relyingPartyContextCreationStrategy;
    
    /** Strategy that will return {@link OIDCMetadataContext}. */
    @Nonnull
    private Function<ProfileRequestContext, OIDCMetadataContext> oidcMetadataContextLookupStrategy;

    /** Constructor. */
    public InitializeRelyingPartyContext() {
        relyingPartyContextCreationStrategy = new ChildContextLookup<>(RelyingPartyContext.class, true);
        oidcMetadataContextLookupStrategy = Functions.compose(
                new ChildContextLookup<>(OIDCMetadataContext.class), new InboundMessageContextLookup());
    }

    /**
     * Set the strategy used to return or create the {@link RelyingPartyContext}.
     * 
     * @param strategy
     *            creation strategy
     */
    public void setRelyingPartyContextCreationStrategy(
            @Nonnull final Function<ProfileRequestContext, RelyingPartyContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        relyingPartyContextCreationStrategy = Constraint.isNotNull(strategy,
                "RelyingPartyContext creation strategy cannot be null");
    }
    
    /**
     * Set the strategy used to return the {@link OIDCMetadataContext}.
     * 
     * @param strategy The lookup strategy.
     */
    public void setOidcMetadataContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, OIDCMetadataContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        oidcMetadataContextLookupStrategy = Constraint.isNotNull(strategy, 
                "OIDCMetadataContext lookup strategy cannot be null");
    }

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

        final RelyingPartyContext rpContext = relyingPartyContextCreationStrategy.apply(profileRequestContext);
        if (rpContext == null) {
            log.debug("{} Unable to locate or create RelyingPartyContext", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_RELYING_PARTY_CTX);
            return;
        }

        final ClientID clientId = request.getClientID();
        log.debug("{} Attaching RelyingPartyContext for rp {}", getLogPrefix(), clientId.getValue());
        rpContext.setRelyingPartyId(clientId.getValue());
        final OIDCMetadataContext oidcContext = oidcMetadataContextLookupStrategy.apply(profileRequestContext);
        if (oidcContext != null && oidcContext.getClientInformation() != null 
                && clientId.equals(oidcContext.getClientInformation().getID())) {
            log.debug("{} Setting the rp context verified", getLogPrefix());
            rpContext.setVerified(true);
        }
    }

}