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
import org.opensaml.profile.context.navigate.InboundMessageContextLookup;

import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.IdPEventIds;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.geant.idpextension.oidc.profile.context.navigate.DefaultClientIDLookupFunction;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Function;
import com.google.common.base.Functions;
import com.nimbusds.oauth2.sdk.id.ClientID;

/**
 * Action that adds a {@link RelyingPartyContext} to the current {@link ProfileRequestContext} tree via a creation
 * function.
 * 
 * @event {@link EventIds#INVALID_MSG_CTX}
 * @event {@link EventIds#INVALID_PROFILE_CTX}
 * @event {@link IdPEventIds#INVALID_RELYING_PARTY_CTX}
 * @post ProfileRequestContext.getSubcontext(RelyingPartyContext.class) != null with relying party id set.
 */
@SuppressWarnings("rawtypes")
public class InitializeRelyingPartyContext extends AbstractProfileAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(InitializeRelyingPartyContext.class);

    /** OIDC client id. */
    private ClientID clientId;

    /** Strategy that will return or create a {@link RelyingPartyContext}. */
    @Nonnull
    private Function<ProfileRequestContext, RelyingPartyContext> relyingPartyContextCreationStrategy;

    /** Strategy that will return {@link OIDCMetadataContext}. */
    @Nonnull
    private Function<ProfileRequestContext, OIDCMetadataContext> oidcMetadataContextLookupStrategy;

    /** Strategy used to obtain the client id value for authorize/token request. */
    @Nonnull
    private Function<MessageContext, ClientID> clientIDLookupStrategy;

    /** Constructor. */
    public InitializeRelyingPartyContext() {
        relyingPartyContextCreationStrategy = new ChildContextLookup<>(RelyingPartyContext.class, true);
        oidcMetadataContextLookupStrategy = Functions.compose(new ChildContextLookup<>(OIDCMetadataContext.class),
                new InboundMessageContextLookup());
        clientIDLookupStrategy = new DefaultClientIDLookupFunction();
    }

    /**
     * Set the strategy used to locate the client id of the request.
     * 
     * @param strategy lookup strategy
     */
    public void setClientIDLookupStrategy(@Nonnull final Function<MessageContext, ClientID> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        clientIDLookupStrategy =
                Constraint.isNotNull(strategy, "ClientIDLookupStrategy lookup strategy cannot be null");
    }

    /**
     * Set the strategy used to return or create the {@link RelyingPartyContext} .
     * 
     * @param strategy creation strategy
     */
    public void setRelyingPartyContextCreationStrategy(
            @Nonnull final Function<ProfileRequestContext, RelyingPartyContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        relyingPartyContextCreationStrategy =
                Constraint.isNotNull(strategy, "RelyingPartyContext creation strategy cannot be null");
    }

    /**
     * Set the strategy used to return the {@link OIDCMetadataContext}.
     * 
     * @param strategy The lookup strategy.
     */
    public void setOidcMetadataContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, OIDCMetadataContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        oidcMetadataContextLookupStrategy =
                Constraint.isNotNull(strategy, "OIDCMetadataContext lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        if (!super.doPreExecute(profileRequestContext)) {
            log.error("{} pre-execute failed", getLogPrefix());
            return false;
        }
        clientId = clientIDLookupStrategy.apply(profileRequestContext.getInboundMessageContext());
        if (clientId == null) {
            log.error("{} Unable to locate client id from the request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;
        }
        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        final RelyingPartyContext rpContext = relyingPartyContextCreationStrategy.apply(profileRequestContext);
        if (rpContext == null) {
            log.error("{} Unable to locate or create RelyingPartyContext", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_RELYING_PARTY_CTX);
            return;
        }
        log.debug("Attaching RelyingPartyContext for rp {}", clientId.getValue());
        rpContext.setRelyingPartyId(clientId.getValue());
        final OIDCMetadataContext oidcContext = oidcMetadataContextLookupStrategy.apply(profileRequestContext);
        if (oidcContext != null && oidcContext.getClientInformation() != null
                && clientId.equals(oidcContext.getClientInformation().getID())) {
            log.debug("{} Setting the rp context verified", getLogPrefix());
            rpContext.setVerified(true);
        }
    }

}