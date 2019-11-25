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

import org.geant.idpextension.oidc.messaging.context.OIDCClientRegistrationResponseContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformationResponse;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Action that adds an outbound {@link MessageContext} and related OIDC context
 * to the {@link ProfileRequestContext}. The {@link OIDCClientRegistrationResponseContext} is also initialized to
 * contain empty {@link OIDCClientMetadata}.
 * 
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 */
@SuppressWarnings("rawtypes")
public class InitializeOutboundRegistrationResponseMessageContext extends AbstractProfileAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(InitializeOutboundRegistrationResponseMessageContext.class);
    
    /** Strategy that will return or create a {@link OIDCClientRegistrationResponseContext}. */
    @Nonnull
    private Function<MessageContext, OIDCClientRegistrationResponseContext> oidcResponseContextCreationStrategy;

    /** Constructor. */
    public InitializeOutboundRegistrationResponseMessageContext() {
        super();
        oidcResponseContextCreationStrategy = 
                new ChildContextLookup<>(OIDCClientRegistrationResponseContext.class, true);
    }

    /**
     * Set the strategy used to return or create the {@link OIDCClientRegistrationResponseContext}
     * .
     * @param strategy
     *            creation strategy
     */
    public void setRelyingPartyContextCreationStrategy(
            @Nonnull final Function<MessageContext, OIDCClientRegistrationResponseContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        oidcResponseContextCreationStrategy = Constraint.isNotNull(strategy,
                "OIDCClientRegistrationResponseContext creation strategy cannot be null");
    }

    
    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        final MessageContext<OIDCClientInformationResponse> msgCtx = 
                new MessageContext<OIDCClientInformationResponse>();
        final OIDCClientRegistrationResponseContext oidcResponseCtx = 
                oidcResponseContextCreationStrategy.apply(msgCtx);
        oidcResponseCtx.setClientMetadata(new OIDCClientMetadata());
        profileRequestContext.setOutboundMessageContext(msgCtx);
        log.debug("{} Initialized outbound message context", getLogPrefix());
    }
}