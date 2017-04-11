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

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;

import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.IdPEventIds;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
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

    /** Constructor. */
    public InitializeRelyingPartyContext() {
        relyingPartyContextCreationStrategy = new ChildContextLookup<>(RelyingPartyContext.class, true);
    }

    /**
     * Set the strategy used to return or create the {@link RelyingPartyContext}
     * .
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

        log.debug("{} Attaching RelyingPartyContext for rp {}", getLogPrefix(), request.getClientID().getValue());
        //TODO: rpContext.setVerified(Check from metadata client exists);
        rpContext.setRelyingPartyId(request.getClientID().getValue());
    }

}