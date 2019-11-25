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

import java.util.Date;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.geant.idpextension.oidc.messaging.context.OIDCClientRegistrationResponseContext;
import org.geant.idpextension.oidc.metadata.resolver.ClientInformationManager;
import org.geant.idpextension.oidc.metadata.resolver.ClientInformationManagerException;
import org.joda.time.DateTime;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformationResponse;

import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.utilities.java.support.annotation.Duration;
import net.shibboleth.utilities.java.support.annotation.constraint.NonNegative;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * An action that stores the {@link ClientInformation} from the {@link OIDCClientRegistrationResponseContext} to the
 * associated {@link StorageService}.
 */
@SuppressWarnings("rawtypes")
public class StoreClientInformation extends AbstractProfileAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(StoreClientInformation.class);
    
    /** The client information manager used for storing the information. */
    private ClientInformationManager clientInformationManager;
    
    /** Strategy to obtain registration validity period policy. */
    @Nullable private Function<ProfileRequestContext,Long> registrationValidityPeriodStrategy;
    
    /** Default validity period for registration. */
    @Duration @NonNegative private long defaultRegistrationValidityPeriod;
    
    /** The response message. */
    private OIDCClientInformationResponse response;
    
    /**
     * Strategy used to locate the {@link OIDCClientRegistrationResponseContext} associated with a given 
     * {@link MessageContext}.
     */
    @Nonnull private Function<MessageContext,OIDCClientRegistrationResponseContext> oidcResponseContextLookupStrategy;

    /** Constructor. */
    public StoreClientInformation() {
        super();
        oidcResponseContextLookupStrategy = new ChildContextLookup<>(OIDCClientRegistrationResponseContext.class);
        defaultRegistrationValidityPeriod = 24 * 60 * 60 * 1000;
    }
    
    /**
     * Set strategy function to obtain registration validity period.
     * 
     * @param strategy The strategy function.
     */
    public void setRegistrationValidityPeriodStrategy(@Nullable final Function<ProfileRequestContext,Long> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        
        registrationValidityPeriodStrategy = strategy;
    }
    
    /**
     * Set the default registration validity period in milliseconds.
     * 
     * @param lifetime The default validity period in milliseconds.
     */
    @Duration public void setDefaultRegistrationValidityPeriod(@Duration @NonNegative final long lifetime) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        
        defaultRegistrationValidityPeriod = Constraint.isGreaterThanOrEqual(0, lifetime,
                "Default registration validity period must be greater than or equal to 0");
    }
    
    /**
     * Get the client information manager used for storing the information.
     * @return The client information manager used for storing the information.
     */
    public ClientInformationManager getClientInformationManager() {
        return clientInformationManager;
    }
    
    /**
     * Set the client information manager used for storing the information.
     * @param manager The client information manager used for storing the information.
     */
    public void setClientInformationManager(final ClientInformationManager manager) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        clientInformationManager = Constraint.isNotNull(manager, "The client information manager cannot be null!");
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

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        if (!super.doPreExecute(profileRequestContext)) {
            log.error("{} pre-execute failed", getLogPrefix());
            return false;
        }
        if (profileRequestContext.getOutboundMessageContext() == null) {
            log.error("{} Unable to locate outbound message context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;
        }
        Object message = profileRequestContext.getOutboundMessageContext().getMessage();

        if (message == null || !(message instanceof OIDCClientInformationResponse)) {
            log.error("{} Unable to locate outbound message", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;
        }
        response = (OIDCClientInformationResponse) message;
        return true;
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        final OIDCClientInformation clientInformation = response.getOIDCClientInformation();
        final Long lifetime = registrationValidityPeriodStrategy != null ?
                registrationValidityPeriodStrategy.apply(profileRequestContext) : null;
        if (lifetime == null) {
            log.debug("{} No registration validity period supplied, using default", getLogPrefix());
        }
        final DateTime expiration = new DateTime(new Date()).plus(
                lifetime != null ? lifetime : defaultRegistrationValidityPeriod);
        
        try {
            if (lifetime == 0) {
                log.debug("{} Registration won't expire, validity set to 0", getLogPrefix());
                clientInformationManager.storeClientInformation(clientInformation, null);
            } else {
                log.debug("{} Registration will expire on {}", getLogPrefix(), expiration);
                clientInformationManager.storeClientInformation(clientInformation, expiration.getMillis());                
            }
        } catch (ClientInformationManagerException e) {
            log.error("{} Could not store the client information", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, EventIds.IO_ERROR);
            return;
        }
        log.info("{} Client information successfully stored for {}", getLogPrefix(), 
                clientInformation.getID().getValue());
        
    }    
}