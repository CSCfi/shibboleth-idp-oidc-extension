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
import org.joda.time.DateTime;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;

import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.utilities.java.support.annotation.Duration;
import net.shibboleth.utilities.java.support.annotation.constraint.NonNegative;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.security.IdentifierGenerationStrategy;
import net.shibboleth.utilities.java.support.security.SecureRandomIdentifierGenerationStrategy;

/**
 * Creates a new client secret with the {@link IdentifierGenerationStrategy} attached to this action. The
 * client secret is included to the {@link OIDCClientRegistrationResponseContext} together with its validity period,
 * if defined.
 */
public class GenerateClientSecret extends AbstractProfileAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(GenerateClientSecret.class);

    /**
     * Strategy used to locate the {@link OIDCClientRegistrationResponseContext} associated with a given
     * {@link MessageContext}.
     */
    @Nonnull
    private Function<MessageContext, OIDCClientRegistrationResponseContext> oidcResponseContextLookupStrategy;

    /** The client secret generator to use. */
    @Nullable
    private IdentifierGenerationStrategy idGenerator;

    /** Strategy used to locate the {@link IdentifierGenerationStrategy} to use. */
    @Nonnull
    private Function<ProfileRequestContext, IdentifierGenerationStrategy> idGeneratorLookupStrategy;

    /** The OIDCClientRegistrationResponseContext to create the client secret to. */
    @Nullable
    private OIDCClientRegistrationResponseContext oidcResponseCtx;
    
    /** Strategy to obtain client secret validity period policy. */
    @Nullable private Function<ProfileRequestContext,Long> secretExpirationPeriodStrategy;
    
    /** Default validity period for client secret. */
    @Duration @NonNegative private long defaultSecretExpirationPeriod;

    /** Constructor. */
    public GenerateClientSecret() {
        oidcResponseContextLookupStrategy = new ChildContextLookup<>(OIDCClientRegistrationResponseContext.class);
        idGeneratorLookupStrategy = new Function<ProfileRequestContext, IdentifierGenerationStrategy>() {
            public IdentifierGenerationStrategy apply(ProfileRequestContext input) {
                return new SecureRandomIdentifierGenerationStrategy();
            }
        };
        defaultSecretExpirationPeriod = 365 * 24 * 60 * 60 * 1000;

    }
    
    /**
     * Set strategy to obtain client secret expiration period policy.
     * 
     * @param strategy What to set.
     */
    public void setSecretExpirationPeriodStrategy(@Nullable final Function<ProfileRequestContext,Long> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        
        secretExpirationPeriodStrategy = strategy;
    }
    
    /**
     * Set the default expiration period for client secret.
     * 
     * @param lifetime What to set.
     */
    @Duration public void setDefaultSecretExpirationPeriod(@Duration @NonNegative final long lifetime) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        
        defaultSecretExpirationPeriod = Constraint.isGreaterThanOrEqual(0, lifetime,
                "Default client secret expiration period must be greater than or equal to 0");
    }

    /**
     * Set the strategy used to locate the {@link OIDCClientRegistrationResponseContext} associated with a given
     * {@link MessageContext}.
     * 
     * @param strategy What to set.
     */
    public void setOidcResponseContextLookupStrategy(
            @Nonnull final Function<MessageContext, OIDCClientRegistrationResponseContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        oidcResponseContextLookupStrategy =
                Constraint.isNotNull(strategy, "OIDCClientRegistrationResponseContext lookup strategy cannot be null");
    }

    /**
     * Set the strategy used to locate the {@link IdentifierGenerationStrategy} to use.
     * 
     * @param strategy What to set.
     */
    public void setIdentifierGeneratorLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, IdentifierGenerationStrategy> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        idGeneratorLookupStrategy =
                Constraint.isNotNull(strategy, "IdentifierGenerationStrategy lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        if (!super.doPreExecute(profileRequestContext)) {
            return false;
        }

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
        
        idGenerator = idGeneratorLookupStrategy.apply(profileRequestContext);
        if (idGenerator == null) {
            log.debug("{} No identifier generation strategy", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }

        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        final Long lifetime = secretExpirationPeriodStrategy != null ?
                secretExpirationPeriodStrategy.apply(profileRequestContext) : null;
        if (lifetime == null) {
            log.debug("{} No secret expiration period supplied, using default", getLogPrefix());
        }
        final DateTime now = DateTime.now();
        final DateTime expiration = now.plus(lifetime != null ? lifetime : defaultSecretExpirationPeriod);

        final String clientSecret = idGenerator.generateIdentifier();
        oidcResponseCtx.setClientSecret(clientSecret);
        if (expiration.isAfter(now)) {
            oidcResponseCtx.setClientSecretExpiresAt(expiration);
            log.debug("{} Created a new client secret, expiring at {}", getLogPrefix(), expiration);
        } else {
            log.debug("{} Created a new client secret, non-expiring", getLogPrefix());
        }
    }
}
