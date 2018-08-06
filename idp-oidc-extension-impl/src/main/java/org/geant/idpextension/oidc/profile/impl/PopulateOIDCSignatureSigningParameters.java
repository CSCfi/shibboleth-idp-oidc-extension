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

import java.util.Collections;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.AbstractHandlerDelegatingProfileAction;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.profile.context.navigate.OutboundMessageContextLookup;
import org.opensaml.saml.common.messaging.context.SAMLMetadataContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.xmlsec.SecurityConfigurationSupport;
import org.opensaml.xmlsec.SignatureSigningConfiguration;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.SignatureSigningParametersResolver;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.google.common.base.Functions;

import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Action that resolves and populates {@link SignatureSigningParameters} on a {@link SecurityParametersContext}
 * created/accessed via a lookup function, by default on the outbound message context.
 * 
 * @event {@link EventIds#PROCEED_EVENT_ID}
 * @event {@link EventIds#INVALID_MSG_CTX}
 * @event {@link EventIds#INVALID_SEC_CFG}
 * 
 *        * Based purely on {@link PopulateSignatureSigningParameters}.
 */
@SuppressWarnings("rawtypes")
public class PopulateOIDCSignatureSigningParameters
        extends AbstractHandlerDelegatingProfileAction<PopulateOIDCSignatureSigningParametersHandler> {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(PopulateOIDCSignatureSigningParameters.class);

    /** Strategy used to look up the {@link SecurityParametersContext} to set the parameters for. */

    @Nonnull
    private Function<ProfileRequestContext, SecurityParametersContext> securityParametersContextLookupStrategy;

    /** Strategy used to look up an existing {@link SecurityParametersContext} to copy. */
    @Nullable
    private Function<ProfileRequestContext, SecurityParametersContext> existingParametersContextLookupStrategy;

    /** Strategy used to look up a per-request {@link SignatureSigningConfiguration} list. */
    @NonnullAfterInit
    private Function<ProfileRequestContext, List<SignatureSigningConfiguration>> configurationLookupStrategy;

    /** Strategy used to look up a SAML metadata context. */
    @Nullable
    private Function<ProfileRequestContext, SAMLMetadataContext> metadataContextLookupStrategy;

    /** Resolver for parameters to store into context. */
    @NonnullAfterInit
    private SignatureSigningParametersResolver resolver;

    /** Whether failure to resolve parameters should be raised as an error. */
    private boolean noResultIsError;

    /**
     * Constructor.
     */
    public PopulateOIDCSignatureSigningParameters() {
        super(PopulateOIDCSignatureSigningParametersHandler.class, new OutboundMessageContextLookup());

        // Create context by default.
        securityParametersContextLookupStrategy = Functions.compose(
                new ChildContextLookup<>(SecurityParametersContext.class, true), new OutboundMessageContextLookup());

        // Default: outbound msg context -> SAMLPeerEntityContext -> SAMLMetadataContext
        metadataContextLookupStrategy = Functions.compose(new ChildContextLookup<>(SAMLMetadataContext.class), Functions
                .compose(new ChildContextLookup<>(SAMLPeerEntityContext.class), new OutboundMessageContextLookup()));

        setErrorEvent(EventIds.INVALID_SEC_CFG);
    }

    /**
     * Set the strategy used to look up the {@link SecurityParametersContext} to set the parameters for.
     * 
     * @param strategy lookup strategy
     */
    public void setSecurityParametersContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, SecurityParametersContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        securityParametersContextLookupStrategy =
                Constraint.isNotNull(strategy, "SecurityParametersContext lookup strategy cannot be null");
    }

    /**
     * Set the strategy used to look up an existing {@link SecurityParametersContext} to copy instead of actually
     * resolving the parameters to set.
     * 
     * @param strategy lookup strategy
     */
    public void setExistingParametersContextLookupStrategy(
            @Nullable final Function<ProfileRequestContext, SecurityParametersContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        existingParametersContextLookupStrategy = strategy;
    }

    /**
     * Set lookup strategy for {@link SAMLMetadataContext} for input to resolution.
     * 
     * @param strategy lookup strategy
     */
    public void setMetadataContextLookupStrategy(
            @Nullable final Function<ProfileRequestContext, SAMLMetadataContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        metadataContextLookupStrategy = strategy;
    }

    /**
     * Set the strategy used to look up a per-request {@link SignatureSigningConfiguration} list.
     * 
     * @param strategy lookup strategy
     */
    public void setConfigurationLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, List<SignatureSigningConfiguration>> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        configurationLookupStrategy =
                Constraint.isNotNull(strategy, "SignatureSigningConfiguration lookup strategy cannot be null");
    }

    /**
     * Set the resolver to use for the parameters to store into the context.
     * 
     * @param newResolver resolver to use
     */
    public void setSignatureSigningParametersResolver(@Nonnull final SignatureSigningParametersResolver newResolver) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        resolver = Constraint.isNotNull(newResolver, "SignatureSigningParametersResolver cannot be null");
    }

    /**
     * Set whether a failure to resolve any parameters should be raised as an exception.
     * 
     * <p>
     * Defaults to false.
     * </p>
     * 
     * @param flag flag to set
     * 
     * @since 3.4.0
     */
    public void setNoResultIsError(final boolean flag) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        noResultIsError = flag;
    }

    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();

        if (resolver == null) {
            throw new ComponentInitializationException("SignatureSigningParametersResolver cannot be null");
        } else if (configurationLookupStrategy == null) {
            configurationLookupStrategy = new Function<ProfileRequestContext, List<SignatureSigningConfiguration>>() {
                public List<SignatureSigningConfiguration> apply(final ProfileRequestContext input) {
                    return Collections
                            .singletonList(SecurityConfigurationSupport.getGlobalSignatureSigningConfiguration());
                }
            };
        }

        final PopulateOIDCSignatureSigningParametersHandler delegate = getDelegate();
        delegate.setNoResultIsError(noResultIsError);
        delegate.setSignatureSigningParametersResolver(resolver);
        delegate.setConfigurationLookupStrategy(adapt(configurationLookupStrategy));
        delegate.setSecurityParametersContextLookupStrategy(adapt(securityParametersContextLookupStrategy));
        delegate.setExistingParametersContextLookupStrategy(adapt(existingParametersContextLookupStrategy));
        delegate.setMetadataContextLookupStrategy(adapt(metadataContextLookupStrategy));
        delegate.initialize();
    }

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        if (super.doPreExecute(profileRequestContext)) {
            log.debug("{} Signing enabled", getLogPrefix());
            return true;
        } else {
            log.debug("{} Signing not enabled", getLogPrefix());
            return false;
        }
    }

}
