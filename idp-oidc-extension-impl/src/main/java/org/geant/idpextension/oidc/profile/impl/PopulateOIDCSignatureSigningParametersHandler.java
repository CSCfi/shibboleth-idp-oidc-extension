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

import org.geant.idpextension.oidc.criterion.ClientInformationCriterion;
import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.geant.idpextension.oidc.profile.context.navigate.DefaultOIDCMetadataContextLookupFunction;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.messaging.context.navigate.ParentContextLookup;
import org.opensaml.messaging.handler.AbstractMessageHandler;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.common.messaging.context.SAMLMetadataContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.criterion.RoleDescriptorCriterion;
import org.opensaml.xmlsec.SecurityConfigurationSupport;
import org.opensaml.xmlsec.SignatureSigningConfiguration;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.SignatureSigningParametersResolver;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.criterion.SignatureSigningConfigurationCriterion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.google.common.base.Functions;

import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * 
 * Handler that resolves and populates {@link SignatureSigningParameters} on a {@link SecurityParametersContext}
 * created/accessed via a lookup function, by default as an immediate child context of the target
 * {@link MessageContext}.
 * 
 * Based on {@link PopulateSignatureSigningParametersHandler} The only addition is to add OIDCClientInformation as
 * criterion and methods related to that.
 */
@SuppressWarnings("rawtypes")
public class PopulateOIDCSignatureSigningParametersHandler extends AbstractMessageHandler {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(PopulateOIDCSignatureSigningParametersHandler.class);

    /** Strategy used to look up the {@link SecurityParametersContext} to set the parameters for. */
    @Nonnull
    private Function<MessageContext, SecurityParametersContext> securityParametersContextLookupStrategy;

    /** Strategy used to look up an existing {@link SecurityParametersContext} to copy. */
    @Nullable
    private Function<MessageContext, SecurityParametersContext> existingParametersContextLookupStrategy;

    /** Strategy used to look up a per-request {@link SignatureSigningConfiguration} list. */
    @NonnullAfterInit
    private Function<MessageContext, List<SignatureSigningConfiguration>> configurationLookupStrategy;

    /** Strategy used to look up a SAML metadata context. */
    @Nullable
    private Function<MessageContext, SAMLMetadataContext> metadataContextLookupStrategy;

    /** Resolver for parameters to store into context. */
    @NonnullAfterInit
    private SignatureSigningParametersResolver resolver;

    /** Whether failure to resolve parameters should be raised as an error. */
    private boolean noResultIsError;

    /** Strategy used to look up a OIDC metadata context. */
    @Nullable
    private Function<MessageContext, OIDCMetadataContext> oidcMetadataContextLookupStrategy;

    /**
     * Constructor.
     */
    public PopulateOIDCSignatureSigningParametersHandler() {
        // Create context by default.
        securityParametersContextLookupStrategy = new ChildContextLookup<>(SecurityParametersContext.class, true);

        oidcMetadataContextLookupStrategy = Functions.compose(new DefaultOIDCMetadataContextLookupFunction(),
                new ParentContextLookup<MessageContext, ProfileRequestContext>());

        // Default: msg context -> SAMLPeerEntityContext -> SAMLMetadataContext
        metadataContextLookupStrategy = Functions.compose(
                new ChildContextLookup<SAMLPeerEntityContext, SAMLMetadataContext>(SAMLMetadataContext.class),
                new ChildContextLookup<MessageContext, SAMLPeerEntityContext>(SAMLPeerEntityContext.class));
    }

    /**
     * Set the strategy used to look up the {@link SecurityParametersContext} to set the parameters for.
     * 
     * @param strategy lookup strategy
     */
    public void setSecurityParametersContextLookupStrategy(
            @Nonnull final Function<MessageContext, SecurityParametersContext> strategy) {
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
            @Nullable final Function<MessageContext, SecurityParametersContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        existingParametersContextLookupStrategy = strategy;
    }

    /**
     * Set lookup strategy for {@link SAMLMetadataContext} for input to resolution.
     * 
     * @param strategy lookup strategy
     */
    public void
            setMetadataContextLookupStrategy(@Nullable final Function<MessageContext, SAMLMetadataContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        metadataContextLookupStrategy = strategy;
    }

    /**
     * Set the strategy used to look up a per-request {@link SignatureSigningConfiguration} list.
     * 
     * @param strategy lookup strategy
     */
    public void setConfigurationLookupStrategy(
            @Nonnull final Function<MessageContext, List<SignatureSigningConfiguration>> strategy) {
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
            configurationLookupStrategy = new Function<MessageContext, List<SignatureSigningConfiguration>>() {
                public List<SignatureSigningConfiguration> apply(final MessageContext input) {
                    return Collections
                            .singletonList(SecurityConfigurationSupport.getGlobalSignatureSigningConfiguration());
                }
            };
        }
    }

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    @Override
    protected boolean doPreInvoke(@Nonnull final MessageContext messageContext) throws MessageHandlerException {

        if (super.doPreInvoke(messageContext)) {
            log.debug("{} Signing enabled", getLogPrefix());
            return true;
        } else {
            log.debug("{} Signing not enabled", getLogPrefix());
            return false;
        }
    }

    // Checkstyle: CyclomaticComplexity|ReturnCount OFF
    /** {@inheritDoc} */
    @Override
    protected void doInvoke(@Nonnull final MessageContext messageContext) throws MessageHandlerException {

        log.debug("{} Resolving SignatureSigningParameters for request", getLogPrefix());

        final SecurityParametersContext paramsCtx = securityParametersContextLookupStrategy.apply(messageContext);
        if (paramsCtx == null) {
            log.debug("{} No SecurityParametersContext returned by lookup strategy", getLogPrefix());
            throw new MessageHandlerException("No SecurityParametersContext returned by lookup strategy");
        }

        if (existingParametersContextLookupStrategy != null) {
            final SecurityParametersContext existingCtx = existingParametersContextLookupStrategy.apply(messageContext);
            if (existingCtx != null && existingCtx.getSignatureSigningParameters() != null) {
                log.debug("{} Found existing SecurityParametersContext to copy from", getLogPrefix());
                paramsCtx.setSignatureSigningParameters(existingCtx.getSignatureSigningParameters());
                return;
            }
        }

        final List<SignatureSigningConfiguration> configs = configurationLookupStrategy.apply(messageContext);
        if (configs == null || configs.isEmpty()) {
            log.error("{} No SignatureSigningConfiguration returned by lookup strategy", getLogPrefix());
            throw new MessageHandlerException("No SignatureSigningConfiguration returned by lookup strategy");
        }

        final CriteriaSet criteria = new CriteriaSet(new SignatureSigningConfigurationCriterion(configs));

        if (metadataContextLookupStrategy != null) {
            final SAMLMetadataContext metadataCtx = metadataContextLookupStrategy.apply(messageContext);
            if (metadataCtx != null && metadataCtx.getRoleDescriptor() != null) {
                log.debug("{} Adding metadata to resolution criteria for signing/digest algorithms", getLogPrefix());
                criteria.add(new RoleDescriptorCriterion(metadataCtx.getRoleDescriptor()));
            }
        }

        // The addition to {@link PopulateSignatureSigningParametersHandler}
        if (oidcMetadataContextLookupStrategy != null) {
            final OIDCMetadataContext oidcMetadataCtx = oidcMetadataContextLookupStrategy.apply(messageContext);
            if (oidcMetadataCtx != null && oidcMetadataCtx.getClientInformation() != null) {
                log.debug("{} Adding oidc client information to resolution criteria for signing/digest algorithms",
                        getLogPrefix());
                criteria.add(new ClientInformationCriterion(oidcMetadataCtx.getClientInformation()));
            } else {
                log.debug("{} oidcMetadataCtx is null", getLogPrefix());
            }
        } else {
            log.debug("{} oidcMetadataContextLookupStrategy is null", getLogPrefix());
        }

        try {
            final SignatureSigningParameters params = resolver.resolveSingle(criteria);
            if (params == null && noResultIsError) {
                log.error("Failed to resolve SignatureSigningParameters");
                throw new MessageHandlerException("Failed to resolve SignatureSigningParameters");
            }
            log.debug("{} {} SignatureSigningParameters", getLogPrefix(),
                    params != null ? "Resolved" : "Failed to resolve");
            paramsCtx.setSignatureSigningParameters(params);
        } catch (final ResolverException e) {
            log.error("{} Error resolving SignatureSigningParameters", getLogPrefix(), e);
            throw new MessageHandlerException("Error resolving SignatureSigningParameters", e);
        }
    }
    // Checkstyle: CyclomaticComplexity|ReturnCount ON

}