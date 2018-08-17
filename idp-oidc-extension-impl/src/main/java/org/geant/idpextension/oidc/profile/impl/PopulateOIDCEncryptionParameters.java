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

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.saml2.profile.context.EncryptionContext;
import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.EncryptionParameters;
import org.opensaml.xmlsec.EncryptionParametersResolver;
import org.opensaml.xmlsec.SecurityConfigurationSupport;
import org.opensaml.xmlsec.criterion.EncryptionConfigurationCriterion;
import org.opensaml.xmlsec.criterion.EncryptionOptionalCriterion;

import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

import org.geant.idpextension.oidc.criterion.ClientInformationCriterion;
import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.geant.idpextension.oidc.profile.context.navigate.DefaultOIDCMetadataContextLookupFunction;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.google.common.base.Functions;

/**
 * Action that resolves and populates {@link EncryptionParameters} on an {@link EncryptionContext} created/accessed via
 * a lookup function, by default on a {@link RelyingPartyContext} child of the profile request context.
 * 
 * <p>
 * The resolution process is contingent on the active profile configuration requesting encryption of some kind, and an
 * {@link EncryptionContext} is also created to capture these requirements.
 * </p>
 * 
 * <p>
 * The OpenSAML default, per-RelyingParty, and default per-profile {@link EncryptionConfiguration} objects are input to
 * the resolution process, along with the relying party's oidc client registration data, which in most cases will be the
 * source of the eventual encryption key.
 * </p>
 * 
 */
@SuppressWarnings("rawtypes")
public class PopulateOIDCEncryptionParameters extends AbstractProfileAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(PopulateOIDCEncryptionParameters.class);

    /** Strategy used to look up the {@link EncryptionContext} to store parameters in. */
    @Nonnull
    private Function<ProfileRequestContext, EncryptionContext> encryptionContextLookupStrategy;

    /** Strategy used to look up a per-request {@link EncryptionConfiguration} list. */
    @NonnullAfterInit
    private Function<ProfileRequestContext, List<EncryptionConfiguration>> configurationLookupStrategy;

    /** Resolver for parameters to store into context. */
    @NonnullAfterInit
    private EncryptionParametersResolver encParamsresolver;

    /** Active configurations to feed into resolver. */
    @Nullable
    @NonnullElements
    private List<EncryptionConfiguration> encryptionConfigurations;

    /** Strategy used to look up a OIDC metadata context. */
    @Nullable
    private Function<ProfileRequestContext, OIDCMetadataContext> oidcMetadataContextLookupStrategy;

    /** Constructor. */
    public PopulateOIDCEncryptionParameters() {
        // Create context by default.
        oidcMetadataContextLookupStrategy = new DefaultOIDCMetadataContextLookupFunction();
        encryptionContextLookupStrategy = Functions.compose(new ChildContextLookup<>(EncryptionContext.class, true),
                new ChildContextLookup<ProfileRequestContext, RelyingPartyContext>(RelyingPartyContext.class));
    }

    /**
     * Set the strategy used to look up the {@link EncryptionContext} to set the flags for.
     * 
     * @param strategy lookup strategy
     */
    public void setEncryptionContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, EncryptionContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        encryptionContextLookupStrategy =
                Constraint.isNotNull(strategy, "EncryptionContext lookup strategy cannot be null");
    }

    /**
     * Set the strategy used to look up the {@link OIDCMetadataContext} to locate client registered encryption
     * parameters.
     * 
     * @param strategy lookup strategy
     */
    public void setOIDCMetadataContextContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, OIDCMetadataContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        oidcMetadataContextLookupStrategy =
                Constraint.isNotNull(strategy, " OIDCMetadataContext lookup strategy cannot be null");
    }

    /**
     * Set the strategy used to look up a per-request {@link EncryptionConfiguration} list.
     * 
     * @param strategy lookup strategy
     */
    public void setConfigurationLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, List<EncryptionConfiguration>> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        configurationLookupStrategy =
                Constraint.isNotNull(strategy, "EncryptionConfiguration lookup strategy cannot be null");
    }

    /**
     * Set the encParamsresolver to use for the parameters to store into the context.
     * 
     * @param newResolver encParamsresolver to use
     */
    public void setEncryptionParametersResolver(@Nonnull final EncryptionParametersResolver newResolver) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        encParamsresolver = Constraint.isNotNull(newResolver, "EncryptionParametersResolver cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();

        if (encParamsresolver == null) {
            throw new ComponentInitializationException("EncryptionParametersResolver cannot be null");
        } else if (configurationLookupStrategy == null) {
            configurationLookupStrategy = new Function<ProfileRequestContext, List<EncryptionConfiguration>>() {
                public List<EncryptionConfiguration> apply(final ProfileRequestContext input) {
                    return Collections.singletonList(SecurityConfigurationSupport.getGlobalEncryptionConfiguration());
                }
            };
        }
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        log.debug("{} Resolving EncryptionParameters for request", getLogPrefix());
        final EncryptionContext encryptCtx = encryptionContextLookupStrategy.apply(profileRequestContext);
        if (encryptCtx == null) {
            log.debug("{} No EncryptionContext returned by lookup strategy", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return;
        }
        try {
            encryptionConfigurations = configurationLookupStrategy.apply(profileRequestContext);
            if (encryptionConfigurations == null || encryptionConfigurations.isEmpty()) {
                throw new ResolverException("No EncryptionConfigurations returned by lookup strategy");
            }
            CriteriaSet criteria = buildCriteriaSet(profileRequestContext);
            final EncryptionParameters params = encParamsresolver.resolveSingle(criteria);
            log.debug("{} {} EncryptionParameters", getLogPrefix(), params != null ? "Resolved" : "Failed to resolve");
            if (params != null) {
                encryptCtx.setAssertionEncryptionParameters(params);
                return;
            }
            final EncryptionOptionalCriterion encryptionOptionalCrit = criteria.get(EncryptionOptionalCriterion.class);
            if (encryptionOptionalCrit != null) {
                if (encryptionOptionalCrit.isEncryptionOptional()) {
                    log.debug("{} Encryption optional", getLogPrefix());
                    return;
                }
            }
        } catch (final ResolverException e) {
            log.error("{} Error resolving EncryptionParameters", getLogPrefix(), e);
        }
        ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_SEC_CFG);
    }

    /**
     * Build the criteria used as input to the {@link EncryptionParametersResolver}.
     * 
     * @param profileRequestContext current profile request context
     * 
     * @return the criteria set to use
     */
    @Nonnull
    private CriteriaSet buildCriteriaSet(@Nonnull final ProfileRequestContext profileRequestContext) {

        final CriteriaSet criteria = new CriteriaSet(new EncryptionConfigurationCriterion(encryptionConfigurations));
        if (oidcMetadataContextLookupStrategy != null) {
            final OIDCMetadataContext oidcMetadataCtx = oidcMetadataContextLookupStrategy.apply(profileRequestContext);
            if (oidcMetadataCtx != null && oidcMetadataCtx.getClientInformation() != null) {
                log.debug(
                        "{} Adding oidc client information to resolution criteria for key transport / encryption algorithms",
                        getLogPrefix());
                criteria.add(new ClientInformationCriterion(oidcMetadataCtx.getClientInformation()));
            } else {
                log.debug("{} oidcMetadataCtx is null", getLogPrefix());
            }
        } else {
            log.debug("{} oidcMetadataContextLookupStrategy is null", getLogPrefix());
        }
        return criteria;
    }

}