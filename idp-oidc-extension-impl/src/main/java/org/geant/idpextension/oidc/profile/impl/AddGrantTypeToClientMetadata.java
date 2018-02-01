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

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.annotation.Nonnull;

import org.geant.idpextension.oidc.config.logic.AuthorizationCodeFlowEnabledPredicate;
import org.geant.idpextension.oidc.config.logic.ImplicitFlowEnabledPredicate;
import org.geant.idpextension.oidc.config.logic.RefreshTokensEnabledPredicate;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Predicate;
import com.nimbusds.oauth2.sdk.GrantType;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * An action that adds the grant_type to the client metadata.
 * 
 * The possible values defined in https://openid.net/specs/openid-connect-registration-1_0.html are:
 * <ul>
 * <li>authorization_code: The Authorization Code Grant Type described in OAuth 2.0 Section 4.1.</li>
 * <li>implicit: The Implicit Grant Type described in OAuth 2.0 Section 4.2.</li>
 * <li>refresh_token: The Refresh Token Grant Type described in OAuth 2.0 Section 6.</li>
 * </ul>
 */
@SuppressWarnings("rawtypes")
public class AddGrantTypeToClientMetadata extends AbstractOIDCClientMetadataPopulationAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(AddGrantTypeToClientMetadata.class);
    
    /** Predicate used to indicate whether authorization code flow is enabled. */
    @Nonnull private Predicate<ProfileRequestContext> authorizationCodeFlowPredicate;
    
    /** Predicate used to indicate whether implicit flow is enabled. */
    @Nonnull private Predicate<ProfileRequestContext> implicitFlowPredicate;
    
    /** Predicate used to indicate whether refresh tokens are enabled. */
    @Nonnull private Predicate<ProfileRequestContext> refreshTokensPredicate;
    
    /** Map of supported grant types and their corresponding predicates. */
    @Nonnull private Map<GrantType, Predicate<ProfileRequestContext>> supportedGrantTypes;
    
    /**
     * Constructor.
     */
    public AddGrantTypeToClientMetadata() {
        authorizationCodeFlowPredicate = new AuthorizationCodeFlowEnabledPredicate();
        implicitFlowPredicate = new ImplicitFlowEnabledPredicate();
        refreshTokensPredicate = new RefreshTokensEnabledPredicate();
    }
    
    /** {@inheritDoc} */
    protected void doInitialize() throws ComponentInitializationException {
        supportedGrantTypes = new HashMap<>();
        supportedGrantTypes.put(GrantType.AUTHORIZATION_CODE, authorizationCodeFlowPredicate);
        supportedGrantTypes.put(GrantType.IMPLICIT, implicitFlowPredicate);
        supportedGrantTypes.put(GrantType.REFRESH_TOKEN, refreshTokensPredicate);        
    }
    
    /**
     * Get predicate used to indicate whether authorization code flow is enabled.
     * @return Predicate used to indicate whether authorization code flow is enabled.
     */
    public Predicate<ProfileRequestContext> getAuthorizationCodeFlowEnabled() {
        return authorizationCodeFlowPredicate;
    }
    
    /**
     * Set predicate used to indicate whether authorization code flow is enabled.
     * @param predicate What to set.
     */
    public void setAuthorizationCodeFlowEnabled(final Predicate<ProfileRequestContext> predicate) {
        authorizationCodeFlowPredicate = Constraint.isNotNull(predicate, 
                "Predicate used to indicate whether authorization code flow is supported cannot be null");
    }

    /**
     * Get predicate used to indicate whether hybrid flow is enabled.
     * @return Predicate used to indicate whether hybrid flow is enabled.
     */
    public Predicate<ProfileRequestContext> getImplicitFlowEnabled() {
        return implicitFlowPredicate;
    }
    
    /**
     * Set predicate used to indicate whether hybrid flow is enabled.
     * @param predicate What to set.
     */
    public void setImplicitFlowEnabled(final Predicate<ProfileRequestContext> predicate) {
        implicitFlowPredicate = Constraint.isNotNull(predicate, 
                "Predicate used to indicate whether hybrid flow is supported cannot be null");
    }
    
    /**
     * Get predicate used to indicate whether refresh tokens are enabled.
     * @return Predicate used to indicate whether refresh tokens are enabled.
     */
    public Predicate<ProfileRequestContext> getRefreshTokensEnabled() {
        return refreshTokensPredicate;
    }
    
    /**
     * Set predicate used to indicate whether refresh tokens are enabled.
     * @param predicate What to set.
     */
    public void setRefreshTokensEnabled(final Predicate<ProfileRequestContext> predicate) {
        refreshTokensPredicate = Constraint.isNotNull(predicate, 
                "Predicate used to indicate whether refresh tokens are supported cannot be null");
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        final Set<GrantType> grantTypes = getInputMetadata().getGrantTypes();
        log.trace("{} Requested grant types: {}", getLogPrefix(), grantTypes);
        final Set<GrantType> resultTypes = new HashSet<>();
        if (grantTypes == null || grantTypes.isEmpty()) {
            log.debug("{} No requested grant types, adding the default set", getLogPrefix());
            for (final GrantType grantType : supportedGrantTypes.keySet()) {
                addGrantTypeIfEnabled(resultTypes, grantType, supportedGrantTypes.get(grantType), 
                        profileRequestContext);
            }
        } else {
            for (final GrantType grantType : grantTypes) {
                if (supportedGrantTypes.keySet().contains(grantType)) {
                    addGrantTypeIfEnabled(resultTypes, grantType, supportedGrantTypes.get(grantType), 
                            profileRequestContext);
                } else {
                    log.warn("{} Ignoring unsupported requested grant type {}", getLogPrefix(), grantType);
                }
            }
        }
        getOutputMetadata().setGrantTypes(resultTypes);
    }
    
    /**
     * Adds a given grant type to the given set of grant types, if the given predicate is true.
     * @param resultTypes The result set where the grant type is potentially added.
     * @param grantType The grant type to check.
     * @param predicate The predicate used for checking.
     * @param profileRequestContext The profile context used as an input for the predicate.
     */
    protected void addGrantTypeIfEnabled(final Set<GrantType> resultTypes, final GrantType grantType, 
            final Predicate<ProfileRequestContext> predicate, final ProfileRequestContext profileRequestContext) {
        if (predicate.apply(profileRequestContext)) {
            log.debug("{} Adding {} to the list of enabled types", getLogPrefix(), grantType);
            resultTypes.add(grantType);
        } else {
            log.debug("{} Grant type {} is not enabled", getLogPrefix(), grantType);
        }
    }
}
