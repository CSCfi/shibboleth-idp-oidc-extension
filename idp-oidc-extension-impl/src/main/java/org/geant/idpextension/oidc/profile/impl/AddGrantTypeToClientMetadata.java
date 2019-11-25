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

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.annotation.Nonnull;

import org.geant.idpextension.oidc.config.logic.AuthorizationCodeFlowEnabledPredicate;
import org.geant.idpextension.oidc.config.logic.ImplicitFlowEnabledPredicate;
import org.geant.idpextension.oidc.config.logic.RefreshTokensEnabledPredicate;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
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
            if (resultTypes.isEmpty()) {
                log.error("{} No supported grant types requested", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
                return;
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
