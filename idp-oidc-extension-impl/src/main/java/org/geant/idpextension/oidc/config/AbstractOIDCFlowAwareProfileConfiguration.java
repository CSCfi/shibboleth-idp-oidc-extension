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

package org.geant.idpextension.oidc.config;

import javax.annotation.Nonnull;

import org.opensaml.profile.context.ProfileRequestContext;

import com.google.common.base.Predicate;
import com.google.common.base.Predicates;

import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Base class for OIDC protocol configuration, containing configuration bits shared by all flow aware OIDC protocol
 * configurations.
 */
@SuppressWarnings("rawtypes")
public abstract class AbstractOIDCFlowAwareProfileConfiguration
        extends AbstractOIDCClientAuthenticableProfileConfiguration {

    /** Predicate used to indicate whether authorization code flow is supported by this profile. Default true. */
    @Nonnull
    private Predicate<ProfileRequestContext> authorizationCodeFlowPredicate;

    /** Predicate used to indicate whether implicit flow is supported by this profile. Default true. */
    @Nonnull
    private Predicate<ProfileRequestContext> implicitFlowPredicate;

    /** Predicate used to indicate whether hybrid flow is supported by this profile. Default true. */
    @Nonnull
    private Predicate<ProfileRequestContext> hybridFlowPredicate;

    /** Predicate used to indicate whether refresh tokens are supported by this profile. Default true. */
    @Nonnull
    private Predicate<ProfileRequestContext> refreshTokensPredicate;

    /**
     * Constructor.
     *
     * @param profileId Unique profile identifier.
     */
    protected AbstractOIDCFlowAwareProfileConfiguration(final String profileId) {
        super(profileId);
        authorizationCodeFlowPredicate = Predicates.alwaysTrue();
        implicitFlowPredicate = Predicates.alwaysTrue();
        hybridFlowPredicate = Predicates.alwaysTrue();
        refreshTokensPredicate = Predicates.alwaysTrue();
    }

    /**
     * Get predicate used to indicate whether authorization code flow is supported by this profile.
     * 
     * @return Predicate used to indicate whether authorization code flow is supported by this profile.
     */
    public Predicate<ProfileRequestContext> getAuthorizationCodeFlowEnabled() {
        return authorizationCodeFlowPredicate;
    }

    /**
     * Set predicate used to indicate whether authorization code flow is supported by this profile.
     * 
     * @param predicate What to set.
     */
    public void setAuthorizationCodeFlowEnabled(final Predicate<ProfileRequestContext> predicate) {
        authorizationCodeFlowPredicate = Constraint.isNotNull(predicate,
                "Predicate used to indicate whether authorization code flow is supported cannot be null");
    }

    /**
     * Get predicate used to indicate whether implicit flow is supported by this profile.
     * 
     * @return Predicate used to indicate whether implicit flow is supported by this profile.
     */
    public Predicate<ProfileRequestContext> getHybridFlowEnabled() {
        return hybridFlowPredicate;
    }

    /**
     * Set predicate used to indicate whether implicit flow is supported by this profile.
     * 
     * @param predicate What to set.
     */
    public void setHybridFlowEnabled(final Predicate<ProfileRequestContext> predicate) {
        hybridFlowPredicate = Constraint.isNotNull(predicate,
                "Predicate used to indicate whether implicit flow is supported cannot be null");
    }

    /**
     * Get predicate used to indicate whether hybrid flow is supported by this profile.
     * 
     * @return Predicate used to indicate whether hybrid flow is supported by this profile.
     */
    public Predicate<ProfileRequestContext> getImplicitFlowEnabled() {
        return implicitFlowPredicate;
    }

    /**
     * Set predicate used to indicate whether hybrid flow is supported by this profile.
     * 
     * @param predicate What to set.
     */
    public void setImplicitFlowEnabled(final Predicate<ProfileRequestContext> predicate) {
        implicitFlowPredicate = Constraint.isNotNull(predicate,
                "Predicate used to indicate whether hybrid flow is supported cannot be null");
    }

    /**
     * Get predicate used to indicate whether refresh tokens are supported by this profile.
     * 
     * @return Predicate used to indicate whether refresh tokens are supported by this profile.
     */
    public Predicate<ProfileRequestContext> getRefreshTokensEnabled() {
        return refreshTokensPredicate;
    }

    /**
     * Set predicate used to indicate whether refresh tokens are supported by this profile.
     * 
     * @param predicate What to set.
     */
    public void setRefreshTokensEnabled(final Predicate<ProfileRequestContext> predicate) {
        refreshTokensPredicate = Constraint.isNotNull(predicate,
                "Predicate used to indicate whether refresh tokens are supported cannot be null");
    }
}
