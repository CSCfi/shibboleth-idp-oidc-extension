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

package org.geant.idpextension.oidc.config;

import javax.annotation.Nonnull;

import org.opensaml.profile.context.ProfileRequestContext;

import com.google.common.base.Predicate;
import com.google.common.base.Predicates;

import net.shibboleth.idp.profile.config.AbstractProfileConfiguration;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.InitializableComponent;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Base class for OIDC protocol configuration, containing configuration bits shared by all OIDC protocol
 * configurations.
 */
@SuppressWarnings("rawtypes")
public abstract class AbstractOIDCProfileConfiguration extends AbstractProfileConfiguration
    implements InitializableComponent{
    
    /** Initialization flag. */
    private boolean initialized;

    /** Predicate used to indicate whether authorization code flow is supported by this profile. Default true. */
    @Nonnull private Predicate<ProfileRequestContext> authorizationCodeFlowPredicate;
    
    /** Predicate used to indicate whether implicit flow is supported by this profile. Default true. */
    @Nonnull private Predicate<ProfileRequestContext> implicitFlowPredicate;
    
    /** Predicate used to indicate whether hybrid flow is supported by this profile. Default true. */
    @Nonnull private Predicate<ProfileRequestContext> hybridFlowPredicate;

    /**
     * Constructor.
     *
     * @param profileId Unique profile identifier.
     */
    protected AbstractOIDCProfileConfiguration(final String profileId) {
        super(profileId);
        authorizationCodeFlowPredicate = Predicates.alwaysTrue();
        implicitFlowPredicate = Predicates.alwaysTrue();
        hybridFlowPredicate = Predicates.alwaysTrue();
    }

    /** {@inheritDoc} */
    @Override
    public void initialize() throws ComponentInitializationException {
        Constraint.isNotNull(getSecurityConfiguration(), "Security configuration cannot be null.");
        Constraint.isNotNull(getSecurityConfiguration().getIdGenerator(),
                "Security configuration ID generator cannot be null.");
        initialized = true;
    }

    /** {@inheritDoc} */
    @Override
    public boolean isInitialized() {
        return initialized;
    }
    
    /**
     * Get predicate used to indicate whether authorization code flow is supported by this profile.
     * @return Predicate used to indicate whether authorization code flow is supported by this profile.
     */
    public Predicate<ProfileRequestContext> getAuthorizationCodeFlowEnabled() {
        return authorizationCodeFlowPredicate;
    }
    
    /**
     * Set predicate used to indicate whether authorization code flow is supported by this profile.
     * @param predicate What to set.
     */
    public void setAuthorizationCodeFlowEnabled(final Predicate<ProfileRequestContext> predicate) {
        authorizationCodeFlowPredicate = Constraint.isNotNull(predicate, 
                "Predicate used to indicate whether authorization code flow is supported cannot be null");
    }

    /**
     * Get predicate used to indicate whether implicit flow is supported by this profile.
     * @return Predicate used to indicate whether implicit flow is supported by this profile.
     */
    public Predicate<ProfileRequestContext> getHybridFlowEnabled() {
        return hybridFlowPredicate;
    }
    
    /**
     * Set predicate used to indicate whether implicit flow is supported by this profile.
     * @param predicate What to set.
     */
    public void setHybridFlowEnabled(final Predicate<ProfileRequestContext> predicate) {
        hybridFlowPredicate = Constraint.isNotNull(predicate, 
                "Predicate used to indicate whether implicit flow is supported cannot be null");
    }

    /**
     * Get predicate used to indicate whether hybrid flow is supported by this profile.
     * @return Predicate used to indicate whether hybrid flow is supported by this profile.
     */
    public Predicate<ProfileRequestContext> getImplicitFlowEnabled() {
        return implicitFlowPredicate;
    }
    
    /**
     * Set predicate used to indicate whether hybrid flow is supported by this profile.
     * @param predicate What to set.
     */
    public void setImplicitFlowEnabled(final Predicate<ProfileRequestContext> predicate) {
        implicitFlowPredicate = Constraint.isNotNull(predicate, 
                "Predicate used to indicate whether hybrid flow is supported cannot be null");
    }
}
