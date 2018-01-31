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

import net.shibboleth.idp.profile.config.AbstractProfileConfiguration;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.InitializableComponent;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Base class for OIDC protocol configuration, containing configuration bits shared by all OIDC protocol
 * configurations.
 */
public abstract class AbstractOIDCProfileConfiguration extends AbstractProfileConfiguration
    implements InitializableComponent{
    
    /** Initialization flag. */
    private boolean initialized;

    /** Flag to indicate whether authorization code flow is supported by this profile. */
    private boolean authorizationCodeFlow = true;
    
    /** Flag to indicate whether implicit flow is supported by this profile. */
    private boolean implicitFlow = true;
    
    /** Flag to indicate whether hybrid flow is supported by this profile. */
    private boolean hybridFlow = true;

    /**
     * Constructor.
     *
     * @param profileId Unique profile identifier.
     */
    protected AbstractOIDCProfileConfiguration(final String profileId) {
        super(profileId);
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
     * Checks whether the authorization code flow is enabled for this profile.
     * 
     * @return True if the flow is enabled for this profile, false otherwise.
     */
    public boolean isAuthorizationCodeFlow() {
        return authorizationCodeFlow;
    }
    
    /**
     * Enables or disables authorization code flow.
     * 
     * @param flow True to enable flow (default), false otherwise.
     */
    public void setAuthorizationCodeFlow(final boolean flow) {
        authorizationCodeFlow = flow;
    }

    /**
     * Checks whether the hybrid flow is enabled for this profile.
     * 
     * @return True if the flow is enabled for this profile, false otherwise.
     */
    public boolean isHybridFlow() {
        return hybridFlow;
    }
    
    /**
     * Enables or disables hybrid flow.
     * 
     * @param flow True to enable flow (default), false otherwise.
     */
    public void setHybridFlow(final boolean flow) {
        hybridFlow = flow;
    }

    /**
     * Checks whether the implicit flow is enabled for this profile.
     * 
     * @return True if the flow is enabled for this profile, false otherwise.
     */
    public boolean isImplicitFlow() {
        return implicitFlow;
    }
    
    /**
     * Enables or disables implicit flow.
     * 
     * @param flow True to enable flow (default), false otherwise.
     */
    public void setImplicitFlow(final boolean flow) {
        implicitFlow = flow;
    }
}
