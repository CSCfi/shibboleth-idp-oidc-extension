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
import javax.annotation.Nullable;

import org.opensaml.profile.context.ProfileRequestContext;

import com.google.common.base.Function;

import net.shibboleth.idp.profile.config.AbstractProfileConfiguration;
import net.shibboleth.utilities.java.support.annotation.Duration;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.InitializableComponent;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Profile configuration for the OpenID Connect dynamic client registration.
 */
public class OIDCDynamicRegistrationConfiguration extends AbstractProfileConfiguration
        implements InitializableComponent {

    /** OIDC base protocol URI. */
    public static final String PROTOCOL_URI = "https://openid.net/specs/openid-connect-registration-1_0.html";

    /** ID for this profile configuration. */
    public static final String PROFILE_ID = "http://csc.fi/ns/profiles/oidc/registration";

    /** Initialization flag. */
    private boolean initialized;

    /** Lookup function to supply {@link #registrationValidityPeriod} property. */
    @Nullable private Function<ProfileRequestContext, Long> registrationValidityPeriodLookupStrategy;

    /** Validity time period of dynamically registered clients. Zero means valid forever. */
    @Duration private long registrationValidityPeriod;

    /**
     * Constructor.
     */
    public OIDCDynamicRegistrationConfiguration() {
        this(PROFILE_ID);
    }

    /**
     * Creates a new configuration instance.
     *
     * @param profileId Unique profile identifier.
     */
    public OIDCDynamicRegistrationConfiguration(@Nonnull @NotEmpty final String profileId) {
        super(profileId);
        setRegistrationValidityPeriod(0);
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
     * Get dynamic registration validity period.
     * 
     * @return Dynamic registration validity period in milliseconds.
     */
    @Duration public long getRegistrationValidityPeriod() {
        return Constraint.isGreaterThan(-1,
                getIndirectProperty(registrationValidityPeriodLookupStrategy, registrationValidityPeriod),
                "Registration validity period must be 0 or positive.");
    }

    /**
     * Sets the registration validity period.
     * 
     * @param millis Registration validity period in milliseconds.
     */
    @Duration public void setRegistrationValidityPeriod(@Duration final long millis) {
        registrationValidityPeriod = Constraint.isGreaterThan(-1, millis, 
                "Registration validity period must be 0 or positive.");
    }

    /**
     * Set a lookup strategy for the {@link #registrationValidityPeriod} property.
     * 
     * @param strategy lookup strategy
     */
    public void setRegistrationValidityPeriodLookupStrategy(@Nullable final Function<ProfileRequestContext, 
            Long> strategy) {
        registrationValidityPeriodLookupStrategy = strategy;
    }

}
