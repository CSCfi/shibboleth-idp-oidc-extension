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
import javax.annotation.Nullable;

import org.opensaml.profile.context.ProfileRequestContext;

import com.google.common.base.Function;

import net.shibboleth.utilities.java.support.annotation.Duration;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.InitializableComponent;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Profile configuration for the OpenID Connect dynamic client registration.
 */
public class OIDCDynamicRegistrationConfiguration extends AbstractOIDCFlowAwareProfileConfiguration
        implements InitializableComponent {

    /** OIDC base protocol URI. */
    public static final String PROTOCOL_URI = "https://openid.net/specs/openid-connect-registration-1_0.html";

    /** ID for this profile configuration. */
    public static final String PROFILE_ID = "http://csc.fi/ns/profiles/oidc/registration";

    /** Initialization flag. */
    private boolean initialized;

    /** Lookup function to supply {@link #registrationValidityPeriod} property. */
    @SuppressWarnings("rawtypes")
    @Nullable private Function<ProfileRequestContext, Long> registrationValidityPeriodLookupStrategy;

    /** Validity time period of dynamically registered clients. Zero means valid forever. */
    @Duration private long registrationValidityPeriod;

    /** Lookup function to supply {@link #secretExpirationPeriod} property. */
    @SuppressWarnings("rawtypes")
    @Nullable private Function<ProfileRequestContext, Long> secretExpirationPeriodLookupStrategy;

    /** Client secret expiration period of dynamically registered clients. Zero means valid forever. */
    @Duration private long secretExpirationPeriod;

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
        setSecretExpirationPeriod(0);
    }

    /** {@inheritDoc} */
    @Override
    public void initialize() throws ComponentInitializationException {
        super.initialize();
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
    @SuppressWarnings("rawtypes")
    public void setRegistrationValidityPeriodLookupStrategy(@Nullable final Function<ProfileRequestContext, 
            Long> strategy) {
        registrationValidityPeriodLookupStrategy = strategy;
    }

    /**
     * Get client secret expiration period.
     * 
     * @return Client secret expiration period in milliseconds.
     */
    @Duration public long getSecretExpirationPeriod() {
        return Constraint.isGreaterThan(-1,
                getIndirectProperty(secretExpirationPeriodLookupStrategy, secretExpirationPeriod),
                "Secret expiration period must be 0 or positive.");
    }

    /**
     * Sets the client secret expiration period.
     * 
     * @param millis What to set in milliseconds.
     */
    @Duration public void setSecretExpirationPeriod(@Duration final long millis) {
        secretExpirationPeriod = Constraint.isGreaterThan(-1, millis, 
                "Secret expiration period must be 0 or positive.");
    }

    /**
     * Set a lookup strategy for the {@link #secretExpirationPeriod} property.
     * 
     * @param strategy lookup strategy
     */
    @SuppressWarnings("rawtypes")
    public void setSecretExpirationPeriodLookupStrategy(@Nullable final Function<ProfileRequestContext, 
            Long> strategy) {
        secretExpirationPeriodLookupStrategy = strategy;
    }
}
