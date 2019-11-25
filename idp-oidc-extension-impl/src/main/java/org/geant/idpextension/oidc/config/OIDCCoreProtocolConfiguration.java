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

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.profile.context.ProfileRequestContext;

import com.google.common.base.Function;
import com.google.common.base.Predicates;
import com.google.common.collect.Collections2;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;

import net.shibboleth.idp.authn.config.AuthenticationProfileConfiguration;
import net.shibboleth.utilities.java.support.annotation.Duration;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.annotation.constraint.NotLive;
import net.shibboleth.utilities.java.support.annotation.constraint.Positive;
import net.shibboleth.utilities.java.support.annotation.constraint.Unmodifiable;
import net.shibboleth.utilities.java.support.component.InitializableComponent;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

/**
 * Profile configuration for the OpenID Connect authorization and token end points.
 */
public class OIDCCoreProtocolConfiguration extends AbstractOIDCFlowAwareProfileConfiguration
        implements InitializableComponent, AuthenticationProfileConfiguration {

    /** OIDC base protocol URI. */
    public static final String PROTOCOL_URI = "http://openid.net/specs/openid-connect-core-1_0.html";

    /** ID for this profile configuration. */
    public static final String PROFILE_ID = "http://csc.fi/ns/profiles/oidc/sso/browser";

    /** Flag to indicate whether attributes should be resolved for this profile. */
    private boolean resolveAttributes = true;

    /** Selects, and limits, the authentication contexts to use for requests. */
    @Nonnull
    @NonnullElements
    private List<Principal> defaultAuthenticationContexts;

    /** Precedence of name identifier formats to use for requests. */
    @Nonnull
    @NonnullElements
    private List<String> nameIDFormatPrecedence;

    /** Filters the usable authentication flows. */
    @Nonnull
    @NonnullElements
    private Set<String> authenticationFlows;

    /** Enables post-authentication interceptor flows. */
    @Nonnull
    @NonnullElements
    private List<String> postAuthenticationFlows;

    /** Lookup function to supply {@link #idTokenLifetime} property. */
    @SuppressWarnings("rawtypes")
    @Nullable
    private Function<ProfileRequestContext, Long> idTokenLifetimeLookupStrategy;

    /** Lifetime of an id token in milliseconds. Default value: 5 minutes */
    @Positive
    @Duration
    private long idTokenLifetime;

    /** Lookup function to supply {@link #authorizeCodeLifetime} property. */
    @SuppressWarnings("rawtypes")
    @Nullable
    private Function<ProfileRequestContext, Long> authorizeCodeLifetimeLookupStrategy;

    /** Lifetime of an authorize code in milliseconds. Default value: 5 minutes */
    @Positive
    @Duration
    private long authorizeCodeLifetime;

    /** Lookup function to supply {@link #accessTokenLifetime} property. */
    @SuppressWarnings("rawtypes")
    @Nullable
    private Function<ProfileRequestContext, Long> accessTokenLifetimeLookupStrategy;

    /** Lifetime of an access token in milliseconds. Default value: 5 minutes */
    @Positive
    @Duration
    private long accessTokenLifetime;

    /** Lookup function to supply {@link #refreshTokenLifetime} property. */
    @SuppressWarnings("rawtypes")
    @Nullable
    private Function<ProfileRequestContext, Long> refreshTokenLifetimeLookupStrategy;

    /** Lifetime of an refresh token in milliseconds. Default value: 5 minutes */
    @Positive
    @Duration
    private long refreshTokenLifetime;

    /** Audiences to which an ID token may be shared. */
    @Nonnull
    @NonnullElements
    @NotLive
    @Unmodifiable
    private Set<String> additionalAudiences;

    /** Whether all acr claim requests should be treated as Essential. */
    private boolean acrRequestAlwaysEssential;

    /** Whether client is required to use PKCE. */
    private boolean forcePKCE;

    /** Whether client is allowed to use PKCE code challenge method plain. */
    private boolean allowPKCEPlain;

    /**
     * Constructor.
     */
    public OIDCCoreProtocolConfiguration() {
        this(PROFILE_ID);
    }

    /**
     * Creates a new configuration instance.
     *
     * @param profileId Unique profile identifier.
     */
    public OIDCCoreProtocolConfiguration(@Nonnull @NotEmpty final String profileId) {
        super(profileId);
        authenticationFlows = Collections.emptySet();
        postAuthenticationFlows = Collections.emptyList();
        defaultAuthenticationContexts = Collections.emptyList();
        nameIDFormatPrecedence = Collections.emptyList();
        idTokenLifetime = 60 * 60 * 1000;
        authorizeCodeLifetime = 5 * 60 * 1000;
        accessTokenLifetime = 10 * 60 * 1000;
        refreshTokenLifetime = 120 * 60 * 1000;
        additionalAudiences = Collections.emptySet();
    }

    /**
     * Checks whether the attributes are set to be resolved with this profile.
     * 
     * @return True if attribute resolution enabled for this profile, false otherwise.
     */
    public boolean isResolveAttributes() {
        return resolveAttributes;
    }

    /**
     * Enables or disables attribute resolution.
     *
     * @param resolve True to enable attribute resolution (default), false otherwise.
     */
    public void setResolveAttributes(final boolean resolve) {
        resolveAttributes = resolve;
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull
    @NonnullElements
    @NotLive
    @Unmodifiable
    public Set<String> getAuthenticationFlows() {
        return ImmutableSet.copyOf(authenticationFlows);
    }

    /**
     * Set the authentication flows to use.
     * 
     * @param flows flow identifiers to use
     */
    public void setAuthenticationFlows(@Nonnull @NonnullElements final Collection<String> flows) {
        Constraint.isNotNull(flows, "Collection of flows cannot be null");

        authenticationFlows = new HashSet<>(StringSupport.normalizeStringCollection(flows));
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull
    @NonnullElements
    @NotLive
    @Unmodifiable
    public List<String> getPostAuthenticationFlows() {
        return postAuthenticationFlows;
    }

    /**
     * Set the ordered collection of post-authentication interceptor flows to enable.
     * 
     * @param flows flow identifiers to enable
     */
    public void setPostAuthenticationFlows(@Nonnull @NonnullElements final Collection<String> flows) {
        Constraint.isNotNull(flows, "Collection of flows cannot be null");

        postAuthenticationFlows = new ArrayList<>(StringSupport.normalizeStringCollection(flows));
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull
    @NonnullElements
    @NotLive
    @Unmodifiable
    public List<Principal> getDefaultAuthenticationMethods() {
        return ImmutableList.<Principal> copyOf(defaultAuthenticationContexts);
    }

    /**
     * Set the default authentication contexts to use, expressed as custom principals.
     * 
     * @param contexts default authentication contexts to use
     */
    public void setDefaultAuthenticationMethods(@Nonnull @NonnullElements final List<Principal> contexts) {
        Constraint.isNotNull(contexts, "List of contexts cannot be null");

        defaultAuthenticationContexts = new ArrayList<>(Collections2.filter(contexts, Predicates.notNull()));
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull
    @NonnullElements
    @NotLive
    @Unmodifiable
    public List<String> getNameIDFormatPrecedence() {
        return ImmutableList.copyOf(nameIDFormatPrecedence);
    }

    /**
     * Set the name identifier formats to use.
     * 
     * @param formats name identifier formats to use
     */
    public void setNameIDFormatPrecedence(@Nonnull @NonnullElements final List<String> formats) {
        Constraint.isNotNull(formats, "List of formats cannot be null");

        nameIDFormatPrecedence = new ArrayList<>(StringSupport.normalizeStringCollection(formats));
    }

    /**
     * Set a lookup strategy for the {@link #idTokenLifetime} property.
     *
     * @param strategy lookup strategy
     */
    public void setIDTokenLifetimeLookupStrategy(
            @SuppressWarnings("rawtypes") @Nullable final Function<ProfileRequestContext, Long> strategy) {
        idTokenLifetimeLookupStrategy = strategy;
    }

    /**
     * Set a lookup strategy for the {@link #authorizeCodeLifetimeLifetime} property.
     *
     * @param strategy lookup strategy
     */
    public void setAuthorizeCodeLifetimeLookupStrategy(
            @SuppressWarnings("rawtypes") @Nullable final Function<ProfileRequestContext, Long> strategy) {
        authorizeCodeLifetimeLookupStrategy = strategy;
    }

    /**
     * Set a lookup strategy for the {@link #accessTokenLifetime} property.
     *
     * @param strategy lookup strategy
     */
    public void setAccessTokenLifetimeLookupStrategy(
            @SuppressWarnings("rawtypes") @Nullable final Function<ProfileRequestContext, Long> strategy) {
        accessTokenLifetimeLookupStrategy = strategy;
    }

    /**
     * Set a lookup strategy for the {@link #refreshTokenLifetime} property.
     *
     * @param strategy lookup strategy
     */
    public void setRefreshTokenLifetimeLookupStrategy(
            @SuppressWarnings("rawtypes") @Nullable final Function<ProfileRequestContext, Long> strategy) {
        refreshTokenLifetimeLookupStrategy = strategy;
    }

    /**
     * Get id token lifetime.
     * 
     * @return id token lifetime is ms.
     */
    @Positive
    @Duration
    public long getIDTokenLifetime() {
        return Constraint.isGreaterThan(0, getIndirectProperty(idTokenLifetimeLookupStrategy, idTokenLifetime),
                "id token lifetime must be greater than 0");
    }

    /**
     * Set the lifetime of an id token.
     * 
     * @param lifetime lifetime of an id token in milliseconds
     */
    @Duration
    public void setIDTokenLifetime(@Positive @Duration final long lifetime) {
        idTokenLifetime = Constraint.isGreaterThan(0, lifetime, "id token lifetime must be greater than 0");
    }

    /**
     * Set the lifetime of an access token.
     * 
     * @param lifetime lifetime of an access token in milliseconds
     */
    @Duration
    public void setAccessTokenLifetime(@Positive @Duration final long lifetime) {
        accessTokenLifetime = Constraint.isGreaterThan(0, lifetime, "access token lifetime must be greater than 0");
    }

    /**
     * Get access token lifetime.
     * 
     * @return access token lifetime is ms.
     */
    @Positive
    @Duration
    public long getAccessTokenLifetime() {
        return Constraint.isGreaterThan(0, getIndirectProperty(accessTokenLifetimeLookupStrategy, accessTokenLifetime),
                "access token lifetime must be greater than 0");
    }

    /**
     * Set the lifetime of authorize code.
     * 
     * @param lifetime lifetime of authorize code in milliseconds
     */
    @Duration
    public void setAuthorizeCodeLifetime(@Positive @Duration final long lifetime) {
        authorizeCodeLifetime = Constraint.isGreaterThan(0, lifetime, "authorize code lifetime must be greater than 0");
    }

    /**
     * Get authz code lifetime.
     * 
     * @return authz code lifetime in ms.
     */
    @Positive
    @Duration
    public long getAuthorizeCodeLifetime() {
        return Constraint.isGreaterThan(0,
                getIndirectProperty(authorizeCodeLifetimeLookupStrategy, authorizeCodeLifetime),
                "authorize code lifetime must be greater than 0");
    }

    /**
     * Set the lifetime of an refresh token.
     * 
     * @param lifetime lifetime of an refresh token in milliseconds
     */
    @Duration
    public void setRefreshTokenLifetime(@Positive @Duration final long lifetime) {
        refreshTokenLifetime = Constraint.isGreaterThan(0, lifetime, "refresh token lifetime must be greater than 0");
    }

    /**
     * Get refresh token lifetime.
     * 
     * @return refresh token lifetime in ms.
     */
    @Positive
    @Duration
    public long getRefreshTokenLifetime() {
        return Constraint.isGreaterThan(0,
                getIndirectProperty(refreshTokenLifetimeLookupStrategy, refreshTokenLifetime),
                "refresh token lifetime must be greater than 0");
    }

    /**
     * Set an unmodifiable set of audiences, in addition to the relying party(ies) to which the IdP is issuing the ID
     * token, with which an ID token may be shared.
     * 
     * @param audiences What to set.
     */
    public void setAdditionalAudiencesForIdToken(
            @Nonnull @NonnullElements @NotLive @Unmodifiable Collection<String> audiences) {
        Constraint.isNotNull(audiences, "Collection of additional audiences cannot be null");

        additionalAudiences = new HashSet<>(StringSupport.normalizeStringCollection(audiences));
    }

    /**
     * Get an unmodifiable set of audiences, in addition to the relying party(ies) to which the IdP is issuing the ID
     * token, with which an ID token may be shared.
     * 
     * @return additional audiences to which an ID token may be shared
     */
    @Nonnull
    @NonnullElements
    @NotLive
    @Unmodifiable
    public Set<String> getAdditionalAudiencesForIdToken() {
        return ImmutableSet.copyOf(additionalAudiences);
    }

    /**
     * Get whether all acr claim requests should be treated as Essential.
     * 
     * @return whether all acr claim requests should be treated as Essential
     */
    public boolean getAcrRequestAlwaysEssential() {
        return acrRequestAlwaysEssential;
    }

    /**
     * Set whether all acr claim requests should be treated as Essential.
     * 
     * @param isAlways whether all acr claim requests should be treated as Essential
     */
    public void setAcrRequestAlwaysEssential(boolean isAlways) {
        acrRequestAlwaysEssential = isAlways;
    }

    /**
     * Set whether client is required to use PKCE.
     * 
     * @param forced whether client is required to use PKCE
     */
    public void setForcePKCE(boolean forced) {
        forcePKCE = forced;
    }

    /**
     * Get whether client is required to use PKCE.
     * 
     * @return whether client is required to use PKCE
     */
    public boolean getForcePKCE() {
        return forcePKCE;
    }

    /**
     * Set whether client is allowed to use PKCE code challenge method plain.
     * 
     * @param allowPlain whether client is allowed to use PKCE code challenge method plain.
     */
    public void setAllowPKCEPlain(boolean allowPlain) {
        allowPKCEPlain = allowPlain;
    }

    /**
     * Get whether client is allowed to use PKCE code challenge method plain.
     * 
     * @return whether client is allowed to use PKCE code challenge method plain.
     */
    public boolean getAllowPKCEPlain() {
        return allowPKCEPlain;
    }
}
