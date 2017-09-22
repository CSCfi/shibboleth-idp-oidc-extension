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

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.annotation.Nonnull;

import org.opensaml.profile.context.ProfileRequestContext;

import com.google.common.base.Predicates;
import com.google.common.collect.Collections2;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;

import net.shibboleth.idp.authn.config.AuthenticationProfileConfiguration;
import net.shibboleth.idp.profile.config.AbstractProfileConfiguration;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.annotation.constraint.NotLive;
import net.shibboleth.utilities.java.support.annotation.constraint.Unmodifiable;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.InitializableComponent;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

import com.google.common.base.Predicate;

/**
 * Base class for OIDC protocol configuration.
 */
public class OIDCCoreProtocolConfiguration extends AbstractProfileConfiguration
    implements InitializableComponent, AuthenticationProfileConfiguration {

    /** OIDC base protocol URI. */
    public static final String PROTOCOL_URI = "http://openid.net/specs/openid-connect-core-1_0.html";

    /** ID for this profile configuration. */
    public static final String PROFILE_ID = "http://csc.fi/ns/profiles/oidc/sso/browser";
    
    /** Initialization flag. */
    private boolean initialized;

    /** Flag to indicate whether attributes should be resolved for this profile. */
    private boolean resolveAttributes = true;
    
    /** Flag to indicate whether authorization code flow is supported by this profile. */
    private boolean authorizationCodeFlow = true;
    
    /** Flag to indicate whether implicit flow is supported by this profile. */
    private boolean implicitFlow = true;
    
    /** Flag to indicate whether hybrid flow is supported by this profile. */
    private boolean hybridFlow = true;
    
    /** Selects, and limits, the authentication contexts to use for requests. */
    @Nonnull @NonnullElements private List<Principal> defaultAuthenticationContexts;
    
    /** Precedence of name identifier formats to use for requests. */
    @Nonnull @NonnullElements private List<String> nameIDFormatPrecedence;
    
    /** Filters the usable authentication flows. */
    @Nonnull @NonnullElements private Set<String> authenticationFlows;
    
    /** Enables post-authentication interceptor flows. */
    @Nonnull @NonnullElements private List<String> postAuthenticationFlows;
    
    /** Predicate used to determine if the generated id token should be signed. Default returns true. */
    @SuppressWarnings("rawtypes")
    @Nonnull private Predicate<ProfileRequestContext> signIDTokensPredicate;

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
        signIDTokensPredicate = Predicates.alwaysTrue();
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
     * Get the predicate used to determine if generated id tokens should be
     * signed.
     * 
     * @return predicate to determine signing of id token.
     */
    @SuppressWarnings("rawtypes")
    @Nonnull
    public Predicate<ProfileRequestContext> getSignIDTokens() {
        return signIDTokensPredicate;
    }

    /**
     * Set the predicate used to determine if generated id tokens should be
     * signed.
     * 
     * @param predicate
     *            predicate used to determine if generated responses should be
     *            signed
     */
    @SuppressWarnings("rawtypes")
    public void setSignIDTokens(@Nonnull final Predicate<ProfileRequestContext> predicate) {
        signIDTokensPredicate = Constraint.isNotNull(predicate,
                "Predicate to determine if id tokens should be signed cannot be null");
    }

    /**
     * Checks whether the attributes are set to be resolved with this profile.
     *  
     * @return True if attribute resolution enabled for this profile, false otherwise. */
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

    /** {@inheritDoc} */
    @Override @Nonnull @NonnullElements @NotLive @Unmodifiable public Set<String> getAuthenticationFlows() {
        return ImmutableSet.copyOf(authenticationFlows);
    }

    /**
     * Set the authentication flows to use.
     * 
     * @param flows   flow identifiers to use
     */
    public void setAuthenticationFlows(@Nonnull @NonnullElements final Collection<String> flows) {
        Constraint.isNotNull(flows, "Collection of flows cannot be null");
        
        authenticationFlows = new HashSet<>(StringSupport.normalizeStringCollection(flows));
    }
    
    /** {@inheritDoc} */
    @Override @Nonnull @NonnullElements @NotLive @Unmodifiable public List<String> getPostAuthenticationFlows() {
        return postAuthenticationFlows;
    }

    /**
     * Set the ordered collection of post-authentication interceptor flows to enable.
     * 
     * @param flows   flow identifiers to enable
     */
    public void setPostAuthenticationFlows(@Nonnull @NonnullElements final Collection<String> flows) {
        Constraint.isNotNull(flows, "Collection of flows cannot be null");
        
        postAuthenticationFlows = new ArrayList<>(StringSupport.normalizeStringCollection(flows));
    }
    
    /** {@inheritDoc} */
    @Override @Nonnull @NonnullElements @NotLive @Unmodifiable public List<Principal> 
        getDefaultAuthenticationMethods() {
        return ImmutableList.<Principal> copyOf(defaultAuthenticationContexts);
    }
    
    /**
     * Set the default authentication contexts to use, expressed as custom principals.
     * 
     * @param contexts default authentication contexts to use
     */
    public void setDefaultAuthenticationMethods(
            @Nonnull @NonnullElements final List<Principal> contexts) {
        Constraint.isNotNull(contexts, "List of contexts cannot be null");

        defaultAuthenticationContexts = new ArrayList<>(Collections2.filter(contexts, Predicates.notNull()));
    }
    
    /** {@inheritDoc} */
    @Override @Nonnull @NonnullElements @NotLive @Unmodifiable public List<String> getNameIDFormatPrecedence() {
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
}
