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

import javax.annotation.Nonnull;

import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.profile.context.navigate.InboundMessageContextLookup;
import org.opensaml.storage.ReplayCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.google.common.base.Functions;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.ClientSecretJWT;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.PlainClientSecret;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

public class ValidateEndpointAuthentication extends AbstractOIDCTokenRequestAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(ValidateEndpointAuthentication.class);
    
    /** Strategy that will return {@link OIDCMetadataContext}. */
    @Nonnull
    private Function<ProfileRequestContext, OIDCMetadataContext> oidcMetadataContextLookupStrategy;
    
    /** Message replay cache instance to use. */
    @NonnullAfterInit
    private ReplayCache replayCache;
    
    /** The attached OIDC metadata context. */
    private OIDCMetadataContext oidcMetadataContext;
    
    /**
     * Constructor.
     */
    public ValidateEndpointAuthentication() {
        oidcMetadataContextLookupStrategy = Functions.compose(new ChildContextLookup<>(OIDCMetadataContext.class),
                new InboundMessageContextLookup());
    }
        
    /**
     * Set the strategy used to return the {@link OIDCMetadataContext}.
     * 
     * @param strategy The lookup strategy.
     */
    public void setOidcMetadataContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, OIDCMetadataContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        oidcMetadataContextLookupStrategy =
                Constraint.isNotNull(strategy, "OIDCMetadataContext lookup strategy cannot be null");
    }
    
    /**
     * Set the replay cache instance to use.
     * 
     * @param cache
     *            The replayCache to set.
     */
    public void setReplayCache(@Nonnull final ReplayCache cache) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        replayCache = Constraint.isNotNull(cache, "ReplayCache cannot be null");
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        Constraint.isNotNull(replayCache, "ReplayCache cannot be null");
    }
    
    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        if (!super.doPreExecute(profileRequestContext)) {
            log.error("{} pre-execute failed", getLogPrefix());
            return false;
        }
        oidcMetadataContext = oidcMetadataContextLookupStrategy.apply(profileRequestContext);
        if (oidcMetadataContext == null) {
            log.error("{} The OICD metadata context is null", getLogPrefix());
            return false;
        }
        return true;
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        final TokenRequest request = getTokenRequest();
        final OIDCClientInformation clientInformation = oidcMetadataContext.getClientInformation();
        final OIDCClientMetadata clientMetadata = clientInformation.getOIDCMetadata();
        final ClientAuthenticationMethod clientAuthMethod = clientMetadata.getTokenEndpointAuthMethod();
        final ClientAuthentication clientAuth = request.getClientAuthentication();
        if (clientAuthMethod.equals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)) {
            if ((clientAuth instanceof ClientSecretBasic)) {
                if (validateSecret((ClientSecretBasic)clientAuth, clientInformation)) {
                    return;
                }
            } else {
                log.warn("{} Unrecognized client authentication {} for client_secret_basic", getLogPrefix(), 
                        request.getClientAuthentication());
            }
        } else if (clientAuthMethod.equals(ClientAuthenticationMethod.CLIENT_SECRET_POST)) {
            if (clientAuth instanceof ClientSecretPost) {
                if (validateSecret((ClientSecretPost)clientAuth, clientInformation)) {
                    return;
                }
            } else {
                log.warn("{} Unrecognized client authentication {} for client_secret_post", getLogPrefix(), 
                        request.getClientAuthentication());
            }
        } else if (clientAuthMethod.equals(ClientAuthenticationMethod.CLIENT_SECRET_JWT)) {
            if (clientAuth instanceof ClientSecretJWT) {
                final ClientSecretJWT secretJwt = (ClientSecretJWT) clientAuth;
                final String clientAssertionType = request.getCustomParameter("client_assertion_type");
                if (!"urn:ietf:params:oauth:client-assertion-type:jwt-bearer".equals(clientAssertionType)) {
                    log.warn("{} Unrecognized client assertion type {}", getLogPrefix(), clientAssertionType);
                } else {
                    final SignedJWT jwt = secretJwt.getClientAssertion();
                    try {
                        final JWSVerifier verifier = new MACVerifier(clientInformation.getSecret().getValue());
                        if (jwt.verify(verifier)) {
                            log.debug("{} The incoming JWT successfully verified", getLogPrefix());
                            return;
                        } else {
                            log.warn("{} The incoming JWT could not be verified", getLogPrefix());
                        }
                    } catch (JOSEException e) {
                        log.error("{} Exception caught during the JWT validation", getLogPrefix(), e);
                    }
                }
            }
            //TODO: check tid
        } else {
            //TODO: support the rest of the standard methods
            log.warn("{} Unsupported client authentication method {}", getLogPrefix(), clientAuth.getMethod());
        }
        ActionSupport.buildEvent(profileRequestContext, EventIds.ACCESS_DENIED);
    }

    protected boolean validateSecret(final PlainClientSecret secret, final OIDCClientInformation clientInformation) {
        final Secret clientSecret = secret.getClientSecret();
        if (clientSecret == null) {
            log.warn("{} The client secret was null and cannot be validated", getLogPrefix());
            return false;
        }
        //TODO: should support other than plaintext storage
        if (clientSecret.equals(clientInformation.getSecret())) {
            log.debug("{} Password successfully verified", getLogPrefix());
            return true;
        }
        log.warn("{} Password validation failed", getLogPrefix());
        return false;
    }
}
