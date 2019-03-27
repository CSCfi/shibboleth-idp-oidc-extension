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

import java.net.MalformedURLException;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.geant.idpextension.oidc.config.navigate.TokenEndpointAuthMethodLookupFunction;
import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.geant.idpextension.oidc.security.impl.JWTSignatureValidationUtil;
import org.geant.idpextension.oidc.security.impl.OIDCSignatureValidationParameters;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.profile.context.navigate.InboundMessageContextLookup;
import org.opensaml.storage.ReplayCache;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.google.common.base.Functions;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.AbstractOptionallyAuthenticatedRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.ClientSecretJWT;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.PlainClientSecret;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Validates the endpoint authentication with the token_endpoint_auth_method stored to the client's metadata.
 */
public class ValidateEndpointAuthentication extends AbstractOIDCRequestAction<AbstractOptionallyAuthenticatedRequest> {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(ValidateEndpointAuthentication.class);
    
    /** Strategy that will return {@link OIDCMetadataContext}. */
    @Nonnull
    private Function<ProfileRequestContext, OIDCMetadataContext> oidcMetadataContextLookupStrategy;
    
    /** Strategy to obtain enabled token endpoint authentication methods. */
    @Nullable private Function<ProfileRequestContext, List<ClientAuthenticationMethod>> 
        tokenEndpointAuthMethodsLookupStrategy;
    
    /** Message replay cache instance to use. */
    @NonnullAfterInit
    private ReplayCache replayCache;
    
    /** The attached OIDC metadata context. */
    private OIDCMetadataContext oidcMetadataContext;
    
    /*** The signature validation parameters. */
    @Nullable
    private OIDCSignatureValidationParameters signatureValidationParameters;

    /**
     * Strategy used to locate the {@link SecurityParametersContext} to use for signing.
     */
    @Nonnull
    private Function<ProfileRequestContext, SecurityParametersContext> securityParametersLookupStrategy;

    
    /**
     * Constructor.
     */
    public ValidateEndpointAuthentication() {
        oidcMetadataContextLookupStrategy = Functions.compose(new ChildContextLookup<>(OIDCMetadataContext.class),
                new InboundMessageContextLookup());
        tokenEndpointAuthMethodsLookupStrategy = new TokenEndpointAuthMethodLookupFunction();
        securityParametersLookupStrategy = new ChildContextLookup<>(SecurityParametersContext.class);
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
     * Set strategy to obtain enabled token endpoint authentication methods.
     * @param strategy What to set.
     */
    public void setTokenEndpointAuthMethodsLookupStrategy(@Nonnull final Function<ProfileRequestContext, 
            List<ClientAuthenticationMethod>> strategy) {
        tokenEndpointAuthMethodsLookupStrategy = Constraint.isNotNull(strategy, 
                "Strategy to obtain enabled token endpoint authentication methods cannot be null");
        
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
    
    /**
     * Set the strategy used to locate the {@link SecurityParametersContext} to use.
     * 
     * @param strategy lookup strategy
     */
    public void setSecurityParametersLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, SecurityParametersContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        securityParametersLookupStrategy =
                Constraint.isNotNull(strategy, "SecurityParameterContext lookup strategy cannot be null");
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
        final AbstractOptionallyAuthenticatedRequest request = getRequest();
        final OIDCClientInformation clientInformation = oidcMetadataContext.getClientInformation();
        final OIDCClientMetadata clientMetadata = clientInformation.getOIDCMetadata();
        final ClientAuthenticationMethod clientAuthMethod = clientMetadata.getTokenEndpointAuthMethod() != null ? 
                clientMetadata.getTokenEndpointAuthMethod() : ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
        final ClientAuthentication clientAuth = request.getClientAuthentication();
        final List<ClientAuthenticationMethod> enabledMethods = 
                tokenEndpointAuthMethodsLookupStrategy.apply(profileRequestContext);
                
        if (enabledAndEquals(enabledMethods, clientAuthMethod, ClientAuthenticationMethod.NONE)) {
           log.debug("{} None authentication is requested and enabled, nothing to do", getLogPrefix());
           return;
        } else if (enabledAndEquals(enabledMethods, clientAuthMethod, 
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC)) {
            if (clientAuth instanceof ClientSecretBasic) {
                if (validateSecret((ClientSecretBasic)clientAuth, clientInformation)) {
                    return;
                }
            } else {
                log.warn("{} Unrecognized client authentication {} for client_secret_basic", getLogPrefix(), 
                        request.getClientAuthentication());
            }
        } else if (enabledAndEquals(enabledMethods, clientAuthMethod, ClientAuthenticationMethod.CLIENT_SECRET_POST)) {
            if (clientAuth instanceof ClientSecretPost) {
                if (validateSecret((ClientSecretPost)clientAuth, clientInformation)) {
                    return;
                }
            } else {
                log.warn("{} Unrecognized client authentication {} for client_secret_post", getLogPrefix(), 
                        request.getClientAuthentication());
            }
        } else if (enabledAndEquals(enabledMethods, clientAuthMethod, ClientAuthenticationMethod.CLIENT_SECRET_JWT)) {
            if (clientAuth instanceof ClientSecretJWT) {
                final ClientSecretJWT secretJwt = (ClientSecretJWT) clientAuth;
                final SignedJWT jwt = secretJwt.getClientAssertion();
                final JWKSource keySource = new ImmutableSecret(clientInformation.getSecret().getValueBytes());
                if (validateJwt(jwt, keySource, clientMetadata.getTokenEndpointAuthJWSAlg())) {
                    return;
                }
            }
        } else if (enabledAndEquals(enabledMethods, clientAuthMethod, ClientAuthenticationMethod.PRIVATE_KEY_JWT)) {
            if (clientAuth instanceof PrivateKeyJWT) {
                final PrivateKeyJWT keyJwt = (PrivateKeyJWT) clientAuth;
                final SignedJWT jwt = keyJwt.getClientAssertion();

                final String errorEventId = JWTSignatureValidationUtil.validateSignature(
                        securityParametersLookupStrategy.apply(profileRequestContext), jwt, EventIds.ACCESS_DENIED);
                
                if (errorEventId != null) {
                    ActionSupport.buildEvent(profileRequestContext, errorEventId);
                }
                return;

            }
        } else {
            log.warn("{} Unsupported client authentication method {}", getLogPrefix(), clientAuth.getMethod());
        }
        ActionSupport.buildEvent(profileRequestContext, EventIds.ACCESS_DENIED);
    }
    
    /**
     * Checks whether the requested authentication method is enabled and matching to the desired method.
     * @param enabledMethods The list of enabled authentication method.
     * @param requestedMethod The requested authentication method to be checked.
     * @param desiredMethod The desired authentication method.
     * @return True if enabled and matching, false otherwise.
     */
    protected boolean enabledAndEquals(final List<ClientAuthenticationMethod> enabledMethods, 
            final ClientAuthenticationMethod requestedMethod, final ClientAuthenticationMethod desiredMethod) {
        if (requestedMethod.equals(desiredMethod)) {
            if (enabledMethods == null || enabledMethods.isEmpty()) {
                log.warn("{} List of enabled methods is empty, all methods are disabled", getLogPrefix());
                return false;
            }
            if (!enabledMethods.contains(requestedMethod)) {
                log.warn("{} The requested method {} is not enabled", getLogPrefix(), requestedMethod);
                return false;
            }
            return true;
        }
        return false;
    }

    /**
     * Initializes the JWK source from the given client's metadata.
     * @param clientMetadata The client metadata.
     * @return The JWK source corresponding to the metadata.
     */
    protected JWKSource initializeKeySource(final OIDCClientMetadata clientMetadata) {
        if (clientMetadata.getJWKSet() != null) {
            return new ImmutableJWKSet(clientMetadata.getJWKSet());
        } else if (clientMetadata.getJWKSetURI() != null) {
            try {
                return new RemoteJWKSet(clientMetadata.getJWKSetURI().toURL());
            } catch (MalformedURLException e) {
                log.warn("{} Could not convert the URI {} to URL", getLogPrefix(), clientMetadata.getJWKSetURI());
            }
        } else {
            log.error("{} No jwks or jwks_uri registered for this client", getLogPrefix());
        }
        return null;
    }
    
    /**
     * Validates the given client secret against the one stored in the client's metadata.
     * @param secret The secret to be validated.
     * @param clientInformation The client metadata.
     * @return True if the secret was valid, false otherwise.
     */
    protected boolean validateSecret(final PlainClientSecret secret, final OIDCClientInformation clientInformation) {
        final Secret clientSecret = secret.getClientSecret();
        if (clientSecret == null) {
            log.warn("{} The client secret was null and cannot be validated", getLogPrefix());
            return false;
        }
        //TODO: should support other than plaintext storage
        if (clientSecret.equals(clientInformation.getSecret())) {
            log.debug("{} The client secret successfully verified", getLogPrefix());
            return true;
        }
        log.warn("{} The client secret validation failed", getLogPrefix());
        return false;
    }
    
    /**
     * Validates the given JWT using the given key source and algorithm.
     * @param jwt The JWT to be validated.
     * @param keySource The key source used for validation.
     * @param expectedAlg The expected algorithm. If null, then the algorithm defined in the JWT's header is used.
     * @return True if the JWT is valid, false otherwise.
     */
    protected boolean validateJwt(final SignedJWT jwt, final JWKSource keySource, final JWSAlgorithm expectedAlg) {
        //TODO verify that the algorithm is accepted
        final JWSAlgorithm algorithm = (expectedAlg == null) ? jwt.getHeader().getAlgorithm() : expectedAlg;
        final ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
        final JWSKeySelector keySelector = new JWSVerificationKeySelector(algorithm, keySource);
        jwtProcessor.setJWSKeySelector(keySelector);
        try {
            final JWTClaimsSet claimsSet = jwtProcessor.process(jwt, null);
            claimsSet.getJWTID();
            if (!replayCache.check(getClass().getName(), claimsSet.getJWTID(),
                    claimsSet.getExpirationTime().getTime())) {
                log.warn("{} Replay detected for JWT id {}", getLogPrefix(), claimsSet.getJWTID());
                return false;
            }
        } catch (BadJOSEException | JOSEException e) {
            log.warn("{} Could not validate the signature", getLogPrefix());
            return false;
        }
        log.debug("{} The incoming JWT successfully verified", getLogPrefix());
        return true;
    }
}
