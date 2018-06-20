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

import java.util.Date;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Function;
import com.google.common.base.Functions;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;

import net.minidev.json.JSONArray;
import net.shibboleth.idp.authn.context.SubjectContext;
import net.shibboleth.idp.profile.IdPEventIds;
import net.shibboleth.idp.profile.config.ProfileConfiguration;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.idp.profile.context.navigate.ResponderIdLookupFunction;

import org.geant.idpextension.oidc.config.OIDCCoreProtocolConfiguration;
import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseConsentContext;
import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseTokenClaimsContext;
import org.geant.idpextension.oidc.profile.context.navigate.OIDCAuthenticationResponseContextLookupFunction;
import org.geant.idpextension.oidc.token.support.AccessTokenClaimsSet;
import org.geant.idpextension.oidc.token.support.AuthorizeCodeClaimsSet;
import org.geant.idpextension.oidc.token.support.RefreshTokenClaimsSet;
import org.geant.idpextension.oidc.token.support.TokenClaimsSet;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;

import net.shibboleth.utilities.java.support.annotation.ParameterName;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.security.DataSealer;
import net.shibboleth.utilities.java.support.security.DataSealerException;
import net.shibboleth.utilities.java.support.security.IdentifierGenerationStrategy;
import net.shibboleth.utilities.java.support.security.SecureRandomIdentifierGenerationStrategy;

/**
 * Action that creates a Access Token, and sets it to work context
 * {@link OIDCAuthenticationResponseContext#getAccessToken()} located under
 * {@link ProfileRequestContext#getOutboundMessageContext()}.
 */
@SuppressWarnings("rawtypes")
public class SetAccessTokenToResponseContext extends AbstractOIDCResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(SetAccessTokenToResponseContext.class);

    /** Access Token lifetime. */
    private long accessTokenLifetime;

    /** Data sealer for handling access token. */
    @Nonnull
    private final DataSealer dataSealer;

    /**
     * Strategy used to locate the {@link RelyingPartyContext} associated with a given {@link ProfileRequestContext}.
     */
    @Nonnull
    private Function<ProfileRequestContext, RelyingPartyContext> relyingPartyContextLookupStrategy;

    /** Authorize Code / Refresh Token the access token is based on. */
    private TokenClaimsSet tokenClaimsSet;

    /** Strategy used to obtain the response issuer value. */
    @Nonnull
    private Function<ProfileRequestContext, String> issuerLookupStrategy;

    /** Subject context. */
    private SubjectContext subjectCtx;

    /** The generator to use. */
    @Nullable
    private IdentifierGenerationStrategy idGenerator;

    /** Strategy used to locate the {@link IdentifierGenerationStrategy} to use. */
    @Nonnull
    private Function<ProfileRequestContext, IdentifierGenerationStrategy> idGeneratorLookupStrategy;

    /** Authentication request the token is based on. */
    private AuthenticationRequest authenticationRequest;

    /** Strategy used to locate the {@link OIDCAuthenticationResponseTokenClaimsContext}. */
    @Nonnull
    private Function<ProfileRequestContext, OIDCAuthenticationResponseTokenClaimsContext> tokenClaimsContextLookupStrategy;

    /** Strategy used to locate the {@link OIDCAuthenticationResponseConsentContext}. */
    @Nonnull
    private Function<ProfileRequestContext, OIDCAuthenticationResponseConsentContext> consentContextLookupStrategy;

    /**
     * Constructor.
     * 
     * @param sealer sealer to encrypt/hmac access token.
     */
    public SetAccessTokenToResponseContext(@Nonnull @ParameterName(name = "sealer") final DataSealer sealer) {
        tokenClaimsContextLookupStrategy =
                Functions.compose(new ChildContextLookup<>(OIDCAuthenticationResponseTokenClaimsContext.class),
                        new OIDCAuthenticationResponseContextLookupFunction());
        consentContextLookupStrategy =
                Functions.compose(new ChildContextLookup<>(OIDCAuthenticationResponseConsentContext.class),
                        new OIDCAuthenticationResponseContextLookupFunction());
        relyingPartyContextLookupStrategy = new ChildContextLookup<>(RelyingPartyContext.class);
        dataSealer = Constraint.isNotNull(sealer, "DataSealer cannot be null");
        issuerLookupStrategy = new ResponderIdLookupFunction();
        idGeneratorLookupStrategy = new Function<ProfileRequestContext, IdentifierGenerationStrategy>() {
            public IdentifierGenerationStrategy apply(ProfileRequestContext input) {
                return new SecureRandomIdentifierGenerationStrategy();
            }
        };
    }

    /**
     * Set the strategy used to locate the {@link OIDCAuthenticationResponseTokenClaimsContext} associated with a given
     * {@link ProfileRequestContext}.
     * 
     * @param strategy lookup strategy
     */
    public void setOIDCAuthenticationResponseTokenClaimsContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, OIDCAuthenticationResponseTokenClaimsContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        tokenClaimsContextLookupStrategy = Constraint.isNotNull(strategy,
                "OIDCAuthenticationResponseTokenClaimsContextt lookup strategy cannot be null");
    }

    /**
     * Set the strategy used to locate the {@link OIDCAuthenticationResponseTokenClaimsContext} associated with a given
     * {@link ProfileRequestContext}.
     * 
     * @param strategy lookup strategy
     */
    public void setOIDCAuthenticationResponseConsentContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, OIDCAuthenticationResponseConsentContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        consentContextLookupStrategy = Constraint.isNotNull(strategy,
                "OIDCAuthenticationResponseConsentContext lookup strategy cannot be null");
    }

    /**
     * Set the strategy used to locate the {@link RelyingPartyContext} associated with a given
     * {@link ProfileRequestContext}.
     * 
     * @param strategy strategy used to locate the {@link RelyingPartyContext} associated with a given
     *            {@link ProfileRequestContext}
     */
    public void setRelyingPartyContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, RelyingPartyContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        relyingPartyContextLookupStrategy =
                Constraint.isNotNull(strategy, "RelyingPartyContext lookup strategy cannot be null");
    }

    /**
     * Set the strategy used to locate the {@link IdentifierGenerationStrategy} to use.
     * 
     * @param strategy lookup strategy
     */
    public void setIdentifierGeneratorLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, IdentifierGenerationStrategy> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        idGeneratorLookupStrategy =
                Constraint.isNotNull(strategy, "IdentifierGenerationStrategy lookup strategy cannot be null");
    }

    /**
     * Set the strategy used to locate the issuer value to use.
     * 
     * @param strategy lookup strategy
     */
    public void setIssuerLookupStrategy(@Nonnull final Function<ProfileRequestContext, String> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        issuerLookupStrategy = Constraint.isNotNull(strategy, "IssuerLookupStrategy lookup strategy cannot be null");
    }

    // Checkstyle: CyclomaticComplexity OFF
    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        if (!super.doPreExecute(profileRequestContext)) {
            return false;
        }
        RelyingPartyContext rpCtx = relyingPartyContextLookupStrategy.apply(profileRequestContext);
        if (rpCtx == null) {
            log.error("{} No relying party context associated with this profile request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_RELYING_PARTY_CTX);
            return false;
        }
        final ProfileConfiguration pc = rpCtx.getProfileConfig();
        if (pc != null && pc instanceof OIDCCoreProtocolConfiguration) {
            accessTokenLifetime = ((OIDCCoreProtocolConfiguration) pc).getAccessTokenLifetime();
        } else {
            log.error("{} No oidc profile configuration associated with this profile request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_RELYING_PARTY_CTX);
            return false;
        }
        tokenClaimsSet = getOidcResponseContext().getTokenClaimsSet();
        if (tokenClaimsSet != null && (!(tokenClaimsSet instanceof RefreshTokenClaimsSet)
                && !(tokenClaimsSet instanceof AuthorizeCodeClaimsSet))) {
            log.error("{} No tokn grant if of illegal type", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        } else if (tokenClaimsSet == null) {

            /**
             * Alternate path possible only when access token is to be provided by authz endpoint without authorization
             * code This is the case only with "token id_token" response type. Unusually complex initialization.
             */

            subjectCtx = profileRequestContext.getSubcontext(SubjectContext.class, false);
            if (subjectCtx == null) {
                log.error("{} No subject context", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
                return false;
            }
            idGenerator = idGeneratorLookupStrategy.apply(profileRequestContext);
            if (idGenerator == null) {
                log.error("{} No identifier generation strategy", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
                return false;
            }
            if (profileRequestContext.getInboundMessageContext() == null
                    || profileRequestContext.getInboundMessageContext().getMessage() == null || !(profileRequestContext
                            .getInboundMessageContext().getMessage() instanceof AuthenticationRequest)) {
                log.error("{} No authentication request avalailable", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
                return false;
            }
            authenticationRequest =
                    (AuthenticationRequest) profileRequestContext.getInboundMessageContext().getMessage();
        }
        return true;
    }
    // Checkstyle: CyclomaticComplexity ON

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        Date dateExp = new Date(System.currentTimeMillis() + accessTokenLifetime);
        ClaimsSet claims = null;
        ClaimsSet claimsUI = null;
        OIDCAuthenticationResponseTokenClaimsContext tokenClaimsCtx =
                tokenClaimsContextLookupStrategy.apply(profileRequestContext);
        if (tokenClaimsCtx != null) {
            claims = tokenClaimsCtx.getClaims();
            claimsUI = tokenClaimsCtx.getUserinfoClaims();
        }
        AccessTokenClaimsSet claimsSet;
        if (tokenClaimsSet != null) {
            // We may not use original claims as input for scope / delivery claims as they may have been reduced.
            claimsSet = new AccessTokenClaimsSet(tokenClaimsSet, getOidcResponseContext().getScope(), claims, claimsUI,
                    new Date(), dateExp);
        } else {
            JSONArray consentable = null;
            JSONArray consented = null;
            OIDCAuthenticationResponseConsentContext consentCtx =
                    consentContextLookupStrategy.apply(profileRequestContext);
            if (consentCtx != null) {
                consentable = consentCtx.getConsentableAttributes();
                consented = consentCtx.getConsentedAttributes();
            }
            // "token id_token" response type. Access token is not derived from Authorization code / Refresh token..
            claimsSet = new AccessTokenClaimsSet(idGenerator, authenticationRequest.getClientID(),
                    issuerLookupStrategy.apply(profileRequestContext), subjectCtx.getPrincipalName(),
                    getOidcResponseContext().getSubject(), getOidcResponseContext().getAcr(), new Date(), dateExp,
                    authenticationRequest.getNonce(), getOidcResponseContext().getAuthTime(),
                    getOidcResponseContext().getRedirectURI(), authenticationRequest.getScope(),
                    authenticationRequest.getClaims(), claims, claimsUI, consentable, consented);
        }
        try {
            getOidcResponseContext().setAccessToken(claimsSet.serialize(dataSealer), accessTokenLifetime / 1000);
            log.debug("{} Setting access token {} as {} to response context ", getLogPrefix(), claimsSet.serialize(),
                    getOidcResponseContext().getAccessToken());
        } catch (DataSealerException e) {
            log.error("{} Access Token generation failed {}", getLogPrefix(), e.getMessage());
            ActionSupport.buildEvent(profileRequestContext, EventIds.UNABLE_TO_ENCRYPT);
        }

    }

}