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

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Function;
import com.nimbusds.jose.util.Base64URL;

import net.shibboleth.idp.profile.IdPEventIds;
import net.shibboleth.idp.profile.config.ProfileConfiguration;
import net.shibboleth.idp.profile.context.RelyingPartyContext;

import org.geant.idpextension.oidc.config.OIDCCoreProtocolConfiguration;
import org.geant.idpextension.oidc.profile.context.navigate.DefaultRequestCodeVerifierLookupFunction;
import org.geant.idpextension.oidc.token.support.AuthorizeCodeClaimsSet;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;

import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Action performs PKCE (https://oauth.net/2/pkce/) validation. If authentication request contains code_challenge
 * parameter, token request when passing authorization code as grant must include code_verifier parameter. Profile
 * configuration may used to force using PKCE, by default it is optional. Profile configuration may be used to allow
 * plain PKCE, by default it is not allowed.
 */
@SuppressWarnings("rawtypes")
public class ValidatePKCE extends AbstractOIDCResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(ValidatePKCE.class);

    /**
     * Strategy used to locate the {@link RelyingPartyContext} associated with a given {@link ProfileRequestContext}.
     */
    @Nonnull
    private Function<ProfileRequestContext, RelyingPartyContext> relyingPartyContextLookupStrategy;

    /**
     * Strategy used to locate the PKCE Code Verifier value.
     */
    @Nonnull
    private Function<ProfileRequestContext, String> codeVerifierLookupStrategy;

    /** Whether PKCE is mandatory. */
    @Nonnull
    private boolean forcePKCE;

    /** Whether plain PKCE is allowed. */
    @Nonnull
    private boolean plainPKCE;

    /** PKCE code challenge. */
    @Nullable
    private String codeChallenge;

    /** PKCE code verifier. */
    @Nullable
    private String codeVerifier;

    /**
     * Constructor.
     */
    public ValidatePKCE() {
        relyingPartyContextLookupStrategy = new ChildContextLookup<>(RelyingPartyContext.class);
        codeVerifierLookupStrategy = new DefaultRequestCodeVerifierLookupFunction();
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
     * Set the strategy used to locate the Code Verifier value.
     * 
     * @param strategy strategy used to locate the Code Verifier value
     */
    public void setCodeVerifierLookupStrategy(@Nonnull final Function<ProfileRequestContext, String> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        codeVerifierLookupStrategy = Constraint.isNotNull(strategy, "CodeVerifier lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        if (!super.doPreExecute(profileRequestContext)) {
            return false;
        }
        if (getOidcResponseContext().getTokenClaimsSet() == null) {
            log.error("{} No validated token claims set available, missing a prior action", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        if (!AuthorizeCodeClaimsSet.VALUE_TYPE_AC.equals(getOidcResponseContext().getTokenClaimsSet().getType())) {
            log.debug("{} No authorization code presented, PKCE not applied, nothing to do", getLogPrefix());
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
            forcePKCE = ((OIDCCoreProtocolConfiguration) pc).getForcePKCE();
            plainPKCE = ((OIDCCoreProtocolConfiguration) pc).getAllowPKCEPlain();
        } else {
            log.error("{} No oidc profile configuration associated with this profile request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_RELYING_PARTY_CTX);
            return false;
        }
        codeChallenge = getOidcResponseContext().getTokenClaimsSet().getCodeChallenge();
        // Checks whether PKCE needs to be validated.
        if ((codeChallenge == null || codeChallenge.isEmpty()) && !forcePKCE) {
            log.debug("{} No PKCE code challenge in request, nothing to do", getLogPrefix());
            return false;
        }
        codeVerifier = codeVerifierLookupStrategy.apply(profileRequestContext);
        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        if (codeChallenge == null || codeChallenge.isEmpty()) {
            // To save one action we have this late verification of the authentication request for PKCE parameter.
            log.error(
                    "{} No PKCE code challenge presented in authentication request even though required to access token endpoint",
                    getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
            return;
        }
        if (codeVerifier == null || codeVerifier.isEmpty()) {
            log.error("{} No PKCE code verifier for code challenge presented in token request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
            return;
        }
        if (codeChallenge.startsWith("plain")) {
            if (!plainPKCE) {
                log.error("{} Plain PKCE code challenge method not allowed", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
            }
            String codeChallengeValue = codeChallenge.substring("plain".length());
            if (!codeVerifier.equals(codeChallengeValue)) {
                log.error("{} PKCE code challenge {} not matching code verifier {}", getLogPrefix(), codeChallengeValue,
                        codeVerifier);
                ActionSupport.buildEvent(profileRequestContext, EventIds.MESSAGE_AUTHN_ERROR);
            }
        } else if (codeChallenge.startsWith("S256")) {
            String codeChallengeValue = codeChallenge.substring("S256".length());
            MessageDigest md = null;
            try {
                md = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                log.error("{} PKCE S256 code challenge verification requires SHA-256", getLogPrefix(),
                        codeChallengeValue, codeVerifier);
                ActionSupport.buildEvent(profileRequestContext, EventIds.MESSAGE_AUTHN_ERROR);
            }
            byte[] hash = md.digest(codeVerifier.getBytes(Charset.forName("utf-8")));
            String codeChallengeComparisonValue = Base64URL.encode(hash).toString();
            if (!codeChallengeComparisonValue.equals(codeChallengeValue)) {
                log.error("{} PKCE code challenge {} not matching code verifier {}({})", getLogPrefix(),
                        codeChallengeValue, codeVerifier, codeChallengeComparisonValue);
                ActionSupport.buildEvent(profileRequestContext, EventIds.MESSAGE_AUTHN_ERROR);
            }
        } else {
            log.error("{} Unknown code challenge method", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
        }
    }

}