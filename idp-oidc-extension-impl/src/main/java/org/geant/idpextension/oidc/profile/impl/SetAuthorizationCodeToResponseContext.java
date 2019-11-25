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
import org.geant.idpextension.oidc.profile.context.navigate.DefaultRequestCodeChallengeLookupFunction;
import org.geant.idpextension.oidc.profile.context.navigate.DefaultRequestCodeChallengeMethodLookupFunction;
import org.geant.idpextension.oidc.profile.context.navigate.DefaultRequestNonceLookupFunction;
import org.geant.idpextension.oidc.profile.context.navigate.OIDCAuthenticationResponseContextLookupFunction;
import org.geant.idpextension.oidc.token.support.AuthorizeCodeClaimsSet;
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
 * Action that creates a Authorization Code, and sets it to work context
 * {@link OIDCAuthenticationResponseContext#getAuthorizationCode()} located under
 * {@link ProfileRequestContext#getOutboundMessageContext()}.
 *
 */
@SuppressWarnings("rawtypes")
public class SetAuthorizationCodeToResponseContext extends AbstractOIDCAuthenticationResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(SetAuthorizationCodeToResponseContext.class);

    /** Strategy used to obtain the response issuer value. */
    @Nonnull
    private Function<ProfileRequestContext, String> issuerLookupStrategy;

    /** Subject context. */
    private SubjectContext subjectCtx;

    /** Authorization code lifetime. */
    private long authCodeLifetime;

    /** Data sealer for handling authorization code. */
    @Nonnull
    private final DataSealer dataSealer;

    /** The generator to use. */
    @Nullable
    private IdentifierGenerationStrategy idGenerator;

    /** Strategy used to locate the {@link IdentifierGenerationStrategy} to use. */
    @Nonnull
    private Function<ProfileRequestContext, IdentifierGenerationStrategy> idGeneratorLookupStrategy;

    /**
     * Strategy used to locate the {@link RelyingPartyContext} associated with a given {@link ProfileRequestContext}.
     */
    @Nonnull
    private Function<ProfileRequestContext, RelyingPartyContext> relyingPartyContextLookupStrategy;

    /** Strategy used to locate the {@link OIDCAuthenticationResponseTokenClaimsContext}. */
    @Nonnull
    private Function<ProfileRequestContext, OIDCAuthenticationResponseTokenClaimsContext> tokenClaimsContextLookupStrategy;

    /** Strategy used to locate the {@link OIDCAuthenticationResponseConsentContext}. */
    @Nonnull
    private Function<ProfileRequestContext, OIDCAuthenticationResponseConsentContext> consentContextLookupStrategy;

    /** Strategy used to locate the code challenge. */
    @Nonnull
    private Function<ProfileRequestContext, String> codeChallengeLookupStrategy;
    
    /** Strategy used to locate the code challenge method. */
    @Nonnull
    private Function<ProfileRequestContext, String> codeChallengeMethodLookupStrategy;
    
    /** Code challenge and the code challenge method stored to authz code.*/
    @Nullable
    private String codeChallenge;

    /**
     * Constructor.
     * 
     * @param sealer sealer to encrypt/hmac authz code.
     */
    public SetAuthorizationCodeToResponseContext(@Nonnull @ParameterName(name = "sealer") final DataSealer sealer) {
        codeChallengeLookupStrategy = new DefaultRequestCodeChallengeLookupFunction();
        codeChallengeMethodLookupStrategy = new DefaultRequestCodeChallengeMethodLookupFunction();
        tokenClaimsContextLookupStrategy =
                Functions.compose(new ChildContextLookup<>(OIDCAuthenticationResponseTokenClaimsContext.class),
                        new OIDCAuthenticationResponseContextLookupFunction());
        consentContextLookupStrategy =
                Functions.compose(new ChildContextLookup<>(OIDCAuthenticationResponseConsentContext.class),
                        new OIDCAuthenticationResponseContextLookupFunction());
        relyingPartyContextLookupStrategy = new ChildContextLookup<>(RelyingPartyContext.class);
        issuerLookupStrategy = new ResponderIdLookupFunction();
        dataSealer = Constraint.isNotNull(sealer, "DataSealer cannot be null");
        idGeneratorLookupStrategy = new Function<ProfileRequestContext, IdentifierGenerationStrategy>() {
            public IdentifierGenerationStrategy apply(ProfileRequestContext input) {
                return new SecureRandomIdentifierGenerationStrategy();
            }
        };
    }

    /**
     * Set the strategy used to locate the Code Challenge of the request.
     * 
     * @param strategy lookup strategy
     */
    public void setCodeChallengeLookupStrategy(@Nonnull final Function<ProfileRequestContext, String> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        codeChallengeLookupStrategy =
                Constraint.isNotNull(strategy, "CodeChallengeLookupStrategy lookup strategy cannot be null");
    }
    
    /**
     * Set the strategy used to locate the Code Challenge Method of the request.
     * 
     * @param strategy lookup strategy
     */
    public void setCodeChallengeMethodLookupStrategy(@Nonnull final Function<ProfileRequestContext, String> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        codeChallengeMethodLookupStrategy =
                Constraint.isNotNull(strategy, "CodeChallengeMethodLookupStrategy lookup strategy cannot be null");
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
                "OIDCAuthenticationResponseTokenClaimsContext lookup strategy cannot be null");
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

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        subjectCtx = profileRequestContext.getSubcontext(SubjectContext.class, false);
        if (subjectCtx == null) {
            log.error("{} No subject context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        idGenerator = idGeneratorLookupStrategy.apply(profileRequestContext);
        if (idGenerator == null) {
            log.debug("{} No identifier generation strategy", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        RelyingPartyContext rpCtx = relyingPartyContextLookupStrategy.apply(profileRequestContext);
        if (rpCtx == null) {
            log.debug("{} No relying party context associated with this profile request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_RELYING_PARTY_CTX);
            return false;
        }
        final ProfileConfiguration pc = rpCtx.getProfileConfig();
        if (pc != null && pc instanceof OIDCCoreProtocolConfiguration) {
            authCodeLifetime = ((OIDCCoreProtocolConfiguration) pc).getAuthorizeCodeLifetime();
        } else {
            log.debug("{} No oidc profile configuration associated with this profile request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_RELYING_PARTY_CTX);
            return false;
        }
        codeChallenge = codeChallengeLookupStrategy.apply(profileRequestContext);
        if (codeChallenge != null && !codeChallenge.isEmpty()) {
            // Preappend the PKCE challenge with method as we need to store both method and challenge. Options for method are
            // "plain" and "S256"
            String codeChallengeMethod = codeChallengeMethodLookupStrategy.apply(profileRequestContext);
            // Default method is "plain"
            codeChallenge = (codeChallengeMethod != null ? codeChallengeMethod : "plain") + codeChallenge;
        }
        return super.doPreExecute(profileRequestContext);
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        JSONArray consentable = null;
        JSONArray consented = null;
        OIDCAuthenticationResponseConsentContext consentCtx = consentContextLookupStrategy.apply(profileRequestContext);
        if (consentCtx != null) {
            consentable = consentCtx.getConsentableAttributes();
            consented = consentCtx.getConsentedAttributes();
        }
        ClaimsSet claims = null;
        ClaimsSet claimsID = null;
        ClaimsSet claimsUI = null;
        OIDCAuthenticationResponseTokenClaimsContext tokenClaimsCtx =
                tokenClaimsContextLookupStrategy.apply(profileRequestContext);
        if (tokenClaimsCtx != null) {
            claims = tokenClaimsCtx.getClaims();
            claimsID = tokenClaimsCtx.getIdtokenClaims();
            claimsUI = tokenClaimsCtx.getUserinfoClaims();
        }
        Date dateExp = new Date(System.currentTimeMillis() + authCodeLifetime);
        AuthorizeCodeClaimsSet claimsSet = new AuthorizeCodeClaimsSet.Builder(idGenerator,
                getAuthenticationRequest().getClientID(), issuerLookupStrategy.apply(profileRequestContext),
                subjectCtx.getPrincipalName(), getOidcResponseContext().getSubject(), new Date(), dateExp,
                getOidcResponseContext().getAuthTime(), getOidcResponseContext().getRedirectURI(),
                getOidcResponseContext().getScope()).setACR(getOidcResponseContext().getAcr())
                        .setNonce(new DefaultRequestNonceLookupFunction().apply(profileRequestContext))
                        .setClaims(getOidcResponseContext().getRequestedClaims()).setDlClaims(claims)
                        .setDlClaimsID(claimsID).setDlClaimsUI(claimsUI).setConsentableClaims(consentable)
                        .setConsentedClaims(consented)
                        .setCodeChallenge(codeChallenge).build();
        // We set token claims set to response context for possible access token generation.
        getOidcResponseContext().setTokenClaimsSet(claimsSet);
        try {
            getOidcResponseContext().setAuthorizationCode(claimsSet.serialize(dataSealer));
            log.debug("{} Setting authz code {} as {} to response context ", getLogPrefix(), claimsSet.serialize(),
                    getOidcResponseContext().getAuthorizationCode());
        } catch (DataSealerException e) {
            log.error("{} Authorization Code generation failed {}", getLogPrefix(), e.getMessage());
            ActionSupport.buildEvent(profileRequestContext, EventIds.UNABLE_TO_ENCRYPT);
        }

    }

}