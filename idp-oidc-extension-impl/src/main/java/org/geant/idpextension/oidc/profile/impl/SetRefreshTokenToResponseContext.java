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
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Function;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;

import net.shibboleth.idp.profile.IdPEventIds;
import net.shibboleth.idp.profile.config.ProfileConfiguration;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import org.geant.idpextension.oidc.config.OIDCCoreProtocolConfiguration;
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

/**
 * Action that creates a Refresh Token, and sets it to work context
 * {@link OIDCAuthenticationResponseContext#geRefreshToken()} located under
 * {@link ProfileRequestContext#getOutboundMessageContext()}. The refresh_token is created only if the request contains
 * offline_access - scope.
 */
@SuppressWarnings("rawtypes")
public class SetRefreshTokenToResponseContext extends AbstractOIDCResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(SetRefreshTokenToResponseContext.class);

    /** Refresh Token lifetime. */
    private long refreshTokenLifetime;

    /** Data sealer for handling access token. */
    @Nonnull
    private final DataSealer dataSealer;

    /**
     * Strategy used to locate the {@link RelyingPartyContext} associated with a given {@link ProfileRequestContext}.
     */
    @Nonnull
    private Function<ProfileRequestContext, RelyingPartyContext> relyingPartyContextLookupStrategy;

    /** Authorize Code / Refresh Token the refresh token will be based on. */
    private TokenClaimsSet tokenClaimsSet;

    /**
     * Constructor.
     * 
     * @param sealer sealer to encrypt/hmac refresh token.
     */
    public SetRefreshTokenToResponseContext(@Nonnull @ParameterName(name = "sealer") final DataSealer sealer) {
        relyingPartyContextLookupStrategy = new ChildContextLookup<>(RelyingPartyContext.class);
        dataSealer = Constraint.isNotNull(sealer, "DataSealer cannot be null");
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

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        if (!super.doPreExecute(profileRequestContext)) {
            log.debug("{} pre-execute failed", getLogPrefix());
            return false;
        }
        if (!getOidcResponseContext().getScope().contains(OIDCScopeValue.OFFLINE_ACCESS)) {
            log.debug("{} no offline_access scope, nothing to do", getLogPrefix());
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
            refreshTokenLifetime = ((OIDCCoreProtocolConfiguration) pc).getRefreshTokenLifetime();
        } else {
            log.error("{} No oidc profile configuration associated with this profile request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_RELYING_PARTY_CTX);
            return false;
        }
        tokenClaimsSet = getOidcResponseContext().getTokenClaimsSet();
        if (tokenClaimsSet == null || (!(tokenClaimsSet instanceof RefreshTokenClaimsSet)
                && !(tokenClaimsSet instanceof AuthorizeCodeClaimsSet))) {
            log.error("{} No token to base refresh on", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        Date dateExp = new Date(System.currentTimeMillis() + refreshTokenLifetime);
        RefreshTokenClaimsSet claimsSet;
        claimsSet = new RefreshTokenClaimsSet(tokenClaimsSet, new Date(), dateExp);
        try {
            getOidcResponseContext().setRefreshToken(claimsSet.serialize(dataSealer));
            log.debug("{} Setting refresh token {} as {} to response context ", getLogPrefix(), claimsSet.serialize(),
                    getOidcResponseContext().getRefreshToken());
        } catch (DataSealerException e) {
            log.error("{} Refresh Token generation failed {}", getLogPrefix(), e.getMessage());
            ActionSupport.buildEvent(profileRequestContext, EventIds.UNABLE_TO_ENCRYPT);
        }

    }

}