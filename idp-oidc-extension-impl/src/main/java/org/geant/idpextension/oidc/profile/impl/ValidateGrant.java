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

import java.text.ParseException;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.geant.idpextension.oidc.profile.OidcEventIds;
import org.geant.idpextension.oidc.storage.RevocationCache;
import org.geant.idpextension.oidc.storage.RevocationCacheContexts;
import org.geant.idpextension.oidc.token.support.AuthorizeCodeClaimsSet;
import org.geant.idpextension.oidc.token.support.RefreshTokenClaimsSet;
import org.geant.idpextension.oidc.token.support.TokenClaimsSet;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.storage.ReplayCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;

import net.shibboleth.idp.profile.IdPEventIds;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.utilities.java.support.annotation.ParameterName;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.security.DataSealer;
import net.shibboleth.utilities.java.support.security.DataSealerException;

/**
 * Action that validates authorization code / refresh token is a valid one. Code is valid if it is successfully
 * unwrapped, parsed as authz code/ refresh token , is not expired, is issued for the client and has not been used
 * before (authz code) or authz code used to produce it has not been revoked (refresh token). Validated code is stored
 * to response context retrievable as claims {@link OIDCAuthenticationResponseContext#getTokenClaimsSet()}.
 */
@SuppressWarnings("rawtypes")
public class ValidateGrant extends AbstractOIDCTokenResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(ValidateGrant.class);

    /** Data sealer for unwrapping authorization code. */
    @Nonnull
    private final DataSealer dataSealer;

    /** Message replay cache instance to use. */
    @NonnullAfterInit
    private ReplayCache replayCache;

    /** Message revocation cache instance to use. */
    @NonnullAfterInit
    private RevocationCache revocationCache;

    /**
     * Strategy used to locate the {@link RelyingPartyContext} associated with a given {@link ProfileRequestContext}.
     */
    @Nonnull
    private Function<ProfileRequestContext, RelyingPartyContext> relyingPartyContextLookupStrategy;

    /** The RelyingPartyContext to operate on. */
    @Nullable
    private RelyingPartyContext rpCtx;

    /**
     * Constructor.
     * 
     * @param sealer sealer to decrypt/hmac authorize code.
     */
    public ValidateGrant(@Nonnull @ParameterName(name = "sealer") final DataSealer sealer) {
        dataSealer = Constraint.isNotNull(sealer, "DataSealer cannot be null");
        relyingPartyContextLookupStrategy = new ChildContextLookup<>(RelyingPartyContext.class);
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
     * Set the replay cache instance to use.
     * 
     * @param cache The replayCache to set.
     */
    public void setReplayCache(@Nonnull final ReplayCache cache) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        replayCache = Constraint.isNotNull(cache, "ReplayCache cannot be null");
    }

    /**
     * Set the revocation cache instance to use.
     * 
     * @param cache The revocationCache to set.
     */
    public void setRevocationCache(@Nonnull final RevocationCache cache) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        revocationCache = Constraint.isNotNull(cache, "ReplayCache cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        Constraint.isNotNull(replayCache, "ReplayCache cannot be null");
        Constraint.isNotNull(revocationCache, "RevocationCache cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        rpCtx = relyingPartyContextLookupStrategy.apply(profileRequestContext);
        if (rpCtx == null) {
            log.debug("{} No relying party context associated with this profile request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_RELYING_PARTY_CTX);
            return false;
        }
        return super.doPreExecute(profileRequestContext);
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        AuthorizationGrant grant = getTokenRequest().getAuthorizationGrant();
        TokenClaimsSet tokenClaimsSet = null;
        if (grant.getType().equals(GrantType.AUTHORIZATION_CODE)) {
            AuthorizationCodeGrant codeGrant = (AuthorizationCodeGrant) grant;
            if (codeGrant.getAuthorizationCode() != null && codeGrant.getAuthorizationCode().getValue() != null) {
                try {
                    AuthorizeCodeClaimsSet authzCodeClaimsSet =
                            AuthorizeCodeClaimsSet.parse(codeGrant.getAuthorizationCode().getValue(), dataSealer);
                    log.debug("{} authz code unwrapped {}", getLogPrefix(), authzCodeClaimsSet.serialize());
                    if (!replayCache.check(getClass().getName(), authzCodeClaimsSet.getID(),
                            authzCodeClaimsSet.getExp().getTime())) {
                        log.error("{} Replay detected of authz code {}", getLogPrefix(), authzCodeClaimsSet.getID());
                        if (!revocationCache.revoke(RevocationCacheContexts.AUTHORIZATION_CODE,
                                authzCodeClaimsSet.getID())) {
                            log.error("{} Fatal error! Unable to set entry to revocation cache", getLogPrefix());
                        }
                        ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_GRANT);
                        return;
                    }
                    tokenClaimsSet = authzCodeClaimsSet;
                } catch (DataSealerException | ParseException e) {
                    log.error("{} Obtaining authz code failed {}", getLogPrefix(), e.getMessage());
                    ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_GRANT);
                    return;
                }
            }
        } else if (grant.getType().equals(GrantType.REFRESH_TOKEN)) {
            RefreshTokenGrant refreshTokentokenGrant = (RefreshTokenGrant) grant;
            if (refreshTokentokenGrant.getRefreshToken() != null
                    && refreshTokentokenGrant.getRefreshToken().getValue() != null) {
                try {
                    RefreshTokenClaimsSet refreshTokenClaimsSet = RefreshTokenClaimsSet
                            .parse(refreshTokentokenGrant.getRefreshToken().getValue(), dataSealer);
                    if (revocationCache.isRevoked(RevocationCacheContexts.AUTHORIZATION_CODE,
                            refreshTokenClaimsSet.getID())) {
                        log.error("{} authorize code {} and all derived tokens have been revoked", getLogPrefix(),
                                refreshTokenClaimsSet.getID());
                        ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_GRANT);
                        return;
                    }
                    tokenClaimsSet = refreshTokenClaimsSet;
                } catch (ParseException | DataSealerException e) {
                    log.error("{} Obtaining refresh token failed {}", getLogPrefix(), e.getMessage());
                    ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_GRANT);
                    return;
                }
            }
        }
        if (tokenClaimsSet == null) {
            log.error("{} Grant type not supported", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_GRANT);
            return;
        }
        if (tokenClaimsSet.isExpired()) {
            log.error("{} token exp is in the past {}", getLogPrefix(), tokenClaimsSet.getExp().getTime());
            ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_GRANT);
            return;
        }
        if (!tokenClaimsSet.getClientID().getValue().equals(rpCtx.getRelyingPartyId())) {
            log.error("{} token issued for client {}, expected value was {}", getLogPrefix(),
                    tokenClaimsSet.getClientID().getValue(), rpCtx.getRelyingPartyId());
            ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_GRANT);
            return;
        }
        getOidcResponseContext().setTokenClaimsSet(tokenClaimsSet);

    }
}
