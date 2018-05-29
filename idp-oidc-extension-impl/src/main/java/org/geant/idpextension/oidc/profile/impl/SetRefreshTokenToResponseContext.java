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
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Function;
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
 * {@link ProfileRequestContext#getOutboundMessageContext()}.
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
            log.error("{} pre-execute failed", getLogPrefix());
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