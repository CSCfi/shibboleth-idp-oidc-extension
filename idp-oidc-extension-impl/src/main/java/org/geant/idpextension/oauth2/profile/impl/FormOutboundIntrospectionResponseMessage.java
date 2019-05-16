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

package org.geant.idpextension.oauth2.profile.impl;

import java.text.ParseException;

import javax.annotation.Nonnull;

import org.geant.idpextension.oidc.profile.impl.AbstractOIDCRequestAction;
import org.geant.idpextension.oidc.storage.RevocationCache;
import org.geant.idpextension.oidc.storage.RevocationCacheContexts;
import org.geant.idpextension.oidc.token.support.AccessTokenClaimsSet;
import org.geant.idpextension.oidc.token.support.RefreshTokenClaimsSet;
import org.geant.idpextension.oidc.token.support.TokenClaimsSet;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import net.shibboleth.utilities.java.support.annotation.ParameterName;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.security.DataSealer;
import net.shibboleth.utilities.java.support.security.DataSealerException;

/**
 * Action that forms outbound token introspection success message. Formed message is set to
 * {@link ProfileRequestContext#getOutboundMessageContext()}.
 */
@SuppressWarnings("rawtypes")
public class FormOutboundIntrospectionResponseMessage extends AbstractOIDCRequestAction<TokenIntrospectionRequest> {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(FormOutboundIntrospectionResponseMessage.class);

    /** Data sealer for unwrapping token. */
    @Nonnull
    private final DataSealer dataSealer;

    /** Message revocation cache instance to use. */
    @NonnullAfterInit
    private RevocationCache revocationCache;

    /**
     * Constructor.
     * 
     * @param sealer sealer to decrypt/hmac access token.
     */
    public FormOutboundIntrospectionResponseMessage(@Nonnull @ParameterName(name = "sealer") final DataSealer sealer) {
        dataSealer = Constraint.isNotNull(sealer, "DataSealer cannot be null");
    }

    /**
     * Set the revocation cache instance to use.
     * 
     * @param cache The revocationCache to set.
     */
    public void setRevocationCache(@Nonnull final RevocationCache cache) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        revocationCache = Constraint.isNotNull(cache, "RevocationCache cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        Constraint.isNotNull(revocationCache, "RevocationCache cannot be null");
    }

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        TokenClaimsSet tokenClaimsSet = null;
        AccessTokenType tokenType = null;
        log.debug("{} token to introspect {}", getLogPrefix(), getRequest().getToken().getValue());
        try {
            tokenClaimsSet = AccessTokenClaimsSet.parse(getRequest().getToken().getValue(), dataSealer);
            tokenType = AccessTokenType.BEARER;
            log.debug("{} access token unwrapped {}", getLogPrefix(), tokenClaimsSet.serialize());
        } catch (DataSealerException | ParseException e) {
            log.debug("{} token to introspect is not valid access token", getLogPrefix());
        }
        if (tokenClaimsSet == null) {
            try {
                tokenClaimsSet = RefreshTokenClaimsSet.parse(getRequest().getToken().getValue(), dataSealer);
                log.debug("{} refresh token unwrapped {}", getLogPrefix(), tokenClaimsSet.serialize());
            } catch (DataSealerException | ParseException e) {
                log.debug("{} token to introspect is not valid refresh token", getLogPrefix());
            }
        }
        if (tokenClaimsSet == null) {
            log.debug("{} unable to decode token", getLogPrefix());
            profileRequestContext.getOutboundMessageContext()
                    .setMessage(new TokenIntrospectionSuccessResponse.Builder(false).build());
            return;
        }
        if (revocationCache.isRevoked(RevocationCacheContexts.AUTHORIZATION_CODE, tokenClaimsSet.getID())) {
            log.debug("{} tokens derived from authorization code {} are all revoked", getLogPrefix(),
                    tokenClaimsSet.getID());
            profileRequestContext.getOutboundMessageContext()
                    .setMessage(new TokenIntrospectionSuccessResponse.Builder(false).build());
            return;
        }
        if (tokenClaimsSet.isExpired()) {
            log.debug("{} tokens is expired", getLogPrefix(), tokenClaimsSet.getID());
            profileRequestContext.getOutboundMessageContext()
                    .setMessage(new TokenIntrospectionSuccessResponse.Builder(false).build());
            return;
        }
        // TODO: We are not returning audience field at all. Audience would be useful for example in cases where
        // Resource Server
        // uses introspection to verify it is on the audience list before accepting the request.
        // Audience information is not currently carried in tokens.
        profileRequestContext.getOutboundMessageContext()
                .setMessage(new TokenIntrospectionSuccessResponse.Builder(true).scope(tokenClaimsSet.getScope())
                        .clientID(tokenClaimsSet.getClientID()).username(tokenClaimsSet.getPrincipal())
                        .tokenType(tokenType).expirationTime(tokenClaimsSet.getClaimsSet().getExpirationTime())
                        .issueTime(tokenClaimsSet.getClaimsSet().getIssueTime())
                        .subject(new Subject(tokenClaimsSet.getClaimsSet().getSubject()))
                        .issuer(new Issuer(tokenClaimsSet.getClaimsSet().getIssuer())).build());
    }
}