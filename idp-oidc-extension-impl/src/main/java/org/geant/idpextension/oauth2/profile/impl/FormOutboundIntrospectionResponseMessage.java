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