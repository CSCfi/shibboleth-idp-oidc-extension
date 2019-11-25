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
import com.nimbusds.oauth2.sdk.TokenRevocationRequest;
import net.shibboleth.utilities.java.support.annotation.ParameterName;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.security.DataSealer;
import net.shibboleth.utilities.java.support.security.DataSealerException;

/**
 * Action revokes all tokens based on authorization grant of the token to be revoked. If token is access token or
 * refresh token, the id of the authorization code they are derived from is marked as revoked and so invalidating all
 * tokens based on it.
 * 
 * If the token to be revoked is not decodable or the revocation fails, the actions still returns success status.
 */
@SuppressWarnings("rawtypes")
public class RevokeToken extends AbstractOIDCRequestAction<TokenRevocationRequest> {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(RevokeToken.class);

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
    public RevokeToken(@Nonnull @ParameterName(name = "sealer") final DataSealer sealer) {
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
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        TokenClaimsSet tokenClaimsSet = null;
        log.debug("{} token to revoke {}", getLogPrefix(), getRequest().getToken().getValue());
        try {
            tokenClaimsSet = AccessTokenClaimsSet.parse(getRequest().getToken().getValue(), dataSealer);
            log.debug("{} access token unwrapped {}", getLogPrefix(), tokenClaimsSet.serialize());
        } catch (DataSealerException | ParseException e) {
            log.debug("{} token to revoke is not valid access token", getLogPrefix());
        }
        if (tokenClaimsSet == null) {
            try {
                tokenClaimsSet = RefreshTokenClaimsSet.parse(getRequest().getToken().getValue(), dataSealer);
                log.debug("{} refresh token unwrapped {}", getLogPrefix(), tokenClaimsSet.serialize());
            } catch (DataSealerException | ParseException e) {
                log.debug("{} token to revoke is not valid refresh token", getLogPrefix());
            }
        }
        if (tokenClaimsSet == null) {
            log.debug("{} unable to decode token to revoke, nothing to do", getLogPrefix());
            return;
        }
        if (revocationCache.revoke(RevocationCacheContexts.AUTHORIZATION_CODE, tokenClaimsSet.getID())) {
            log.debug("{} revoked all tokens based on authorize code {}", getLogPrefix(), tokenClaimsSet.getID());
        } else {
            log.warn("{} failed to revoke tokens based on authorize code {}", getLogPrefix(), tokenClaimsSet.getID());
        }
    }
}