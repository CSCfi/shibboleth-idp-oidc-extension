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
import org.geant.idpextension.oidc.profile.OidcEventIds;
import org.geant.idpextension.oidc.storage.RevocationCache;
import org.geant.idpextension.oidc.storage.RevocationCacheContexts;
import org.geant.idpextension.oidc.token.support.AccessTokenClaimsSet;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import net.shibboleth.utilities.java.support.annotation.ParameterName;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.security.DataSealer;
import net.shibboleth.utilities.java.support.security.DataSealerException;

/**
 * Action that validates access token is a valid one. Token is valid if it is successfully unwrapped, parsed as access
 * token, is not expired and authorize code it has been derived from has not been revoked. Validated token is stored to
 * response context retrievable as claims {@link OIDCAuthenticationResponseContext#getAccessTokenClaimsSet()}.
 * 
 */
@SuppressWarnings("rawtypes")
public class ValidateAccessToken extends AbstractOIDCUserInfoValidationResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(ValidateAccessToken.class);

    /** Data sealer for unwrapping authorization code. */
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
    public ValidateAccessToken(@Nonnull @ParameterName(name = "sealer") final DataSealer sealer) {
        dataSealer = Constraint.isNotNull(sealer, "DataSealer cannot be null");
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
        Constraint.isNotNull(revocationCache, "RevocationCache cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        AccessTokenClaimsSet accessTokenClaimsSet;
        try {
            accessTokenClaimsSet =
                    AccessTokenClaimsSet.parse(getUserInfoRequest().getAccessToken().getValue(), dataSealer);
            log.debug("{} access token unwrapped {}", getLogPrefix(), accessTokenClaimsSet.serialize());
        } catch (DataSealerException | ParseException e) {
            log.error("{} Obtaining access token failed {}", getLogPrefix(), e.getMessage());
            ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_GRANT);
            return;
        }
        if (accessTokenClaimsSet.isExpired()) {
            log.error("{} access token exp is in the past {}", getLogPrefix(), accessTokenClaimsSet.getExp().getTime());
            ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_GRANT);
            return;
        }
        if (revocationCache.isRevoked(RevocationCacheContexts.AUTHORIZATION_CODE, accessTokenClaimsSet.getID())) {
            log.error("{} authorize code {} and all derived tokens have been revoked", getLogPrefix(),
                    accessTokenClaimsSet.getID());
            ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_GRANT);
            return;
        }
        log.debug("{} access token {} validated", getLogPrefix(), accessTokenClaimsSet.getID());
        getOidcResponseContext().setTokenClaimsSet(accessTokenClaimsSet);
        return;

    }
}