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

import java.text.ParseException;
import javax.annotation.Nonnull;

import org.geant.idpextension.oidc.profile.OidcEventIds;
import org.geant.idpextension.oidc.storage.RevocationCache;
import org.geant.idpextension.oidc.storage.RevocationCacheContexts;
import org.geant.idpextension.oidc.token.support.AuthorizeCodeClaimsSet;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.storage.ReplayCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.GrantType;
import net.shibboleth.utilities.java.support.annotation.ParameterName;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.security.DataSealer;
import net.shibboleth.utilities.java.support.security.DataSealerException;

/**
 * Action that validates authorization code is a valid one. Code is valid if it is successfully unwrapped, parsed as
 * authz code, is not expired and has not been used before. Validated code is stored to response context retrievable as
 * claims {@link OIDCAuthenticationResponseContext#getAuthorizationCodeClaimsSet()}.
 * 
 */
@SuppressWarnings("rawtypes")
public class ValidateAuthorizeCode extends AbstractOIDCTokenResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(ValidateAuthorizeCode.class);

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
     * Constructor.
     */
    public ValidateAuthorizeCode(@Nonnull @ParameterName(name = "sealer") final DataSealer sealer) {
        dataSealer = Constraint.isNotNull(sealer, "DataSealer cannot be null");
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
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        AuthorizationGrant grant = getTokenRequest().getAuthorizationGrant();
        if (grant.getType().equals(GrantType.AUTHORIZATION_CODE)) {
            AuthorizationCodeGrant codeGrant = (AuthorizationCodeGrant) grant;
            if (codeGrant.getAuthorizationCode() != null && codeGrant.getAuthorizationCode().getValue() != null) {
                try {
                    AuthorizeCodeClaimsSet authzCodeClaimsSet =
                            AuthorizeCodeClaimsSet.parse(codeGrant.getAuthorizationCode().getValue(), dataSealer);
                    log.debug("{} authz code unwrapped {}", getLogPrefix(), authzCodeClaimsSet.serialize());
                    if (authzCodeClaimsSet.isExpired()) {
                        log.error("{} Authorization code exp is in the past {}", getLogPrefix(),
                                authzCodeClaimsSet.getExp().getTime());
                        ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_GRANT);
                        return;
                    }
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
                    getOidcResponseContext().setTokenClaimsSet(authzCodeClaimsSet);
                    return;
                } catch (DataSealerException | ParseException e) {
                    log.error("{} Obtaining auhz code failed {}", getLogPrefix(), e.getMessage());
                    ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_GRANT);
                    return;
                }
            }
        }
        log.error("{} unable to obtain authz code", getLogPrefix());
        ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_GRANT);

    }
}