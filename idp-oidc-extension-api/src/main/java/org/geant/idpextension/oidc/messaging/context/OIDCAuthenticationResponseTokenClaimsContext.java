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

package org.geant.idpextension.oidc.messaging.context;

import javax.annotation.Nonnull;

import org.geant.idpextension.oidc.token.support.TokenDeliveryClaimsClaimsSet;
import org.opensaml.messaging.context.BaseContext;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;

/**
 * Subcontext carrying information to form token and userinfo responses for relying party. This context appears as a
 * subcontext of the {@link OIDCAuthenticationResponseContext}.
 * 
 * This context is populated by authentication endpoint if there are attributes unresolvable in token/userinfo endpoints
 * that need to be carried in token. Token and userinfo endpoints populate the same context with carried claims to be
 * returned in response.
 */
public class OIDCAuthenticationResponseTokenClaimsContext extends BaseContext {

    /** Claims for id token and userinfo endpoint. */
    @Nonnull
    private ClaimsSet claims;

    /** Claims for id token only. */
    @Nonnull
    private ClaimsSet idtokenClaims;

    /** Claims for userinfo only. */
    @Nonnull
    private ClaimsSet userinfoClaims;

    /**
     * Constructor.
     */
    public OIDCAuthenticationResponseTokenClaimsContext() {
        claims = new TokenDeliveryClaimsClaimsSet();
        idtokenClaims = new TokenDeliveryClaimsClaimsSet();
        userinfoClaims = new TokenDeliveryClaimsClaimsSet();
    }

    /**
     * Get claims for id token and userinfo endpoint.
     * 
     * @return claims for id token and userinfo endpoint.
     */
    @Nonnull
    public ClaimsSet getClaims() {
        return claims;
    }

    /**
     * Get claims for id token only.
     * 
     * @return claims for id token only
     */
    @Nonnull
    public ClaimsSet getIdtokenClaims() {
        return idtokenClaims;
    }

    /**
     * Get claims for userinfo only.
     * 
     * @return claims for userinfo only
     */
    @Nonnull
    public ClaimsSet getUserinfoClaims() {
        return userinfoClaims;
    }

}