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