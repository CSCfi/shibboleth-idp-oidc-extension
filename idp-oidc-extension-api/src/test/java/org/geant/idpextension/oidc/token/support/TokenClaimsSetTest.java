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

package org.geant.idpextension.oidc.token.support;

import org.testng.annotations.Test;
import org.testng.Assert;

/**
 * Tests for {@link TokenClaimsSet}
 */
public class TokenClaimsSetTest extends BaseTokenClaimsSetTest {

    private TokenClaimsSet tokenClaimsSet;

    private String tokenType = "myType";

    private String tokenID = "1";

    protected void init() {
        tokenClaimsSet = new TokenClaimsSet(tokenType, tokenID, clientID, issuer, userPrincipal, subject, acr, iat, exp,
                nonce, authTime, redirectURI, scope, claims, dlClaims, dlClaimsID, dlClaimsUI, consentableClaims,
                consentedClaims, codeChallenge);
    }

    @Test
    public void testGetters() {
        init();
        Assert.assertEquals(tokenClaimsSet.getACR(), acr.getValue());
        Assert.assertEquals(tokenClaimsSet.getID(), tokenID);
        Assert.assertEquals(tokenClaimsSet.getPrincipal(), userPrincipal);
        Assert.assertEquals(tokenClaimsSet.isExpired(), false);
        Assert.assertEquals(tokenClaimsSet.getAuthenticationTime().getTime(), authTime.getTime());
        Assert.assertTrue(tokenClaimsSet.getClaimsRequest().getIDTokenClaimNames(false).contains("email"));
        Assert.assertEquals(tokenClaimsSet.getDeliveryClaims().getClaim("tokenDelivery"), "value");
        Assert.assertEquals(tokenClaimsSet.getIDTokenDeliveryClaims().getClaim("tokenToIdtokenDeliveryClaim"), "value");
        Assert.assertEquals(tokenClaimsSet.getUserinfoDeliveryClaims().getClaim("tokenToUserInfotokenDeliveryClaim"),
                "value");
        Assert.assertEquals(tokenClaimsSet.getClientID(), clientID);
        Assert.assertTrue(tokenClaimsSet.getConsentableClaims().contains("consentableClaim"));
        Assert.assertTrue(tokenClaimsSet.getConsentedClaims().contains("consentedClaim"));
        Assert.assertEquals(tokenClaimsSet.getExp().getTime(), exp.getTime());
        Assert.assertEquals(tokenClaimsSet.getNonce(), nonce);
        Assert.assertEquals(tokenClaimsSet.getRedirectURI(), redirectURI);
        Assert.assertEquals(tokenClaimsSet.getScope(), scope);
        Assert.assertEquals(tokenClaimsSet.getCodeChallenge(), codeChallenge);
    }

    @Test
    public void testNullGetters() {
        tokenClaimsSet = new TokenClaimsSet(tokenType, tokenID, clientID, issuer, userPrincipal, subject, null, iat,
                exp, null, authTime, redirectURI, scope, null, null, null, null, null, null, null);
        Assert.assertNull(tokenClaimsSet.getACR());
        Assert.assertNull(tokenClaimsSet.getClaimsRequest());
        Assert.assertNull(tokenClaimsSet.getDeliveryClaims());
        Assert.assertNull(tokenClaimsSet.getIDTokenDeliveryClaims());
        Assert.assertNull(tokenClaimsSet.getUserinfoDeliveryClaims());
        Assert.assertNull(tokenClaimsSet.getConsentableClaims());
        Assert.assertNull(tokenClaimsSet.getConsentedClaims());
        Assert.assertNull(tokenClaimsSet.getNonce());
    }

}