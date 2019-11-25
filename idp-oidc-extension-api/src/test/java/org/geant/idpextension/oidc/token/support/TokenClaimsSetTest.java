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