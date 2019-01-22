/*
 * Licensed to the University Corporation for Advanced Internet Development,
 * Inc. (UCAID) under one or more contributor license agreements.  See the
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache
 * License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.geant.idpextension.oidc.token.support;

import org.testng.annotations.Test;
import net.shibboleth.utilities.java.support.security.DataSealerException;
import java.text.ParseException;
import org.testng.Assert;

/**
 * Tests for {@link RefreshTokenClaimsSetTest}
 */
public class RefreshTokenClaimsSetTest extends BaseTokenClaimsSetTest {

    private RefreshTokenClaimsSet rfClaimsSet;

    protected void init() {
        AuthorizeCodeClaimsSet acClaimsSet = new AuthorizeCodeClaimsSet(new MockIdStrategy(), clientID, issuer,
                userPrincipal, subject, acr, iat, exp, nonce, authTime, redirectURI, scope, idpSessionId, claims,
                dlClaims, dlClaimsID, dlClaimsUI, consentableClaims, consentedClaims);
        rfClaimsSet = new RefreshTokenClaimsSet(acClaimsSet, iat, exp);
    }

    @Test
    public void testSerialization() throws ParseException, DataSealerException {
        init();
        RefreshTokenClaimsSet rfClaimsSet2 = RefreshTokenClaimsSet.parse(rfClaimsSet.serialize());
        Assert.assertEquals(rfClaimsSet2.getACR(), acr.getValue());
        RefreshTokenClaimsSet rfClaimsSet3 = RefreshTokenClaimsSet.parse(rfClaimsSet2.serialize(sealer), sealer);
        Assert.assertEquals(rfClaimsSet3.getACR(), acr.getValue());
    }

    @Test(expectedExceptions = ParseException.class)
    public void testSerializationWrongType() throws ParseException {
        AuthorizeCodeClaimsSet accessnClaimsSet = new AuthorizeCodeClaimsSet(new MockIdStrategy(), clientID, issuer,
                userPrincipal, subject, acr, iat, exp, nonce, authTime, redirectURI, scope, idpSessionId, claims,
                dlClaims, null, dlClaimsUI, consentableClaims, consentedClaims);
        rfClaimsSet = RefreshTokenClaimsSet.parse(accessnClaimsSet.serialize());
    }

}