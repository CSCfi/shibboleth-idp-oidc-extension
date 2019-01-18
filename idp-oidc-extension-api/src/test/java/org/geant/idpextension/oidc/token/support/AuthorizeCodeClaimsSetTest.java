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
import net.shibboleth.utilities.java.support.security.IdentifierGenerationStrategy;
import java.text.ParseException;
import org.testng.Assert;

/**
 * Tests for {@link AuthorizeCodeClaimsSet}
 */
public class AuthorizeCodeClaimsSetTest extends BaseTokenClaimsSetTest {

    private AuthorizeCodeClaimsSet acClaimsSet;

    protected void init() {
        acClaimsSet = new AuthorizeCodeClaimsSet(new MockIdStrategy(), clientID, issuer, userPrincipal, subject, acr,
                iat, exp, nonce, authTime, redirectURI, scope, idpSessionId, claims, dlClaims, dlClaimsID, dlClaimsUI,
                consentableClaims, consentedClaims);
    }

    @Test
    public void testSerialization() throws ParseException, DataSealerException {
        init();
        AuthorizeCodeClaimsSet acClaimsSet2 = AuthorizeCodeClaimsSet.parse(acClaimsSet.serialize());
        Assert.assertEquals(acClaimsSet2.getACR(), acr.getValue());
        AuthorizeCodeClaimsSet acClaimsSet3 = AuthorizeCodeClaimsSet.parse(acClaimsSet2.serialize(sealer), sealer);
        Assert.assertEquals(acClaimsSet3.getACR(), acr.getValue());
    }

    @Test(expectedExceptions = ParseException.class)
    public void testSerializationWrongType() throws ParseException {
        AccessTokenClaimsSet accessnClaimsSet = new AccessTokenClaimsSet(new MockIdStrategy(), clientID, issuer,
                userPrincipal, subject, acr, iat, exp, nonce, authTime, redirectURI, scope, idpSessionId, claims,
                dlClaims, dlClaimsUI, consentableClaims, consentedClaims);
        acClaimsSet = AuthorizeCodeClaimsSet.parse(accessnClaimsSet.serialize());
    }

    public class MockIdStrategy implements IdentifierGenerationStrategy {

        @Override
        public String generateIdentifier() {
            return "x";
        }

        @Override
        public String generateIdentifier(boolean xmlSafe) {
            // TODO Auto-generated method stub
            return null;
        }

    }

}