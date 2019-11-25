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

import net.shibboleth.utilities.java.support.security.DataSealerException;
import net.shibboleth.utilities.java.support.security.SecureRandomIdentifierGenerationStrategy;
import java.text.ParseException;

import org.testng.Assert;

/**
 * Tests for {@link AccessTokenClaimsSetTest}
 */
public class AccessTokenClaimsSetTest extends BaseTokenClaimsSetTest {

    private AccessTokenClaimsSet atClaimsSet;

    protected void init() {
        atClaimsSet = new AccessTokenClaimsSet.Builder(new SecureRandomIdentifierGenerationStrategy(), clientID, issuer,
                userPrincipal, subject, iat, exp, authTime, redirectURI, scope).setACR(acr).build();

    }

    protected void init2() {
        AuthorizeCodeClaimsSet acClaimsSet =
                new AuthorizeCodeClaimsSet.Builder(new SecureRandomIdentifierGenerationStrategy(), clientID, issuer,
                        userPrincipal, subject, iat, exp, authTime, redirectURI, scope).setACR(acr).build();
        atClaimsSet = new AccessTokenClaimsSet(acClaimsSet, scope, dlClaims, dlClaimsUI, iat, exp);
    }

    @Test
    public void testConstructorSimple() throws ParseException, DataSealerException {
        init();
        Assert.assertEquals(atClaimsSet.getACR(), acr.getValue());
        // start with second constructor
        init2();
        Assert.assertEquals(atClaimsSet.getACR(), acr.getValue());
    }

    @Test
    public void testSerialization() throws ParseException, DataSealerException {
        init();
        AccessTokenClaimsSet acClaimsSet2 = AccessTokenClaimsSet.parse(atClaimsSet.serialize());
        Assert.assertEquals(acClaimsSet2.getACR(), acr.getValue());
        AccessTokenClaimsSet acClaimsSet3 = AccessTokenClaimsSet.parse(acClaimsSet2.serialize(sealer), sealer);
        Assert.assertEquals(acClaimsSet3.getACR(), acr.getValue());
    }

    @Test(expectedExceptions = ParseException.class)
    public void testSerializationWrongType() throws ParseException {
        AuthorizeCodeClaimsSet accessnClaimsSet =
                new AuthorizeCodeClaimsSet.Builder(new SecureRandomIdentifierGenerationStrategy(), clientID, issuer,
                        userPrincipal, subject, iat, exp, authTime, redirectURI, scope).setACR(acr).build();
        atClaimsSet = AccessTokenClaimsSet.parse(accessnClaimsSet.serialize());
    }

}