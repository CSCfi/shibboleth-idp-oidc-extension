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
                iat, exp, nonce, authTime, redirectURI, scope, claims, dlClaims, dlClaimsID, dlClaimsUI,
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
                userPrincipal, subject, acr, iat, exp, nonce, authTime, redirectURI, scope, claims, dlClaims,
                dlClaimsUI, consentableClaims, consentedClaims);
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