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


package org.geant.idpextension.oidc.profile.flow;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

import org.geant.idpextension.oidc.profile.impl.BaseOIDCResponseActionTest;
import org.geant.idpextension.oidc.token.support.AccessTokenClaimsSet;
import org.geant.idpextension.oidc.token.support.TokenClaimsSet;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.security.DataSealerException;

/**
 * Abstract unit test for the OIDC flows using access tokens.
 */
public class AbstractOidcApiFlowTest extends AbstractOidcFlowTest {
    
    protected AbstractOidcApiFlowTest(String flowId) {
        super(flowId);
    }
    
    protected BearerAccessToken buildToken(String clientId, String subject, Scope scope)
            throws URISyntaxException, NoSuchAlgorithmException, DataSealerException, ComponentInitializationException {
        return buildToken(clientId, subject, scope, null);
    }

    protected BearerAccessToken buildToken(String clientId, String subject, Scope scope, ClaimsSet userInfoDeliverySet)
            throws URISyntaxException, NoSuchAlgorithmException, DataSealerException, ComponentInitializationException {
        TokenClaimsSet claims = new AccessTokenClaimsSet.Builder(idGenerator, new ClientID(clientId),
                "https://op.example.org",
                "jdoe", subject, new Date(), new Date(System.currentTimeMillis() + 1000), new Date(),
                new URI("http://example.com"), scope).setDlClaimsUI(userInfoDeliverySet).build();
        return new BearerAccessToken(claims.serialize(BaseOIDCResponseActionTest.initializeDataSealer()));
    }

}
