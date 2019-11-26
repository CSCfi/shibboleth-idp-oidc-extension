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
                "jdoe", subject, new Date(), new Date(System.currentTimeMillis() + 30000), new Date(),
                new URI("http://example.com"), scope).setDlClaimsUI(userInfoDeliverySet).build();
        return new BearerAccessToken(claims.serialize(BaseOIDCResponseActionTest.initializeDataSealer()));
    }

}
