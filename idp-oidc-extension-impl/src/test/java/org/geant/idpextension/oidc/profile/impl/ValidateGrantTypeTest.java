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

package org.geant.idpextension.oidc.profile.impl;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.Set;

import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.geant.idpextension.oidc.profile.OidcEventIds;
import org.springframework.webflow.execution.Event;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

/** {@link ValidateGrantType} unit test. */
public class ValidateGrantTypeTest extends BaseOIDCResponseActionTest {

    private ValidateGrantType action;

    private OIDCClientMetadata metaData;

    @BeforeMethod
    private void init() throws ComponentInitializationException, URISyntaxException, ParseException {
        action = new ValidateGrantType();
        action.initialize();
        OIDCMetadataContext oidcCtx =
                profileRequestCtx.getInboundMessageContext().getSubcontext(OIDCMetadataContext.class, true);
        metaData = new OIDCClientMetadata();
        Set<GrantType> grantTypes = new HashSet<GrantType>();
        grantTypes.add(GrantType.parse("refresh_token"));
        grantTypes.add(GrantType.parse("authorization_code"));
        metaData.setGrantTypes(grantTypes);
        metaData.setRedirectionURI(new URI("https://notmatching.org"));
        OIDCClientInformation information =
                new OIDCClientInformation(new ClientID("test"), null, metaData, null, null, null);
        oidcCtx.setClientInformation(information);
        TokenRequest req =
                new TokenRequest(new URI("https://notmatching.org"), new RefreshTokenGrant(new RefreshToken()));
        setTokenRequest(req);
    }

    /**
     * Test that action accepts the "refresh_token" grant type.
     */
    @Test
    public void testSuccess() throws ComponentInitializationException {
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
    }

    /**
     * Test that action rejects the "refresh_token" grant type.
     */
    @Test
    public void testFailure() throws ComponentInitializationException, ParseException {
        Set<GrantType> grantTypes = new HashSet<GrantType>();
        grantTypes.add(GrantType.parse("authorization_code"));
        metaData.setGrantTypes(grantTypes);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, OidcEventIds.INVALID_GRANT_TYPE);
    }

}