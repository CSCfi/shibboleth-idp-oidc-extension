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

import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;
import net.shibboleth.utilities.java.support.security.DataSealerException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import org.geant.idpextension.oidc.profile.OidcEventIds;
import org.geant.idpextension.oidc.token.support.AccessTokenClaimsSet;
import org.geant.idpextension.oidc.token.support.AuthorizeCodeClaimsSet;
import org.geant.idpextension.oidc.token.support.TokenClaimsSet;
import org.springframework.webflow.execution.Event;
import org.testng.annotations.Test;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;

/** {@link ValidateAccessToken} unit test. */
public class ValidateAccessTokenTest extends BaseOIDCResponseActionTest {

    private ValidateAccessToken action;

    private void init() throws ComponentInitializationException, NoSuchAlgorithmException {
        action = new ValidateAccessToken(getDataSealer());
        action.setRevocationCache(new MockRevocationCache(false, true));
        action.initialize();
    }

    /**
     * Test that action throws error if revocation cache is not set.
     */
    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testNoRevocationCache() throws NoSuchAlgorithmException, ComponentInitializationException {
        action = new ValidateAccessToken(getDataSealer());
        action.initialize();
        action.execute(requestCtx);
    }

    /**
     * Basic success case.
     */
    @Test
    public void testSuccess()
            throws NoSuchAlgorithmException, ComponentInitializationException, URISyntaxException, DataSealerException {
        init();
        TokenClaimsSet claims = new AccessTokenClaimsSet.Builder(idGenerator, new ClientID(), "issuer", "userPrin",
                "subject", new Date(), new Date(System.currentTimeMillis() + 1000), new Date(),
                new URI("http://example.com"), new Scope()).build();
        BearerAccessToken token = new BearerAccessToken(claims.serialize(getDataSealer()));
        UserInfoRequest req = new UserInfoRequest(new URI("http://example.com"), token);
        setUserInfoRequest(req);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
    }

    /**
     * Fails due to access token being substituted with authorize code.
     */
    @Test
    public void testFailsNotAccessToken()
            throws NoSuchAlgorithmException, ComponentInitializationException, URISyntaxException, DataSealerException {
        init();
        TokenClaimsSet claims =
                new AuthorizeCodeClaimsSet.Builder(idGenerator, new ClientID(clientId), "issuer", "userPrin", "subject",
                        new Date(), new Date(), new Date(), new URI("http://example.com"), new Scope()).build();
        BearerAccessToken token = new BearerAccessToken(claims.serialize(getDataSealer()));
        UserInfoRequest req = new UserInfoRequest(new URI("http://example.com"), token);
        setUserInfoRequest(req);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, OidcEventIds.INVALID_GRANT);
    }

    /**
     * Fails due token expiration.
     */
    @Test
    public void testFailsExpired()
            throws NoSuchAlgorithmException, ComponentInitializationException, URISyntaxException, DataSealerException {
        init();
        TokenClaimsSet claims = new AccessTokenClaimsSet.Builder(idGenerator, new ClientID(), "issuer", "userPrin",
                "subject", new Date(), new Date(System.currentTimeMillis() - 1), new Date(),
                new URI("http://example.com"), new Scope()).build();
        BearerAccessToken token = new BearerAccessToken(claims.serialize(getDataSealer()));
        UserInfoRequest req = new UserInfoRequest(new URI("http://example.com"), token);
        setUserInfoRequest(req);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, OidcEventIds.INVALID_GRANT);
    }

    /**
     * Fails due token authz code is revoked. Test not 100% as it really does not test passing id to revocation cache.
     */
    @Test
    public void testFailsRevoked()
            throws NoSuchAlgorithmException, ComponentInitializationException, URISyntaxException, DataSealerException {
        action = new ValidateAccessToken(getDataSealer());
        action.setRevocationCache(new MockRevocationCache(true, true));
        action.initialize();
        TokenClaimsSet claims = new AccessTokenClaimsSet.Builder(idGenerator, new ClientID(), "issuer", "userPrin",
                "subject", new Date(), new Date(System.currentTimeMillis() + 1000), new Date(),
                new URI("http://example.com"), new Scope()).build();
        BearerAccessToken token = new BearerAccessToken(claims.serialize(getDataSealer()));
        UserInfoRequest req = new UserInfoRequest(new URI("http://example.com"), token);
        setUserInfoRequest(req);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, OidcEventIds.INVALID_GRANT);
    }

}