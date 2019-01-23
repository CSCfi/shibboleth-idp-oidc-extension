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
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.claims.ACR;

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
     * 
     * @throws ComponentInitializationException
     * @throws NoSuchAlgorithmException
     */
    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testNoRevocationCache() throws NoSuchAlgorithmException, ComponentInitializationException {
        action = new ValidateAccessToken(getDataSealer());
        action.initialize();
        action.execute(requestCtx);
    }

    /**
     * Basic success case.
     * 
     * @throws ComponentInitializationException
     * @throws NoSuchAlgorithmException
     * @throws URISyntaxException
     * @throws DataSealerException
     */
    @Test
    public void testSuccess()
            throws NoSuchAlgorithmException, ComponentInitializationException, URISyntaxException, DataSealerException {
        init();
        TokenClaimsSet claims = new AccessTokenClaimsSet(new idStrat(), new ClientID(), "issuer", "userPrin", "subject",
                new ACR("0"), new Date(), new Date(System.currentTimeMillis() + 1000), new Nonce(), new Date(),
                new URI("http://example.com"), new Scope(), "id", null, null, null, null, null);
        BearerAccessToken token = new BearerAccessToken(claims.serialize(getDataSealer()));
        UserInfoRequest req = new UserInfoRequest(new URI("http://example.com"), token);
        setUserInfoRequest(req);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
    }

    /**
     * Fails due to access token being substituted with authorize code.
     * 
     * @throws ComponentInitializationException
     * @throws NoSuchAlgorithmException
     * @throws URISyntaxException
     * @throws DataSealerException
     */
    @Test
    public void testFailsNotAccessToken()
            throws NoSuchAlgorithmException, ComponentInitializationException, URISyntaxException, DataSealerException {
        init();
        TokenClaimsSet claims = new AuthorizeCodeClaimsSet(new idStrat(), new ClientID(), "issuer", "userPrin",
                "subject", new ACR("0"), new Date(), new Date(), new Nonce(), new Date(), new URI("http://example.com"),
                new Scope(), "id", null, null, null, null, null, null);
        BearerAccessToken token = new BearerAccessToken(claims.serialize(getDataSealer()));
        UserInfoRequest req = new UserInfoRequest(new URI("http://example.com"), token);
        setUserInfoRequest(req);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, OidcEventIds.INVALID_GRANT);
    }

    /**
     * Fails due token expiration.
     * 
     * @throws ComponentInitializationException
     * @throws NoSuchAlgorithmException
     * @throws URISyntaxException
     * @throws DataSealerException
     */
    @Test
    public void testFailsExpired()
            throws NoSuchAlgorithmException, ComponentInitializationException, URISyntaxException, DataSealerException {
        init();
        TokenClaimsSet claims = new AccessTokenClaimsSet(new idStrat(), new ClientID(), "issuer", "userPrin", "subject",
                new ACR("0"), new Date(), new Date(System.currentTimeMillis() - 1), new Nonce(), new Date(),
                new URI("http://example.com"), new Scope(), "id", null, null, null, null, null);
        BearerAccessToken token = new BearerAccessToken(claims.serialize(getDataSealer()));
        UserInfoRequest req = new UserInfoRequest(new URI("http://example.com"), token);
        setUserInfoRequest(req);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, OidcEventIds.INVALID_GRANT);
    }

    /**
     * Fails due token authz code is revoked. Test not 100% as it really does not test passing id to revocation cache.
     * 
     * @throws ComponentInitializationException
     * @throws NoSuchAlgorithmException
     * @throws URISyntaxException
     * @throws DataSealerException
     */
    @Test
    public void testFailsRevoked()
            throws NoSuchAlgorithmException, ComponentInitializationException, URISyntaxException, DataSealerException {
        action = new ValidateAccessToken(getDataSealer());
        action.setRevocationCache(new MockRevocationCache(true, true));
        action.initialize();
        TokenClaimsSet claims = new AccessTokenClaimsSet(new idStrat(), new ClientID(), "issuer", "userPrin", "subject",
                new ACR("0"), new Date(), new Date(System.currentTimeMillis() + 1000), new Nonce(), new Date(),
                new URI("http://example.com"), new Scope(), "id", null, null, null, null, null);
        BearerAccessToken token = new BearerAccessToken(claims.serialize(getDataSealer()));
        UserInfoRequest req = new UserInfoRequest(new URI("http://example.com"), token);
        setUserInfoRequest(req);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, OidcEventIds.INVALID_GRANT);
    }

}