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

/** Unit tests for {@link OAuth2TokenRevocationConfiguration}. */

package org.geant.idpextension.oauth2.profile.impl;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;

import org.geant.idpextension.oidc.storage.RevocationCache;
import org.geant.idpextension.oidc.storage.RevocationCacheContexts;
import org.geant.idpextension.oidc.token.support.AccessTokenClaimsSet;
import org.geant.idpextension.oidc.token.support.AuthorizeCodeClaimsSet;
import org.geant.idpextension.oidc.token.support.BaseTokenClaimsSetTest;
import org.geant.idpextension.oidc.token.support.RefreshTokenClaimsSet;
import org.opensaml.storage.impl.MemoryStorageService;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.TokenRevocationRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;

import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.security.DataSealerException;
import net.shibboleth.utilities.java.support.security.SecureRandomIdentifierGenerationStrategy;

/**
 * Tests for {@link RevokeToken}.
 */
public class RevokeTokenTest extends BaseTokenClaimsSetTest {

    private RevokeToken action;

    private MemoryStorageService storageService;

    private AccessTokenClaimsSet atClaimsSet;

    private RefreshTokenClaimsSet rfClaimsSet;

    TokenRevocationRequest revokeAccessToken;

    TokenRevocationRequest revokeRefreshToken;

    TokenRevocationRequest unknownToken;

    private RevocationCache revocationCache;

    @BeforeMethod
    protected void setUp() throws Exception {

        storageService = new MemoryStorageService();
        storageService.setId("test");
        storageService.initialize();

        revocationCache = new RevocationCache();
        revocationCache.setEntryExpiration(500);
        revocationCache.setStorage(storageService);
        revocationCache.initialize();
    }

    @AfterMethod
    protected void tearDown() {
        revocationCache.destroy();
        revocationCache = null;

        storageService.destroy();
        storageService = null;
    }

    protected void init()
            throws ComponentInitializationException, NoSuchAlgorithmException, DataSealerException, URISyntaxException {
        // init tokens
        AuthorizeCodeClaimsSet acClaimsSet =
                new AuthorizeCodeClaimsSet.Builder(new SecureRandomIdentifierGenerationStrategy(), clientID, issuer,
                        userPrincipal, subject, iat, exp, authTime, redirectURI, scope).build();
        atClaimsSet = new AccessTokenClaimsSet(acClaimsSet, scope, dlClaims, dlClaimsUI, iat, exp);
        rfClaimsSet = new RefreshTokenClaimsSet(acClaimsSet, iat, exp);
        // init action
        action = new RevokeToken(sealer);
        action.setRevocationCache(revocationCache);
        action.initialize();
        revokeAccessToken = new TokenRevocationRequest(new URI("https://example.com"), new ClientID(),
                new BearerAccessToken(atClaimsSet.serialize(sealer)));
        // Using BearerAccessToken for refresh token has no relevance to test
        revokeRefreshToken = new TokenRevocationRequest(new URI("https://example.com"), new ClientID(),
                new BearerAccessToken(rfClaimsSet.serialize(sealer)));
        unknownToken = new TokenRevocationRequest(new URI("https://example.com"), new ClientID(),
                new BearerAccessToken("sometoken"));
    }

    @Test
    public void testRevokeAccessToken()
            throws ComponentInitializationException, NoSuchAlgorithmException, DataSealerException, URISyntaxException {
        init();
        RequestContext requestContext =
                new RequestContextBuilder().setInboundMessage(revokeAccessToken).buildRequestContext();
        Assert.assertFalse(revocationCache.isRevoked(RevocationCacheContexts.AUTHORIZATION_CODE, atClaimsSet.getID()));
        ActionTestingSupport.assertProceedEvent(action.execute(requestContext));
        Assert.assertTrue(revocationCache.isRevoked(RevocationCacheContexts.AUTHORIZATION_CODE, atClaimsSet.getID()));
    }

    @Test
    public void testRevokeRefreshToken()
            throws ComponentInitializationException, NoSuchAlgorithmException, DataSealerException, URISyntaxException {
        init();
        RequestContext requestContext =
                new RequestContextBuilder().setInboundMessage(revokeRefreshToken).buildRequestContext();
        Assert.assertFalse(revocationCache.isRevoked(RevocationCacheContexts.AUTHORIZATION_CODE, rfClaimsSet.getID()));
        ActionTestingSupport.assertProceedEvent(action.execute(requestContext));
        Assert.assertTrue(revocationCache.isRevoked(RevocationCacheContexts.AUTHORIZATION_CODE, rfClaimsSet.getID()));
    }

    @Test
    public void testRevokeSomeUnknownToken()
            throws ComponentInitializationException, NoSuchAlgorithmException, DataSealerException, URISyntaxException {
        init();
        RequestContext requestContext =
                new RequestContextBuilder().setInboundMessage(unknownToken).buildRequestContext();
        ActionTestingSupport.assertProceedEvent(action.execute(requestContext));

    }

}