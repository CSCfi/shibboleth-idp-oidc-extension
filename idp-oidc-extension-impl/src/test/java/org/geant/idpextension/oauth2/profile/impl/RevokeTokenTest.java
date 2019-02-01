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
        AuthorizeCodeClaimsSet acClaimsSet = new AuthorizeCodeClaimsSet(new MockIdStrategy(), clientID, issuer,
                userPrincipal, subject, acr, iat, exp, nonce, authTime, redirectURI, scope, claims, dlClaims,
                dlClaimsID, dlClaimsUI, consentableClaims, consentedClaims);
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