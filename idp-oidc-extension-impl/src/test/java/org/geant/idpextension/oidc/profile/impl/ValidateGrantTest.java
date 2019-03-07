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
import net.shibboleth.utilities.java.support.security.SecureRandomIdentifierGenerationStrategy;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

import org.geant.idpextension.oidc.profile.OidcEventIds;
import org.geant.idpextension.oidc.token.support.AuthorizeCodeClaimsSet;
import org.geant.idpextension.oidc.token.support.RefreshTokenClaimsSet;
import org.geant.idpextension.oidc.token.support.TokenClaimsSet;
import org.opensaml.storage.ReplayCache;
import org.opensaml.storage.impl.MemoryStorageService;
import org.testng.annotations.Test;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.RefreshToken;

/** {@link ValidateGrant} unit test. */
public class ValidateGrantTest extends BaseOIDCResponseActionTest {

    private ValidateGrant action;

    TokenClaimsSet acClaims;

    TokenClaimsSet rfClaims;

    AuthorizationGrant codeGrant;

    RefreshTokenGrant rfGrant;

    URI callback;

    @SuppressWarnings("unchecked")
    private void init()
            throws ComponentInitializationException, NoSuchAlgorithmException, URISyntaxException, DataSealerException {
        Date now = new Date();
        acClaims =
                new AuthorizeCodeClaimsSet.Builder(idGenerator, new ClientID(clientId), "issuer", "userPrin", "subject",
                        now, new Date(now.getTime() + 100000), now, new URI("http://example.com"), new Scope()).build();
        rfClaims = new RefreshTokenClaimsSet(acClaims, now, new Date(now.getTime() + 100000));
        AuthorizationCode code = new AuthorizationCode(acClaims.serialize(getDataSealer()));
        RefreshToken rfToken = new RefreshToken(rfClaims.serialize(getDataSealer()));
        callback = new URI("https://client.com/callback");
        codeGrant = new AuthorizationCodeGrant(code, callback);
        rfGrant = new RefreshTokenGrant(rfToken);
        // by default we create authz code request
        TokenRequest req = new TokenRequest(callback, new ClientID(clientId), codeGrant);
        profileRequestCtx.getInboundMessageContext().setMessage(req);
        action = new ValidateGrant(getDataSealer());
        action.setRevocationCache(new MockRevocationCache(false, true));
        ReplayCache replayCache = new ReplayCache();
        MemoryStorageService storageService = new MemoryStorageService();
        storageService.setId("id");
        storageService.initialize();
        replayCache.setStorage(storageService);
        action.setReplayCache(replayCache);
        action.initialize();
    }

    public static AuthorizationCode buildAuthorizationCode(String clientId, String issuer, String userPrincipal,
            String sub, String callbackUrl)
            throws URISyntaxException, NoSuchAlgorithmException, DataSealerException, ComponentInitializationException {
        Date now = new Date();
        ValidateGrantTest test = new ValidateGrantTest();
        TokenClaimsSet acClaims = new AuthorizeCodeClaimsSet.Builder(new SecureRandomIdentifierGenerationStrategy(),
                new ClientID(clientId), issuer, userPrincipal, sub, now, new Date(now.getTime() + 100000), now,
                new URI(callbackUrl), new Scope()).build();
        return new AuthorizationCode(acClaims.serialize(test.getDataSealer()));
    }

    @Test
    public void testAuthorizeCodeSuccess()
            throws NoSuchAlgorithmException, ComponentInitializationException, URISyntaxException, DataSealerException {
        init();
        ActionTestingSupport.assertProceedEvent(action.execute(requestCtx));
    }

    @Test
    public void testAuthorizeCodeReplayed()
            throws NoSuchAlgorithmException, ComponentInitializationException, URISyntaxException, DataSealerException {
        init();
        ActionTestingSupport.assertProceedEvent(action.execute(requestCtx));
        ActionTestingSupport.assertEvent(action.execute(requestCtx), OidcEventIds.INVALID_GRANT);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testRefreshTokenSuccess()
            throws NoSuchAlgorithmException, ComponentInitializationException, URISyntaxException, DataSealerException {
        init();
        TokenRequest req = new TokenRequest(callback, new ClientID(clientId), rfGrant);
        profileRequestCtx.getInboundMessageContext().setMessage(req);
        ActionTestingSupport.assertProceedEvent(action.execute(requestCtx));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testRefreshTokenReplayed()
            throws NoSuchAlgorithmException, ComponentInitializationException, URISyntaxException, DataSealerException {
        init();
        TokenRequest req = new TokenRequest(callback, new ClientID(clientId), rfGrant);
        profileRequestCtx.getInboundMessageContext().setMessage(req);
        ActionTestingSupport.assertProceedEvent(action.execute(requestCtx));
        ActionTestingSupport.assertProceedEvent(action.execute(requestCtx));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testMixGrant()
            throws NoSuchAlgorithmException, ComponentInitializationException, URISyntaxException, DataSealerException {
        init();
        TokenRequest req = new TokenRequest(callback, new ClientID(clientId),
                new RefreshTokenGrant(new RefreshToken(acClaims.serialize(getDataSealer()))));
        profileRequestCtx.getInboundMessageContext().setMessage(req);
        ActionTestingSupport.assertEvent(action.execute(requestCtx), OidcEventIds.INVALID_GRANT);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testWrongClient()
            throws NoSuchAlgorithmException, ComponentInitializationException, URISyntaxException, DataSealerException {
        init();
        AuthorizationCode code =
                buildAuthorizationCode("clientIdWrong", "issuer", "userPrin", "subject", "http://example.com");
        TokenRequest req =
                new TokenRequest(callback, new ClientID(clientId), new AuthorizationCodeGrant(code, callback));
        profileRequestCtx.getInboundMessageContext().setMessage(req);
        ActionTestingSupport.assertEvent(action.execute(requestCtx), OidcEventIds.INVALID_GRANT);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testExpired()
            throws NoSuchAlgorithmException, ComponentInitializationException, URISyntaxException, DataSealerException {
        init();
        Date now = new Date();
        rfClaims = new RefreshTokenClaimsSet(acClaims, now, new Date(now.getTime() - 10));
        TokenRequest req = new TokenRequest(callback, new ClientID(clientId),
                new RefreshTokenGrant(new RefreshToken(rfClaims.serialize(getDataSealer()))));
        profileRequestCtx.getInboundMessageContext().setMessage(req);
        ActionTestingSupport.assertEvent(action.execute(requestCtx), OidcEventIds.INVALID_GRANT);
    }

    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testNoRevocationCache() throws NoSuchAlgorithmException, ComponentInitializationException {
        action = new ValidateGrant(getDataSealer());
        ReplayCache replayCache = new ReplayCache();
        MemoryStorageService storageService = new MemoryStorageService();
        storageService.setId("mockId");
        storageService.initialize();
        replayCache.setStorage(storageService);
        action.setReplayCache(replayCache);
        action.initialize();
    }

    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testNoReplayCache() throws NoSuchAlgorithmException, ComponentInitializationException {
        action = new ValidateGrant(getDataSealer());
        action.setRevocationCache(new MockRevocationCache(false, true));
        action.initialize();
    }

    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testNoDataSealer() throws NoSuchAlgorithmException, ComponentInitializationException {
        action = new ValidateGrant(null);
    }

}