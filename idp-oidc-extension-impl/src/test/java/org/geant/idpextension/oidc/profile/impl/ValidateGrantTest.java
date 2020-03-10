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

import net.minidev.json.JSONObject;
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
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;

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
        return buildAuthorizationCode(clientId, issuer, userPrincipal, sub, callbackUrl, null);
    }

    public static AuthorizationCode buildAuthorizationCode(String clientId, String issuer, String userPrincipal,
            String sub, String callbackUrl, String codeChallenge)
            throws URISyntaxException, NoSuchAlgorithmException, DataSealerException, ComponentInitializationException {
        return buildAuthorizationCode(clientId, issuer, userPrincipal, sub, callbackUrl, codeChallenge, null, null, null);
    }
    
    public static AuthorizationCode buildAuthorizationCode(String clientId, String issuer, String userPrincipal,
            String sub, String callbackUrl, String codeChallenge, JSONObject deliveryClaims,
            JSONObject deliveryClaimsIDToken, JSONObject deliveryClaimsUserInfo)
            throws URISyntaxException, NoSuchAlgorithmException, DataSealerException, ComponentInitializationException {
        Date now = new Date();
        ValidateGrantTest test = new ValidateGrantTest();
        AuthorizeCodeClaimsSet.Builder builder = new AuthorizeCodeClaimsSet.Builder(
                new SecureRandomIdentifierGenerationStrategy(), new ClientID(clientId), issuer, userPrincipal, sub,
                now, new Date(now.getTime() + 100000), now, new URI(callbackUrl), new Scope());
        if (codeChallenge != null) {
            builder.setCodeChallenge(codeChallenge);
        }
        if (deliveryClaims != null) {
            builder.setDlClaims(new DeliveryClaimsSet(deliveryClaims));
        }
        if (deliveryClaimsIDToken != null) {
            builder.setDlClaimsID(new DeliveryClaimsSet(deliveryClaimsIDToken));
        }
        if (deliveryClaimsUserInfo != null) {
            builder.setDlClaimsUI(new DeliveryClaimsSet(deliveryClaimsUserInfo));
        }
        TokenClaimsSet acClaims = builder.build();
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
    
    private static class DeliveryClaimsSet extends ClaimsSet {
        
        public DeliveryClaimsSet(final JSONObject claims) {
            super(claims);
        }
    }

}