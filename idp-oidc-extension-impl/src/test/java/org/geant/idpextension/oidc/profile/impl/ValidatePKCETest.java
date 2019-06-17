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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Date;

import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

import org.geant.idpextension.oidc.config.OIDCCoreProtocolConfiguration;
import org.geant.idpextension.oidc.token.support.AuthorizeCodeClaimsSet;
import org.geant.idpextension.oidc.token.support.RefreshTokenClaimsSet;
import org.geant.idpextension.oidc.token.support.TokenClaimsSet;
import org.opensaml.profile.action.EventIds;
import org.springframework.webflow.execution.Event;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.claims.ACR;

/** {@link ValidatePKCE} unit test. */
public class ValidatePKCETest extends BaseOIDCResponseActionTest {

    private ValidatePKCE action;

    private String codeVerifier = "1234567812345678123456781234567812345678123456781234567812345678";

    @BeforeMethod
    private void init() throws ComponentInitializationException, URISyntaxException, ParseException {
        action = new ValidatePKCE();
        action.initialize();
        // We may use mock code as the actions does not access it directly from request. What we need the request for is
        // to pass the code verifier value.
        TokenRequest req = new TokenRequest(new URI("https://client.com/callback"), new ClientID(clientId),
                new AuthorizationCodeGrant(new AuthorizationCode("mockCode"), new URI("https://client.com/callback"),
                        new CodeVerifier(codeVerifier)));
        setTokenRequest(req);
        TokenClaimsSet claims =
                new AuthorizeCodeClaimsSet.Builder(idGenerator, new ClientID(), "issuer", "userPrin", "subject",
                        new Date(), new Date(), new Date(), new URI("http://example.com"), new Scope())
                                .setACR(new ACR("0"))
                                .setCodeChallenge("S256" + CodeChallenge
                                        .compute(CodeChallengeMethod.S256, new CodeVerifier(codeVerifier)).getValue())
                                .build();
        respCtx.setTokenClaimsSet(claims);
    }

    /**
     * Test success case of using "S256".
     */
    @Test
    public void testSuccess() throws ComponentInitializationException {
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
    }

    /**
     * Test success case of using "S256".
     * 
     * @throws URISyntaxException
     */
    @Test
    public void testWrongValue() throws ComponentInitializationException, URISyntaxException {
        TokenRequest req = new TokenRequest(new URI("https://client.com/callback"), new ClientID(clientId),
                new AuthorizationCodeGrant(new AuthorizationCode("mockCode"), new URI("https://client.com/callback"),
                        new CodeVerifier(codeVerifier + "someWrongValue")));
        setTokenRequest(req);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.MESSAGE_AUTHN_ERROR);
    }

    /**
     * Test fail case of using "plain" as it is not allowed by default.
     */
    @Test
    public void testFailPlainNotAllowed() throws ComponentInitializationException, URISyntaxException {
        TokenClaimsSet claims =
                new AuthorizeCodeClaimsSet.Builder(idGenerator, new ClientID(), "issuer", "userPrin", "subject",
                        new Date(), new Date(), new Date(), new URI("http://example.com"), new Scope())
                                .setACR(new ACR("0"))
                                .setCodeChallenge("plain" + CodeChallenge
                                        .compute(CodeChallengeMethod.PLAIN, new CodeVerifier(codeVerifier)).getValue())
                                .build();
        respCtx.setTokenClaimsSet(claims);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_MESSAGE);
    }

    /**
     * Test success case of using "plain".
     */
    @Test
    public void testSuccessPlain() throws ComponentInitializationException, URISyntaxException {
        ((OIDCCoreProtocolConfiguration) rpCtx.getProfileConfig()).setAllowPKCEPlain(true);
        TokenClaimsSet claims =
                new AuthorizeCodeClaimsSet.Builder(idGenerator, new ClientID(), "issuer", "userPrin", "subject",
                        new Date(), new Date(), new Date(), new URI("http://example.com"), new Scope())
                                .setACR(new ACR("0"))
                                .setCodeChallenge("plain" + CodeChallenge
                                        .compute(CodeChallengeMethod.PLAIN, new CodeVerifier(codeVerifier)).getValue())
                                .build();
        respCtx.setTokenClaimsSet(claims);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
    }

    /**
     * Test fail case of using "plain" with wrong value.
     */
    @Test
    public void testFailPlain() throws ComponentInitializationException, URISyntaxException {
        ((OIDCCoreProtocolConfiguration) rpCtx.getProfileConfig()).setAllowPKCEPlain(true);
        TokenClaimsSet claims = new AuthorizeCodeClaimsSet.Builder(idGenerator, new ClientID(), "issuer", "userPrin",
                "subject", new Date(), new Date(), new Date(), new URI("http://example.com"), new Scope())
                        .setACR(new ACR("0"))
                        .setCodeChallenge("plain" + CodeChallenge
                                .compute(CodeChallengeMethod.PLAIN, new CodeVerifier(codeVerifier + "someWrongvalue"))
                                .getValue())
                        .build();
        respCtx.setTokenClaimsSet(claims);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.MESSAGE_AUTHN_ERROR);
    }

    /**
     * Test success in the case of not having forced PKCE and not using the PKCE parameters.
     */
    @Test
    public void testSuccessNoPKCE() throws ComponentInitializationException, URISyntaxException {
        TokenRequest req = new TokenRequest(new URI("https://client.com/callback"), new ClientID(clientId),
                new AuthorizationCodeGrant(new AuthorizationCode("mockCode"), new URI("https://client.com/callback")));
        setTokenRequest(req);
        TokenClaimsSet claims = new AuthorizeCodeClaimsSet.Builder(idGenerator, new ClientID(), "issuer", "userPrin",
                "subject", new Date(), new Date(), new Date(), new URI("http://example.com"), new Scope())
                        .setACR(new ACR("0")).build();
        respCtx.setTokenClaimsSet(claims);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
    }

    /**
     * Test failure in the case of having forced PKCE and not using the PKCE parameters.
     */
    @Test
    public void testFailureNoPKCE() throws ComponentInitializationException, URISyntaxException {
        ((OIDCCoreProtocolConfiguration) rpCtx.getProfileConfig()).setForcePKCE(true);
        TokenRequest req = new TokenRequest(new URI("https://client.com/callback"), new ClientID(clientId),
                new AuthorizationCodeGrant(new AuthorizationCode("mockCode"), new URI("https://client.com/callback")));
        setTokenRequest(req);
        TokenClaimsSet claims = new AuthorizeCodeClaimsSet.Builder(idGenerator, new ClientID(), "issuer", "userPrin",
                "subject", new Date(), new Date(), new Date(), new URI("http://example.com"), new Scope())
                        .setACR(new ACR("0")).build();
        respCtx.setTokenClaimsSet(claims);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_MESSAGE);
    }

    /**
     * Test failure in the case of missing code verifier in token request.
     */
    @Test
    public void testFailureTokenRequestMissingVerfier() throws ComponentInitializationException, URISyntaxException {
        TokenRequest req = new TokenRequest(new URI("https://client.com/callback"), new ClientID(clientId),
                new AuthorizationCodeGrant(new AuthorizationCode("mockCode"), new URI("https://client.com/callback")));
        setTokenRequest(req);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_MESSAGE);
    }

    /**
     * Test success in the case of having forced PKCE, not using the PKCE parameters but different grant type than Authz
     * Code.
     */
    @Test
    public void testSuccessNoAuthzCode() throws ComponentInitializationException, URISyntaxException {
        ((OIDCCoreProtocolConfiguration) rpCtx.getProfileConfig()).setForcePKCE(true);
        TokenRequest req = new TokenRequest(new URI("https://client.com/callback"), new ClientID(clientId),
                new RefreshTokenGrant(new RefreshToken()));
        setTokenRequest(req);
        TokenClaimsSet claims = new RefreshTokenClaimsSet(
                new AuthorizeCodeClaimsSet.Builder(idGenerator, new ClientID(), "issuer", "userPrin", "subject",
                        new Date(), new Date(), new Date(), new URI("http://example.com"), new Scope())
                                .setACR(new ACR("0")).build(),
                new Date(), new Date());
        respCtx.setTokenClaimsSet(claims);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
    }

    /**
     * Test fail in the case of unknowm method.
     * 
     * @throws URISyntaxException
     */
    @Test
    public void testFailUnknownType() throws ComponentInitializationException, URISyntaxException {
        TokenClaimsSet claims =
                new AuthorizeCodeClaimsSet.Builder(idGenerator, new ClientID(), "issuer", "userPrin", "subject",
                        new Date(), new Date(), new Date(), new URI("http://example.com"), new Scope())
                                .setACR(new ACR("0"))
                                .setCodeChallenge("not_S256" + CodeChallenge
                                        .compute(CodeChallengeMethod.S256, new CodeVerifier(codeVerifier)).getValue())
                                .build();
        respCtx.setTokenClaimsSet(claims);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_MESSAGE);
    }

}