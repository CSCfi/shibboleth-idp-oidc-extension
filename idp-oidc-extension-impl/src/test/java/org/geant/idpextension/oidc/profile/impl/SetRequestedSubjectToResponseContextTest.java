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
import java.net.URI;
import org.testng.Assert;
import org.springframework.webflow.execution.Event;
import org.testng.annotations.Test;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import com.nimbusds.openid.connect.sdk.ClaimsRequest.Entry;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;

/** {@link SetRequestedSubjectToResponseContext} unit test. */
public class SetRequestedSubjectToResponseContextTest extends BaseOIDCResponseActionTest {

    private SetRequestedSubjectToResponseContext action;

    private void init() throws ComponentInitializationException {
        action = new SetRequestedSubjectToResponseContext();
        action.initialize();
    }

    /**
     * Test action handles not having requested subject correctly.
     * 
     * @throws ComponentInitializationException
     */
    @Test
    public void testNoReqSubject() throws ComponentInitializationException {
        init();
        respCtx.setRequestedSubject(null);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNull(respCtx.getRequestedSubject());
    }

    /**
     * Test subject carried in id token hint is set to response ctx.
     * 
     * @throws ComponentInitializationException
     */
    @Test
    public void testIdTokenHint() throws ComponentInitializationException {
        init();
        JWT idTokenHint = new PlainJWT(new JWTClaimsSet.Builder().subject("reqsubidtokenhint").build());
        AuthenticationRequest req =
                new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"), new ClientID("000123"),
                        URI.create("https://example.com/callback")).idTokenHint(idTokenHint).state(new State()).build();
        setAuthenticationRequest(req);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertEquals(respCtx.getRequestedSubject(), "reqsubidtokenhint");
    }

    /**
     * Test subject carried in claims request is set to response ctx.
     * 
     * @throws ComponentInitializationException
     */
    @Test
    public void testClaimsRequest() throws ComponentInitializationException {
        init();
        ClaimsRequest claims = new ClaimsRequest();
        Entry entry = new Entry("sub", ClaimRequirement.ESSENTIAL, null, "reqsubclaims");
        claims.addIDTokenClaim(entry);
        AuthenticationRequest req =
                new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"), new ClientID("000123"),
                        URI.create("https://example.com/callback")).claims(claims).state(new State()).build();
        setAuthenticationRequest(req);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertEquals(respCtx.getRequestedSubject(), "reqsubclaims");
    }

    /**
     * Test subject carried in claims request is set to response ctx in the sub is set to both claims request and id
     * token hint.
     * 
     * @throws ComponentInitializationException
     */
    @Test
    public void testMixed() throws ComponentInitializationException {
        init();
        ClaimsRequest claims = new ClaimsRequest();
        Entry entry = new Entry("sub", ClaimRequirement.ESSENTIAL, null, "reqsubclaims");
        JWT idTokenHint = new PlainJWT(new JWTClaimsSet.Builder().subject("reqsubidtokenhint").build());
        claims.addIDTokenClaim(entry);
        AuthenticationRequest req = new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"),
                new ClientID("000123"), URI.create("https://example.com/callback")).idTokenHint(idTokenHint)
                        .claims(claims).state(new State()).build();
        setAuthenticationRequest(req);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertEquals(respCtx.getRequestedSubject(), "reqsubclaims");
    }

}