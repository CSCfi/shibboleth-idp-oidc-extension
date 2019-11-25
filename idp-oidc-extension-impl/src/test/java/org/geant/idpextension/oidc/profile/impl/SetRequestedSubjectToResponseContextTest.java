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
        respCtx.setRequestedClaims(claims);
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
        respCtx.setRequestedClaims(claims);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertEquals(respCtx.getRequestedSubject(), "reqsubclaims");
    }

}