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

package org.geant.idpextension.oidc.profile.context.navigate;

import java.net.URI;

import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.RequestContext;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;

import junit.framework.Assert;

public class DefaultRequestedScopeLookupFunctionTest {

    private DefaultRequestedScopeLookupFunction lookup;

    @SuppressWarnings("rawtypes")
    private ProfileRequestContext prc;

    private MessageContext<AuthenticationRequest> msgCtx;

    @SuppressWarnings("unchecked")
    @BeforeMethod
    protected void setUp() throws Exception {
        lookup = new DefaultRequestedScopeLookupFunction();
        final RequestContext requestCtx = new RequestContextBuilder().buildRequestContext();
        prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        msgCtx = new MessageContext<AuthenticationRequest>();
        prc.setInboundMessageContext(msgCtx);
    }

    @Test
    public void testSuccessNoReqObject() {
        Scope parameterScope = new Scope("openid", "email");
        AuthenticationRequest req = new AuthenticationRequest.Builder(new ResponseType("code"), parameterScope,
                new ClientID("000123"), URI.create("https://example.com/callback")).state(new State()).build();
        msgCtx.setMessage(req);
        Assert.assertTrue(lookup.apply(prc).contains("openid"));
        Assert.assertTrue(lookup.apply(prc).contains("email"));
        Assert.assertEquals(2, lookup.apply(prc).size());
    }

    @Test
    public void testSuccessReqObject() {
        Scope parameterScope = new Scope("openid");
        JWTClaimsSet ro = new JWTClaimsSet.Builder().claim("scope", "openid email").build();
        AuthenticationRequest req = new AuthenticationRequest.Builder(new ResponseType("code"), parameterScope,
                new ClientID("000123"), URI.create("https://example.com/callback")).state(new State())
                        .requestObject(new PlainJWT(ro)).build();
        msgCtx.setMessage(req);
        Assert.assertTrue(lookup.apply(prc).contains("openid"));
        Assert.assertTrue(lookup.apply(prc).contains("email"));
        Assert.assertEquals(2, lookup.apply(prc).size());
    }

}