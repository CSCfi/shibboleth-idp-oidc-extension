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

import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;

import java.net.URI;

import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.RequestContext;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;

import junit.framework.Assert;

@SuppressWarnings({"unchecked", "rawtypes"})
public class AbstractAuthenticationRequestLookupFunctionTest {

    protected ProfileRequestContext prc;

    protected MessageContext<AuthenticationRequest> msgCtx;

    protected OIDCAuthenticationResponseContext oidcCtx;

    protected MockOKLookupFunction mock = new MockOKLookupFunction();

    @BeforeMethod
    protected void setUpCtxs() throws Exception {
        final RequestContext requestCtx = new RequestContextBuilder().buildRequestContext();
        prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        msgCtx = new MessageContext<AuthenticationRequest>();
        prc.setInboundMessageContext(msgCtx);
        AuthenticationRequest req = new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"),
                new ClientID("000123"), URI.create("https://example.com/callback")).state(new State()).build();
        msgCtx.setMessage(req);
        prc.setOutboundMessageContext(new MessageContext());
        oidcCtx = new OIDCAuthenticationResponseContext();
        prc.getOutboundMessageContext().addSubcontext(oidcCtx);
    }

    @Test
    public void testOK() {
        Assert.assertEquals("OK", mock.apply(prc));
    }

    @Test
    public void testNoInboundCtxts() {
        // No profilecontext
        Assert.assertNull(mock.apply(null));
        // No inbound message context
        prc.setInboundMessageContext(null);
        Assert.assertNull(mock.apply(prc));
        // No message in inbound message context
        prc.setInboundMessageContext(msgCtx);
        msgCtx.setMessage(null);
        Assert.assertNull(mock.apply(prc));
    }

    @Test
    public void testNoOutboundCtxts() {
        // No outbound msg context
        prc.setOutboundMessageContext(null);
        Assert.assertNull(mock.apply(prc));
        // No authentication response context
        prc.setOutboundMessageContext(new MessageContext());
        Assert.assertNull(mock.apply(prc));
    }

    class MockOKLookupFunction extends AbstractAuthenticationRequestLookupFunction {

        @Override
        Object doLookup(AuthenticationRequest req) {
            return req != null ? new String("OK") : new String("NOK");
        }

    }

}