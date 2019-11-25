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