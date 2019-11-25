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
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseContext;
import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;

import net.shibboleth.idp.profile.RequestContextBuilder;

/** {@link AbstractOIDCAuthenticationResponseAction} unit test. */
public class AbstractOIDCAuthenticationResponseActionTest {

    private MockOIDCResponseAction action;
    private RequestContext requestCtx;

    @SuppressWarnings({ "unchecked", "rawtypes" })
    @BeforeMethod
    protected void setUp() throws Exception {
        action = new MockOIDCResponseAction();
        AuthenticationRequest req = AuthenticationRequest
                .parse("response_type=code&client_id=s6BhdRkqt3&login_hint=foo&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid%20profile&state=af0ifjsldkj&nonce=n-0S6_WzA2Mj");
        requestCtx = new RequestContextBuilder().setInboundMessage(req).buildRequestContext();
        final MessageContext<AuthenticationResponse> msgCtx = new MessageContext<AuthenticationResponse>();
        final ProfileRequestContext prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        prc.getInboundMessageContext().addSubcontext(new OIDCMetadataContext());
        prc.setOutboundMessageContext(msgCtx);
        action.initialize();
    }

    /**
     * Test that the action functions properly if there is no outbound message
     * context.
     */

    @SuppressWarnings({ "unchecked", "rawtypes" })
    @Test
    public void testNoOutboundMessageContext() throws Exception {
        final ProfileRequestContext prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        prc.setOutboundMessageContext(null);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_MSG_CTX);
    }

    /**
     * Test that the action functions properly if there is no oidc response
     * context.
     */

    @Test
    public void testNoOidcResponseContext() throws Exception {
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_MSG_CTX);
    }

    /**
     * Test that the action functions properly in success case.
     */

    @SuppressWarnings("rawtypes")
    @Test
    public void testSuccess() throws Exception {
        final ProfileRequestContext prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        prc.getOutboundMessageContext().addSubcontext(new OIDCAuthenticationResponseContext());
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
    }

    class MockOIDCResponseAction extends AbstractOIDCAuthenticationResponseAction {

    }
}