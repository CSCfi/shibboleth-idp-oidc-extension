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
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.testng.annotations.Test;

import com.nimbusds.openid.connect.sdk.AuthenticationRequest;

import net.shibboleth.idp.profile.RequestContextBuilder;

/** {@link AbstractOIDCAuthenticationRequestAction} unit test. */
public class AbstractOIDCAuthenticationRequestActionTest {

    /**
     * Test that the action functions properly if there is no inbound message
     * context.
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testNoInboundMessageContext() throws Exception {

        final RequestContext requestCtx = new RequestContextBuilder().buildRequestContext();
        @SuppressWarnings("rawtypes")
        final ProfileRequestContext prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        prc.setInboundMessageContext(null);
        final MockOIDCRequestAction action = new MockOIDCRequestAction();
        action.initialize();
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_MSG_CTX);
    }

    /** Test that the action functions properly if there is no inbound message. */
    @Test
    public void testNoInboundMessage() throws Exception {
        final RequestContext requestCtx = new RequestContextBuilder().setInboundMessage(null).buildRequestContext();
        final MockOIDCRequestAction action = new MockOIDCRequestAction();
        action.initialize();
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_MSG_CTX);
    }

    /**
     * Test that the action functions properly if the inbound message is a oidc
     * authentication request.
     */
    @Test
    public void testSuccess() throws Exception {
        AuthenticationRequest req = AuthenticationRequest
                .parse("response_type=code&client_id=s6BhdRkqt3&login_hint=foo&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid%20profile&state=af0ifjsldkj&nonce=n-0S6_WzA2Mj");
        final RequestContext requestCtx = new RequestContextBuilder().setInboundMessage(req).buildRequestContext();
        final MockOIDCRequestAction action = new MockOIDCRequestAction();
        action.initialize();
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
      }

    class MockOIDCRequestAction extends AbstractOIDCAuthenticationRequestAction{
        
    }
}