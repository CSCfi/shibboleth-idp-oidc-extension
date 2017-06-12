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
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.testng.annotations.Test;

import com.nimbusds.openid.connect.sdk.AuthenticationRequest;

import net.shibboleth.idp.profile.RequestContextBuilder;

/** {@link InitializeAuthenticationContext} unit test. */
public class AbstractOIDCRequestActionTest {

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

    class MockOIDCRequestAction extends AbstractOIDCRequestAction{
        
    }
}