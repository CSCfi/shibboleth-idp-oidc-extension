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
import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

import org.geant.idpextension.oidc.messaging.context.OIDCResponseContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;

/** {@link InitializeAuthenticationContext} unit test. */
public class FormOutboundMessageTest extends BaseOIDCResponseActionTest {

    private FormOutboundMessage action;

    private void init() throws ComponentInitializationException, URISyntaxException {
        action = new FormOutboundMessage();
        respCtx.setRedirectURI(new URI("http://example.org"));
        action.initialize();
    }

    /**
     * Test that action copes with no redirect uri in response context.
     * 
     * @throws ComponentInitializationException
     * @throws URISyntaxException
     */
    @Test
    public void testNoRedirectUri() throws ComponentInitializationException, URISyntaxException {
        init();
        respCtx.setRedirectURI(null);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_MSG_CTX);

    }

    /**
     * Test that action is able to form error message.
     * 
     * @throws ComponentInitializationException
     * @throws URISyntaxException
     */
    @Test
    public void testErrorMessage() throws ComponentInitializationException, URISyntaxException {
        init();
        respCtx.setErrorCode("error");
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        AuthenticationResponse resp = (AuthenticationResponse) ((MessageContext<?>) respCtx.getParent()).getMessage();
        Assert.assertTrue(resp instanceof AuthenticationErrorResponse);
    }

    /**
     * Test that action is able to cope with unsupported flow.
     * 
     * @throws ComponentInitializationException
     * @throws URISyntaxException
     * @throws ParseException
     */
    @SuppressWarnings({ "rawtypes", "unchecked" })
    @Test
    public void testUnsupportedFlow() throws ComponentInitializationException, URISyntaxException, ParseException {
        request = AuthenticationRequest
                .parse("response_type=code&client_id=s6BhdRkqt3&login_hint=foo&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid%20profile&state=af0ifjsldkj&nonce=n-0S6_WzA2Mj");
        requestCtx = new RequestContextBuilder().setInboundMessage(request).buildRequestContext();
        final MessageContext<AuthenticationResponse> msgCtx = new MessageContext<AuthenticationResponse>();
        final ProfileRequestContext prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        prc.setOutboundMessageContext(msgCtx);
        respCtx = new OIDCResponseContext();
        prc.getOutboundMessageContext().addSubcontext(respCtx);
        init();
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_MESSAGE);
    }

    /**
     * Test that action is able to form success message.
     * 
     * @throws ComponentInitializationException
     * @throws URISyntaxException
     */
    @Test
    public void testSuccessMessage() throws ComponentInitializationException, URISyntaxException {
        init();
        setIdTokenToResponseContext("iss", "sub", "aud", new Date(), new Date());
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        AuthenticationResponse resp = (AuthenticationResponse) ((MessageContext<?>) respCtx.getParent()).getMessage();
        Assert.assertTrue(resp instanceof AuthenticationSuccessResponse);
    }

}