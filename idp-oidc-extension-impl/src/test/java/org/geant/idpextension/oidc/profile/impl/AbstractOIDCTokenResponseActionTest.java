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

import java.net.URI;

import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseContext;
import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;

import net.shibboleth.idp.profile.RequestContextBuilder;

/** {@link InitializeAuthenticationContext} unit test. */
public class AbstractOIDCTokenResponseActionTest {

    private MockOIDCTokenResponseAction action;

    private RequestContext requestCtx;

    private OIDCMetadataContext oIDCMetadataContext;

    private OIDCAuthenticationResponseContext oIDCAuthenticationResponseContext;

    @SuppressWarnings("rawtypes")
    private ProfileRequestContext prc;

    @SuppressWarnings({"unchecked"})
    @BeforeMethod
    protected void setUp() throws Exception {
        action = new MockOIDCTokenResponseAction();
        oIDCMetadataContext = new OIDCMetadataContext();
        oIDCAuthenticationResponseContext = new OIDCAuthenticationResponseContext();
        AuthorizationCode code = new AuthorizationCode("xyz...");
        URI callback = new URI("https://client.com/callback");
        AuthorizationGrant codeGrant = new AuthorizationCodeGrant(code, callback);
        TokenRequest req = new TokenRequest(callback, new ClientID(), codeGrant);
        requestCtx = new RequestContextBuilder().setInboundMessage(req).buildRequestContext();
        final MessageContext<AuthenticationResponse> msgCtx = new MessageContext<AuthenticationResponse>();
        prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        prc.getInboundMessageContext().addSubcontext(oIDCMetadataContext);
        msgCtx.addSubcontext(oIDCAuthenticationResponseContext);
        prc.setOutboundMessageContext(msgCtx);
        action.initialize();
    }

    /**
     * Test that the action functions properly if there is no outbound message context.
     */

    @SuppressWarnings({"unchecked"})
    @Test
    public void testNoOutboundMessageContext() throws Exception {
        prc.setOutboundMessageContext(null);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_MSG_CTX);
    }

    /**
     * Test that the action functions properly if there is no oidc response context.
     */

    @Test
    public void testNoOidcResponseContext() throws Exception {
        prc.getOutboundMessageContext().removeSubcontext(oIDCAuthenticationResponseContext);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_MSG_CTX);
    }

    /**
     * Test that the action functions properly in success case.
     */

    @Test
    public void testNoMetadataContext() throws Exception {
        prc.getInboundMessageContext().removeSubcontext(oIDCMetadataContext);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_MSG_CTX);
    }

    /**
     * Test that the action functions properly in success case.
     */

    @Test
    public void testSuccess() throws Exception {
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
    }

    class MockOIDCTokenResponseAction extends AbstractOIDCTokenResponseAction {

    }
}