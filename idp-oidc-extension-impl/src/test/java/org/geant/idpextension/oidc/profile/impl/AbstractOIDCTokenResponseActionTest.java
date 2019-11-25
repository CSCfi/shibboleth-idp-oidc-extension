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

/** {@link AbstractOIDCTokenResponseAction} unit test. */
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
     * Test that the action functions properly if metadata context is missing.
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