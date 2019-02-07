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
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;

import java.net.URI;
import java.util.Date;

import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;

/** {@link InitializeRelyingPartyContext} unit test. */
public class InitializeRelyingPartyContextTest {

    private InitializeRelyingPartyContext action;

    private RequestContext requestCtx;

    @SuppressWarnings("rawtypes")
    private ProfileRequestContext prc;

    private OIDCMetadataContext metadataCtx;

    @BeforeMethod
    public void init() throws ComponentInitializationException {
        action = new InitializeRelyingPartyContext();
        action.initialize();
        AuthenticationRequest req = new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"),
                new ClientID("000123"), URI.create("https://example.com/callback")).state(new State()).build();
        requestCtx = new RequestContextBuilder().setInboundMessage(req).buildRequestContext();
        prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        metadataCtx = (OIDCMetadataContext) prc.getInboundMessageContext().addSubcontext(new OIDCMetadataContext());
        OIDCClientInformation information =
                new OIDCClientInformation(new ClientID("000123"), new Date(), new OIDCClientMetadata(), new Secret());
        metadataCtx.setClientInformation(information);
    }

    /** Test that rp context has been initialized and rp is verified. */
    @Test
    public void testSuccessVerified() {
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertEquals(prc.getSubcontext(RelyingPartyContext.class).getRelyingPartyId(), "000123");
        Assert.assertTrue(prc.getSubcontext(RelyingPartyContext.class).isVerified());
    }

    /** Test that rp context has been initialized and rp is not verified. */
    @Test
    public void testSuccessUnverified() {
        metadataCtx.setClientInformation(null);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertEquals(prc.getSubcontext(RelyingPartyContext.class).getRelyingPartyId(), "000123");
        Assert.assertFalse(prc.getSubcontext(RelyingPartyContext.class).isVerified());
    }

    /** Test that rp context has been initialized and rp is not verified, no metadata context set. */
    @Test
    public void testSuccessUnverifiedNoMetadata() {
        prc.getInboundMessageContext().removeSubcontext(OIDCMetadataContext.class);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertEquals(prc.getSubcontext(RelyingPartyContext.class).getRelyingPartyId(), "000123");
        Assert.assertFalse(prc.getSubcontext(RelyingPartyContext.class).isVerified());
    }

    /** Test case of not being able to get client id from the request. */
    @Test
    public void testSuccessNoRequest() throws ComponentInitializationException {
        requestCtx = new RequestContextBuilder().buildRequestContext();
        prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_MSG_CTX);
    }

    /** Test case of setting null strategy. */
    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testFailsNullOidcMetadataContextLookupStrategy() {
        action = new InitializeRelyingPartyContext();
        action.setOidcMetadataContextLookupStrategy(null);
    }

    /** Test case of setting null strategy. */
    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testFailsNullClientIDLookupStrategy() {
        action = new InitializeRelyingPartyContext();
        action.setClientIDLookupStrategy(null);
    }

    /** Test case of setting null strategy. */
    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testFailsNullRelyingPartyContextCreationStrategy() {
        action = new InitializeRelyingPartyContext();
        action.setRelyingPartyContextCreationStrategy(null);
    }

}