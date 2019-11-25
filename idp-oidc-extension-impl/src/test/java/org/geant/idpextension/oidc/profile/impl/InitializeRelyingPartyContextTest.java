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