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

import net.shibboleth.idp.authn.AuthenticationResult;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;

import java.net.URI;

import javax.security.auth.Subject;

import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Prompt;

import net.shibboleth.idp.profile.RequestContextBuilder;

/** {@link InitializeAuthenticationContext} unit test. */
public class InitializeAuthenticationContextTest {

    private InitializeAuthenticationContext action;

    private RequestContext requestCtx;

    @SuppressWarnings("rawtypes")
    private ProfileRequestContext prc;

    @BeforeMethod
    public void init() throws ComponentInitializationException, ParseException {
        action = new InitializeAuthenticationContext();
        action.initialize();
        AuthenticationRequest req = new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"),
                new ClientID("000123"), URI.create("https://example.com/callback")).state(new State())
                        .prompt(new Prompt(Prompt.Type.LOGIN)).loginHint("foo").build();
        requestCtx = new RequestContextBuilder().setInboundMessage(req).buildRequestContext();
        prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        AuthenticationContext existingContext = new AuthenticationContext();
        existingContext.setAuthenticationResult(new AuthenticationResult("flowId", new Subject()));
        prc.addSubcontext(existingContext);
        prc.getOutboundMessageContext().addSubcontext(new OIDCAuthenticationResponseContext());
    }

    /**
     * Test forced, hinted name and existing initial result
     */
    @Test
    public void testOIDCAuthnRequestForcedWithHintedName() throws Exception {
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        AuthenticationContext authnCtx = prc.getSubcontext(AuthenticationContext.class, false);
        Assert.assertNotNull(authnCtx);
        Assert.assertTrue(authnCtx.isForceAuthn());
        Assert.assertFalse(authnCtx.isPassive());
        Assert.assertEquals(authnCtx.getMaxAge(), 0);
        Assert.assertEquals(authnCtx.getHintedName(), "foo");
        Assert.assertNotNull(prc.getSubcontext(AuthenticationContext.class).getInitialAuthenticationResult());
    }

    /**
     * Test passive max 5s
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testOIDCAuthnRequestPassive() throws Exception {
        AuthenticationRequest req = new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"),
                new ClientID("000123"), URI.create("https://example.com/callback")).state(new State())
                        .prompt(new Prompt(Prompt.Type.NONE)).maxAge(5).build();
        prc.getInboundMessageContext().setMessage(req);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        AuthenticationContext authnCtx = prc.getSubcontext(AuthenticationContext.class, false);
        Assert.assertNotNull(authnCtx);
        Assert.assertFalse(authnCtx.isForceAuthn());
        Assert.assertTrue(authnCtx.isPassive());
        Assert.assertEquals(authnCtx.getMaxAge(), 5000);
    }

    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testSetNullLoginHintLookupStrategy() throws Exception {
        action = new InitializeAuthenticationContext();
        action.setLoginHintLookupStrategy(null);
    }

    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testSetNullPromptLookupStrategy() throws Exception {
        action = new InitializeAuthenticationContext();
        action.setPromptLookupStrategy(null);
    }

    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testSetNullMaxAgeLookupStrategy() throws Exception {
        action = new InitializeAuthenticationContext();
        action.setMaxAgeLookupStrategy(null);
    }

}