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