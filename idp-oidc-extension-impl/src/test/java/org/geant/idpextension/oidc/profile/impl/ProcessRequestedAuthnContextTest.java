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

import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.PreferredPrincipalContext;
import net.shibboleth.idp.authn.context.RequestedPrincipalContext;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import org.geant.idpextension.oidc.authn.principal.AuthenticationContextClassReferencePrincipal;
import org.opensaml.profile.action.EventIds;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.Test;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import com.nimbusds.openid.connect.sdk.ClaimsRequest.Entry;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;

/** {@link ProcessRequestedAuthnContext} unit test. */
public class ProcessRequestedAuthnContextTest extends BaseOIDCResponseActionTest {

    private ProcessRequestedAuthnContext action;

    private void init() throws ComponentInitializationException {
        action = new ProcessRequestedAuthnContext();
        action.initialize();
    }

    /**
     * Test that.
     * 
     * @throws ComponentInitializationException
     */
    @Test
    public void testNoAuthnContext() throws ComponentInitializationException {
        init();
        List<ACR> acrValues = new ArrayList<ACR>();
        acrValues.add(new ACR("1"));
        acrValues.add(new ACR("2"));
        AuthenticationRequest req =
                new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"), new ClientID("000123"),
                        URI.create("https://example.com/callback")).acrValues(acrValues).state(new State()).build();
        setAuthenticationRequest(req);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_PROFILE_CTX);
    }

    /**
     * Test no requested claims.
     * 
     * @throws ComponentInitializationException
     */
    @Test
    public void testNoReqACRSuccess() throws ComponentInitializationException {
        init();
        profileRequestCtx.addSubcontext(new AuthenticationContext());
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
    }

    /**
     * Test that acr param is handled correctly.
     * 
     * @throws ComponentInitializationException
     */
    @Test
    public void testSuccessACRParam() throws ComponentInitializationException {
        init();
        List<ACR> acrValues = new ArrayList<ACR>();
        acrValues.add(new ACR("1"));
        acrValues.add(new ACR("2"));
        AuthenticationRequest req = new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"),
                new ClientID("clientid"), URI.create("https://example.com/callback")).acrValues(acrValues)
                        .state(new State()).build();
        setAuthenticationRequest(req);
        AuthenticationContext ctx =
                (AuthenticationContext) profileRequestCtx.addSubcontext(new AuthenticationContext());
        final Event event = action.execute(requestCtx);
        PreferredPrincipalContext rpCtx = ctx.getSubcontext(PreferredPrincipalContext.class, false);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNotNull(rpCtx);
        Assert.assertTrue(rpCtx.getPreferredPrincipals().contains(new AuthenticationContextClassReferencePrincipal("1")));
        Assert.assertTrue(rpCtx.getPreferredPrincipals().contains(new AuthenticationContextClassReferencePrincipal("2")));
    }

    /**
     * Test that acr in claims request is handled correctly.
     * 
     * @throws ComponentInitializationException
     */
    @Test
    public void testSuccessRequestedClaims1() throws ComponentInitializationException {
        init();
        Entry entry = new Entry("acr", ClaimRequirement.VOLUNTARY, null, "1");
        ClaimsRequest claims = new ClaimsRequest();
        claims.addIDTokenClaim(entry);
        respCtx.setRequestedClaims(claims);
        AuthenticationRequest req = new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"),
                new ClientID("clientid"), URI.create("https://example.com/callback")).claims(claims).state(new State())
                        .build();
        setAuthenticationRequest(req);
        AuthenticationContext ctx =
                (AuthenticationContext) profileRequestCtx.addSubcontext(new AuthenticationContext());
        final Event event = action.execute(requestCtx);
        PreferredPrincipalContext ppCtx = ctx.getSubcontext(PreferredPrincipalContext.class, false);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNotNull(ppCtx);
        Assert.assertTrue(ppCtx.getPreferredPrincipals().contains(new AuthenticationContextClassReferencePrincipal("1")));
    }

    /**
     * Test that acr in claims request is handled correctly.
     * 
     * @throws ComponentInitializationException
     */
    @Test
    public void testSuccessRequestedClaims2() throws ComponentInitializationException {
        init();
        List<String> acrs = new ArrayList<String>();
        acrs.add("1");
        acrs.add("2");
        Entry entry = new Entry("acr", ClaimRequirement.ESSENTIAL, null, acrs);
        ClaimsRequest claims = new ClaimsRequest();
        claims.addIDTokenClaim(entry);
        respCtx.setRequestedClaims(claims);
        AuthenticationRequest req = new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"),
                new ClientID("clientid"), URI.create("https://example.com/callback")).claims(claims).state(new State())
                        .build();
        setAuthenticationRequest(req);
        AuthenticationContext ctx =
                (AuthenticationContext) profileRequestCtx.addSubcontext(new AuthenticationContext());
        final Event event = action.execute(requestCtx);
        RequestedPrincipalContext rpCtx = ctx.getSubcontext(RequestedPrincipalContext.class, false);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNotNull(rpCtx);
        Assert.assertTrue(rpCtx.getRequestedPrincipals().contains(new AuthenticationContextClassReferencePrincipal("1")));
        Assert.assertTrue(rpCtx.getRequestedPrincipals().contains(new AuthenticationContextClassReferencePrincipal("2")));
    }

    /**
     * Test that acr in claims request is handled correctly.
     * 
     * @throws ComponentInitializationException
     */
    @Test
    public void testSuccessRequestedClaims3() throws ComponentInitializationException {
        init();
        ClaimsRequest claims = new ClaimsRequest();
        claims.addIDTokenClaim("acr");
        AuthenticationRequest req = new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"),
                new ClientID("clientid"), URI.create("https://example.com/callback")).claims(claims).state(new State())
                        .build();
        setAuthenticationRequest(req);
        AuthenticationContext ctx =
                (AuthenticationContext) profileRequestCtx.addSubcontext(new AuthenticationContext());
        final Event event = action.execute(requestCtx);
        RequestedPrincipalContext rpCtx = ctx.getSubcontext(RequestedPrincipalContext.class, false);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNull(rpCtx);
    }

}