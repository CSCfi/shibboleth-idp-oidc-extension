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