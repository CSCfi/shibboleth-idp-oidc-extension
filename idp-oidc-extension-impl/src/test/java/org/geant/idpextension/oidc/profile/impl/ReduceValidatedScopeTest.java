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
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import java.net.URI;
import java.net.URISyntaxException;

import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseTokenClaimsContext;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.Test;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.token.RefreshToken;

/** {@link ReduceValidatedScope} unit test. */
public class ReduceValidatedScopeTest extends BaseOIDCResponseActionTest {

    private ReduceValidatedScope action;

    private void init() throws ComponentInitializationException {
        action = new ReduceValidatedScope();
        action.initialize();
        OIDCAuthenticationResponseTokenClaimsContext tokenClaimsCtx =
                (OIDCAuthenticationResponseTokenClaimsContext) respCtx
                        .addSubcontext(new OIDCAuthenticationResponseTokenClaimsContext());
        tokenClaimsCtx.getClaims().setClaim("gen", "value1");
        tokenClaimsCtx.getIdtokenClaims().setClaim("idtoken", "value2");
        tokenClaimsCtx.getUserinfoClaims().setClaim("userinfo", "value3");
    }

    /**
     * Test that scope reducing works as expected allowing only predefined new scopes and removing token delivery
     * attributes if scope is reduced.
     * 
     * @throws ComponentInitializationException
     * @throws URISyntaxException
     */
    @Test
    public void testSuccessReduced() throws ComponentInitializationException, URISyntaxException {
        init();
        Scope scope = new Scope();
        scope.add("1");
        scope.add("2");
        scope.add("3");
        respCtx.setScope(scope);
        scope = new Scope();
        scope.add("2");
        scope.add("4");
        TokenRequest req =
                new TokenRequest(new URI("http://example.com"), new RefreshTokenGrant(new RefreshToken()), scope);
        setTokenRequest(req);
        final Event event = action.execute(requestCtx);
        Scope reducedScope = respCtx.getScope();
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertTrue(reducedScope.contains("2"));
        Assert.assertTrue(reducedScope.size() == 1);
        Assert.assertNull(respCtx.getSubcontext(OIDCAuthenticationResponseTokenClaimsContext.class, false));
    }

    /**
     * Test that scope reducing works as expected allowing only predefined new scopes and not removing token delivery
     * attributes if scope is not reduced.
     * 
     * @throws ComponentInitializationException
     * @throws URISyntaxException
     */
    @Test
    public void testSuccessNotReduced() throws ComponentInitializationException, URISyntaxException {
        init();
        Scope scope = new Scope();
        scope.add("1");
        scope.add("2");
        scope.add("3");
        respCtx.setScope(scope);
        scope = new Scope();
        scope.add("1");
        scope.add("2");
        scope.add("3");
        scope.add("4");
        TokenRequest req =
                new TokenRequest(new URI("http://example.com"), new RefreshTokenGrant(new RefreshToken()), scope);
        setTokenRequest(req);
        final Event event = action.execute(requestCtx);
        Scope reducedScope = respCtx.getScope();
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertTrue(!reducedScope.contains("4"));
        Assert.assertTrue(reducedScope.size() == 3);
        Assert.assertNotNull(respCtx.getSubcontext(OIDCAuthenticationResponseTokenClaimsContext.class, false));
    }

    /**
     * Test that scope reducing works as expected when there is no new scopes defined.
     * 
     * @throws ComponentInitializationException
     * @throws URISyntaxException
     */
    @Test
    public void testSuccessNoScope() throws ComponentInitializationException, URISyntaxException {
        init();
        Scope scope = new Scope();
        scope.add("1");
        scope.add("2");
        scope.add("3");
        respCtx.setScope(scope);
        TokenRequest req = new TokenRequest(new URI("http://example.com"), new RefreshTokenGrant(new RefreshToken()));
        setTokenRequest(req);
        final Event event = action.execute(requestCtx);
        Scope reducedScope = respCtx.getScope();
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertTrue(reducedScope.size() == 3);
        Assert.assertNotNull(respCtx.getSubcontext(OIDCAuthenticationResponseTokenClaimsContext.class, false));
    }

}