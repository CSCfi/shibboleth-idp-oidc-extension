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