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

import net.shibboleth.idp.consent.context.ConsentManagementContext;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;

import java.net.URI;
import java.security.NoSuchAlgorithmException;

import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.Prompt;

/** {@link RevokeConsent} unit test. */
public class RevokeConsentTest extends BaseOIDCResponseActionTest {

    private RevokeConsent action;

    @BeforeMethod
    private void init() throws ComponentInitializationException {
        action = new RevokeConsent();
        action.initialize();
        respCtx.setScope(new Scope());
    }

    /**
     * Test that action does nothing if offline_access or prompt=consent are not set.
     */
    @Test
    public void testNotRevoked() throws NoSuchAlgorithmException, ComponentInitializationException {
        action.execute(requestCtx);
        Assert.assertNull(profileRequestCtx.getSubcontext(ConsentManagementContext.class));
    }

    /**
     * Test that action revokes consent for offline_access.
     */
    @Test
    public void testRevokeOfflineAccess() throws NoSuchAlgorithmException, ComponentInitializationException {
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OFFLINE_ACCESS);
        respCtx.setScope(scope);
        ActionTestingSupport.assertProceedEvent(action.execute(requestCtx));
        Assert.assertTrue(profileRequestCtx.getSubcontext(ConsentManagementContext.class).getRevokeConsent());
    }

    /**
     * Test that action revokes consent for prompt = consent.
     */
    @Test
    public void testNoRevocationCache() throws NoSuchAlgorithmException, ComponentInitializationException {
        AuthenticationRequest req = new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"),
                new ClientID("000123"), URI.create("https://example.com/callback")).prompt(new Prompt("consent"))
                        .state(new State()).build();
        setAuthenticationRequest(req);
        action.initialize();
        ActionTestingSupport.assertProceedEvent(action.execute(requestCtx));
        Assert.assertTrue(profileRequestCtx.getSubcontext(ConsentManagementContext.class).getRevokeConsent());
    }

    /**
     * Test that action does not accept null strategy
     */
    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testNullStrategy() throws NoSuchAlgorithmException, ComponentInitializationException {
        action = new RevokeConsent();
        action.setPromptLookupStrategy(null);
    }

}