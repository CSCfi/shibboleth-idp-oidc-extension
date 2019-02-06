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