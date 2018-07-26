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
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.idp.session.IdPSession;
import net.shibboleth.idp.session.SPSession;
import net.shibboleth.idp.session.SessionException;
import net.shibboleth.idp.session.SessionResolver;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.Set;
import org.geant.idpextension.oidc.token.support.AccessTokenClaimsSet;
import org.geant.idpextension.oidc.token.support.TokenClaimsSet;
import org.opensaml.profile.action.EventIds;
import org.springframework.webflow.execution.Event;
import org.testng.annotations.Test;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.ACR;

/** {@link ValidateUserPresence} unit test. */
public class ValidateUserPresenceTest extends BaseOIDCResponseActionTest {

    private ValidateUserPresence action;

    private long timeOut = 10000;

    private void init(boolean resolve) throws ComponentInitializationException, URISyntaxException {
        action = new ValidateUserPresence(new MockSessionResolver(resolve));
        action.setSessionTimeout(timeOut);
        action.initialize();
        TokenClaimsSet claims = new AccessTokenClaimsSet(new idStrat(), new ClientID(), "issuer", "userPrin", "subject",
                new ACR("0"), new Date(), new Date(System.currentTimeMillis() - 1), new Nonce(), new Date(),
                new URI("http://example.com"), new Scope(), "id", null, null, null, null, null);
        respCtx.setTokenClaimsSet(claims);
        respCtx.setScope(new Scope("openid"));
    }

    /**
     * Test that action construction fails if session resolver is null.
     */
    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testNoSessionResolver() throws NoSuchAlgorithmException, ComponentInitializationException {
        action = new ValidateUserPresence(null);
    }

    /**
     * Test that offline_access bypasses all verifications.
     */
    @Test
    public void testOfflineAccessSuccess()
            throws NoSuchAlgorithmException, ComponentInitializationException, URISyntaxException {
        init(false);
        respCtx.setScope(new Scope("offline_access"));
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
    }

    /**
     * Test basic success case. There is user presence.
     */
    @Test
    public void testUserPresenceSuccess()
            throws NoSuchAlgorithmException, ComponentInitializationException, URISyntaxException {
        init(true);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
    }

    /**
     * User presence has timed out.
     */
    @Test
    public void testUserPresenceFail()
            throws NoSuchAlgorithmException, ComponentInitializationException, URISyntaxException {
        timeOut = 1;
        init(true);
        timeOut = 10000;
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.ACCESS_DENIED);
    }

    /**
     * Test no presence case.
     * 
     * @throws ComponentInitializationException
     * @throws NoSuchAlgorithmException
     * @throws URISyntaxException
     */
    @Test
    public void testNoPresence() throws NoSuchAlgorithmException, ComponentInitializationException, URISyntaxException {
        init(false);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.ACCESS_DENIED);
    }

    class MockSessionResolver implements SessionResolver {

        boolean resolves;

        MockSessionResolver(boolean resolves) {
            this.resolves = resolves;
        }

        @Override
        public Iterable<IdPSession> resolve(CriteriaSet criteria) throws ResolverException {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public IdPSession resolveSingle(CriteriaSet criteria) throws ResolverException {
            if (resolves) {
                return new MockIdPSession();
            }
            throw new ResolverException("failed miserably");
        }

        class MockIdPSession implements IdPSession {

            @Override
            public String getId() {
                // TODO Auto-generated method stub
                return null;
            }

            @Override
            public String getPrincipalName() {
                // TODO Auto-generated method stub
                return null;
            }

            @Override
            public long getCreationInstant() {
                // TODO Auto-generated method stub
                return 0;
            }

            @Override
            public long getLastActivityInstant() {
                return System.currentTimeMillis()-2;
            }

            @Override
            public boolean checkAddress(String address) throws SessionException {
                // TODO Auto-generated method stub
                return false;
            }

            @Override
            public boolean checkTimeout() throws SessionException {
                // TODO Auto-generated method stub
                return false;
            }

            @Override
            public Set<AuthenticationResult> getAuthenticationResults() {
                // TODO Auto-generated method stub
                return null;
            }

            @Override
            public AuthenticationResult getAuthenticationResult(String flowId) {
                // TODO Auto-generated method stub
                return null;
            }

            @Override
            public AuthenticationResult addAuthenticationResult(AuthenticationResult result) throws SessionException {
                // TODO Auto-generated method stub
                return null;
            }

            @Override
            public void updateAuthenticationResultActivity(AuthenticationResult result) throws SessionException {
                // TODO Auto-generated method stub

            }

            @Override
            public boolean removeAuthenticationResult(AuthenticationResult result) throws SessionException {
                // TODO Auto-generated method stub
                return false;
            }

            @Override
            public Set<SPSession> getSPSessions() {
                // TODO Auto-generated method stub
                return null;
            }

            @Override
            public SPSession getSPSession(String serviceId) {
                // TODO Auto-generated method stub
                return null;
            }

            @Override
            public SPSession addSPSession(SPSession spSession) throws SessionException {
                // TODO Auto-generated method stub
                return null;
            }

            @Override
            public boolean removeSPSession(SPSession spSession) throws SessionException {
                // TODO Auto-generated method stub
                return false;
            }

        }

    }
}