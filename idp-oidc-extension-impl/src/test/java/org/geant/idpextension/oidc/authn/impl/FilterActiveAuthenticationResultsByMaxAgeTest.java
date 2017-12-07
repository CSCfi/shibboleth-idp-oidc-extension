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
package org.geant.idpextension.oidc.authn.impl;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.security.auth.Subject;
import net.shibboleth.idp.authn.AuthenticationResult;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.springframework.webflow.execution.Event;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;

public class FilterActiveAuthenticationResultsByMaxAgeTest {

    private FilterActiveAuthenticationResultsByMaxAge action;
    private AuthenticationContext authnCtx;
    protected RequestContext requestCtx;

    @SuppressWarnings("rawtypes")
    private void init(String request) throws ParseException, ComponentInitializationException {
        AuthenticationRequest req = AuthenticationRequest.parse(request);
        requestCtx = new RequestContextBuilder().setInboundMessage(req).buildRequestContext();
        ProfileRequestContext prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        authnCtx = prc.getSubcontext(AuthenticationContext.class, true);
        List<AuthenticationResult> results = new ArrayList<AuthenticationResult>();
        Subject subject1 = new Subject();
        AuthenticationResult result1 = new AuthenticationResult("id1", subject1);
        // 10 seconds ago
        result1.setAuthenticationInstant(new Date().getTime() - 10000);
        Subject subject2 = new Subject();
        AuthenticationResult result2 = new AuthenticationResult("id2", subject2);
        // 5 seconds ago
        result2.setAuthenticationInstant(new Date().getTime() - 5000);
        results.add(result1);
        results.add(result2);
        authnCtx.setActiveResults(results);
        action = new FilterActiveAuthenticationResultsByMaxAge();
        action.initialize();
    }

    /**
     * Test that the action functions properly if there is no max age set.
     */
    @Test
    public void testNoMaxAge() throws Exception {
        init("response_type=code&client_id=s6BhdRkqt3&login_hint=foo&redirect_uri=https%3A%2F%2Fclient."
                + "example.org%2Fcb&scope=openid%20profile&state=af0ifjsldkj&nonce=n-0S6_WzA2Mj");
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertEquals(authnCtx.getActiveResults().size(), 2);
    }

    /**
     * Test that the action copes with no authentication context.
     */
    @SuppressWarnings("rawtypes")
    @Test
    public void testNoAuthContext() throws Exception {
        init("response_type=code&client_id=s6BhdRkqt3&login_hint=foo&redirect_uri=https%3A%2F%2Fclient."
                + "example.org%2Fcb&scope=openid%20profile&state=af0ifjsldkj&nonce=n-0S6_WzA2Mj&max_age=15");
        ProfileRequestContext prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        prc.removeSubcontext(AuthenticationContext.class);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_PROFILE_CTX);
    }
    
    /**
     * Test that the action functions properly if max age is more than age of
     * two existing results.
     */
    @Test
    public void testMaxAgePlenty() throws Exception {
        init("response_type=code&client_id=s6BhdRkqt3&login_hint=foo&redirect_uri=https%3A%2F%2Fclient."
                + "example.org%2Fcb&scope=openid%20profile&state=af0ifjsldkj&nonce=n-0S6_WzA2Mj&max_age=15");
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertEquals(authnCtx.getActiveResults().size(), 2);
    }

    /**
     * Test that the action functions properly if max age is in between of two
     * existing results.
     */
    @Test
    public void testMaxAgeSome() throws Exception {
        init("response_type=code&client_id=s6BhdRkqt3&login_hint=foo&redirect_uri=https%3A%2F%2Fclient."
                + "example.org%2Fcb&scope=openid%20profile&state=af0ifjsldkj&nonce=n-0S6_WzA2Mj&max_age=8");
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertEquals(authnCtx.getActiveResults().size(), 1);
    }

    /**
     * Test that the action functions properly if max age is below of two
     * existing results.
     */
    @Test
    public void testMaxAgeStrict() throws Exception {
        init("response_type=code&client_id=s6BhdRkqt3&login_hint=foo&redirect_uri=https%3A%2F%2Fclient."
                + "example.org%2Fcb&scope=openid%20profile&state=af0ifjsldkj&nonce=n-0S6_WzA2Mj&max_age=4");
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertEquals(authnCtx.getActiveResults().size(), 0);
    }

}
