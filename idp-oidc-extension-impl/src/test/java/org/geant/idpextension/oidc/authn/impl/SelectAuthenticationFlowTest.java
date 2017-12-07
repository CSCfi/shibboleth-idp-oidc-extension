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

import java.security.Principal;
import java.util.Arrays;
import java.util.List;

import javax.security.auth.Subject;

import net.shibboleth.idp.authn.AuthenticationResult;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.RequestedPrincipalContext;
import net.shibboleth.idp.authn.impl.BaseAuthenticationContextTest;
import net.shibboleth.idp.authn.principal.TestPrincipal;
import net.shibboleth.idp.authn.principal.impl.ExactPrincipalEvalPredicateFactory;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

import org.geant.idpextension.oidc.messaging.context.OIDCRequestedPrincipalContext;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.google.common.collect.ImmutableList;

/**
 * Based on {@link net.shibboleth.idp.authn.impl.SelectAuthenticationFlowTest}.
 * 
 * Verifies that the original test cases for
 * {@link net.shibboleth.idp.authn.impl.SelectAuthenticationFlow} still pass for
 * {@link SelectAuthenticationFlow}.
 * 
 * There is one new test, testRequestNoMatchNotEssential, testing the new
 * functionality.
 * 
 * 
 */
public class SelectAuthenticationFlowTest extends BaseAuthenticationContextTest {
    private SelectAuthenticationFlow action;

    @BeforeMethod
    public void setUp() throws Exception {
        super.setUp();

        action = new SelectAuthenticationFlow();
        action.initialize();
    }

    @Test
    public void testNoRequestNoneActive() {
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class);

        final Event event = action.execute(src);

        Assert.assertNull(authCtx.getAuthenticationResult());
        Assert.assertEquals(authCtx.getAttemptedFlow(), authCtx.getPotentialFlows().get(event.getId()));
        Assert.assertEquals(authCtx.getAttemptedFlow().getId(), "test1");
    }

    @Test
    public void testNoRequestNoneActivePassive() {
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class);
        authCtx.setIsPassive(true);

        final Event event = action.execute(src);

        Assert.assertNull(authCtx.getAuthenticationResult());
        Assert.assertEquals(authCtx.getAttemptedFlow(), authCtx.getPotentialFlows().get(event.getId()));
        Assert.assertEquals(authCtx.getAttemptedFlow().getId(), "test2");
    }

    @Test
    public void testNoRequestNoneActiveIntermediate() {
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class);
        authCtx.getIntermediateFlows().put("test1", authCtx.getPotentialFlows().get("test1"));

        final Event event = action.execute(src);

        Assert.assertNull(authCtx.getAuthenticationResult());
        Assert.assertEquals(authCtx.getAttemptedFlow(), authCtx.getPotentialFlows().get(event.getId()));
        Assert.assertEquals(authCtx.getAttemptedFlow().getId(), "test2");
    }

    @Test
    public void testNoRequestActive() {
        final AuthenticationResult active = new AuthenticationResult("test2", new Subject());
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class);
        authCtx.setActiveResults(Arrays.asList(active));

        final Event event = action.execute(src);

        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertEquals(active, authCtx.getAuthenticationResult());
    }

    @Test
    public void testNoRequestInitialForced() {
        final AuthenticationResult active = new AuthenticationResult("test2", new Subject());
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class);
        authCtx.setForceAuthn(true);
        authCtx.setInitialAuthenticationResult(active);
        authCtx.setActiveResults(Arrays.asList(active));

        final Event event = action.execute(src);

        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertEquals(active, authCtx.getAuthenticationResult());
    }

    @Test
    public void testNoRequestForced() {
        final AuthenticationResult active = new AuthenticationResult("test2", new Subject());
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class);
        authCtx.setActiveResults(Arrays.asList(active));
        authCtx.setForceAuthn(true);

        final Event event = action.execute(src);

        Assert.assertNull(authCtx.getAuthenticationResult());
        Assert.assertEquals(authCtx.getAttemptedFlow(), authCtx.getPotentialFlows().get(event.getId()));
    }

    @Test
    public void testRequestNoMatch() {
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class);
        final RequestedPrincipalContext rpc = new RequestedPrincipalContext();
        rpc.setOperator("exact");
        rpc.setRequestedPrincipals(Arrays.<Principal> asList(new TestPrincipal("foo")));
        authCtx.addSubcontext(rpc, true);

        final Event event = action.execute(src);

        ActionTestingSupport.assertEvent(event, AuthnEventIds.REQUEST_UNSUPPORTED);
    }

    @Test
    public void testRequestNoMatchNotEssential() {
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class);
        final OIDCRequestedPrincipalContext oidcRPCtx = authCtx
                .getSubcontext(OIDCRequestedPrincipalContext.class, true);
        oidcRPCtx.setEssential(false);
        final RequestedPrincipalContext rpc = new RequestedPrincipalContext();
        rpc.setOperator("exact");
        rpc.setRequestedPrincipals(Arrays.<Principal> asList(new TestPrincipal("foo")));
        authCtx.addSubcontext(rpc, true);
        final Event event = action.execute(src);
        Assert.assertNull(authCtx.getAuthenticationResult());
        Assert.assertEquals(authCtx.getAttemptedFlow(), authCtx.getPotentialFlows().get(event.getId()));
        Assert.assertEquals(authCtx.getAttemptedFlow().getId(), "test1");
    }

    @Test
    public void testRequestNoneActive() {
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class);
        final List<Principal> principals = Arrays.<Principal> asList(new TestPrincipal("test3"));
        final RequestedPrincipalContext rpc = new RequestedPrincipalContext();
        rpc.getPrincipalEvalPredicateFactoryRegistry().register(TestPrincipal.class, "exact",
                new ExactPrincipalEvalPredicateFactory());
        rpc.setOperator("exact");
        rpc.setRequestedPrincipals(principals);
        authCtx.addSubcontext(rpc, true);
        authCtx.getPotentialFlows().get("test3").setSupportedPrincipals(principals);

        action.execute(src);

        Assert.assertNull(authCtx.getAuthenticationResult());
        Assert.assertEquals(authCtx.getAttemptedFlow().getId(), "test3");
    }

    @Test
    public void testRequestNoneActiveIntermediate() {
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class);
        authCtx.getIntermediateFlows().put("test2", authCtx.getPotentialFlows().get("test2"));
        final List<Principal> principals = Arrays.<Principal> asList(new TestPrincipal("test3"), new TestPrincipal(
                "test2"));
        final RequestedPrincipalContext rpc = new RequestedPrincipalContext();
        rpc.getPrincipalEvalPredicateFactoryRegistry().register(TestPrincipal.class, "exact",
                new ExactPrincipalEvalPredicateFactory());
        rpc.setOperator("exact");
        rpc.setRequestedPrincipals(principals);
        authCtx.addSubcontext(rpc, true);
        authCtx.getPotentialFlows().get("test2").setSupportedPrincipals(principals);
        authCtx.getPotentialFlows().get("test3").setSupportedPrincipals(principals);

        action.execute(src);

        Assert.assertNull(authCtx.getAuthenticationResult());
        Assert.assertEquals(authCtx.getAttemptedFlow().getId(), "test3");
    }

    @Test
    public void testRequestPickInactive() {
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class);
        final List<Principal> principals = Arrays.<Principal> asList(new TestPrincipal("test3"), new TestPrincipal(
                "test2"));
        final RequestedPrincipalContext rpc = new RequestedPrincipalContext();
        rpc.getPrincipalEvalPredicateFactoryRegistry().register(TestPrincipal.class, "exact",
                new ExactPrincipalEvalPredicateFactory());
        rpc.setOperator("exact");
        rpc.setRequestedPrincipals(principals);
        authCtx.addSubcontext(rpc, true);
        final AuthenticationResult active = new AuthenticationResult("test2", new Subject());
        active.getSubject().getPrincipals().add(new TestPrincipal("test2"));
        authCtx.setActiveResults(Arrays.asList(active));
        authCtx.getPotentialFlows().get("test3").setSupportedPrincipals(ImmutableList.of(principals.get(0)));

        action.execute(src);

        Assert.assertNull(authCtx.getAuthenticationResult());
        Assert.assertEquals(authCtx.getAttemptedFlow(), authCtx.getPotentialFlows().get("test3"));
    }

    @Test
    public void testRequestPickInactiveInitial() {
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class);
        final List<Principal> principals = Arrays.<Principal> asList(new TestPrincipal("test3"), new TestPrincipal(
                "test2"));
        final RequestedPrincipalContext rpc = new RequestedPrincipalContext();
        rpc.getPrincipalEvalPredicateFactoryRegistry().register(TestPrincipal.class, "exact",
                new ExactPrincipalEvalPredicateFactory());
        rpc.setOperator("exact");
        rpc.setRequestedPrincipals(principals);
        authCtx.addSubcontext(rpc, true);
        final AuthenticationResult active = new AuthenticationResult("test2", new Subject());
        active.getSubject().getPrincipals().add(new TestPrincipal("test2"));
        authCtx.setActiveResults(Arrays.asList(active));
        authCtx.setInitialAuthenticationResult(active);
        authCtx.setForceAuthn(true);
        authCtx.getPotentialFlows().get("test3").setSupportedPrincipals(ImmutableList.of(principals.get(0)));

        action.execute(src);

        Assert.assertNull(authCtx.getAuthenticationResult());
        Assert.assertEquals(authCtx.getAttemptedFlow(), authCtx.getPotentialFlows().get("test3"));
    }

    @Test
    public void testRequestPickActiveInitial() throws ComponentInitializationException {
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class);
        final List<Principal> principals = Arrays.<Principal> asList(new TestPrincipal("test3"), new TestPrincipal(
                "test2"));
        final RequestedPrincipalContext rpc = new RequestedPrincipalContext();
        rpc.getPrincipalEvalPredicateFactoryRegistry().register(TestPrincipal.class, "exact",
                new ExactPrincipalEvalPredicateFactory());
        rpc.setOperator("exact");
        rpc.setRequestedPrincipals(principals);
        authCtx.addSubcontext(rpc, true);
        final AuthenticationResult active = new AuthenticationResult("test2", new Subject());
        active.getSubject().getPrincipals().add(new TestPrincipal("test2"));
        authCtx.setActiveResults(Arrays.asList(active));
        authCtx.setInitialAuthenticationResult(active);
        authCtx.setForceAuthn(true);
        authCtx.getPotentialFlows().get("test3").setSupportedPrincipals(ImmutableList.of(principals.get(0)));

        action = new SelectAuthenticationFlow();
        action.setFavorSSO(true);
        action.initialize();
        action.execute(src);

        Assert.assertEquals(active, authCtx.getAuthenticationResult());
    }

    @Test
    public void testRequestPickActive() {
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class);
        final List<Principal> principals = Arrays.<Principal> asList(new TestPrincipal("test3"), new TestPrincipal(
                "test2"));
        final RequestedPrincipalContext rpc = new RequestedPrincipalContext();
        rpc.getPrincipalEvalPredicateFactoryRegistry().register(TestPrincipal.class, "exact",
                new ExactPrincipalEvalPredicateFactory());
        rpc.setOperator("exact");
        rpc.setRequestedPrincipals(principals);
        authCtx.addSubcontext(rpc, true);
        final AuthenticationResult active = new AuthenticationResult("test3", new Subject());
        active.getSubject().getPrincipals().add(new TestPrincipal("test3"));
        authCtx.setActiveResults(Arrays.asList(active));
        authCtx.getPotentialFlows().get("test3").setSupportedPrincipals(ImmutableList.of(principals.get(0)));

        final Event event = action.execute(src);

        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertEquals(active, authCtx.getAuthenticationResult());
    }

    @Test
    public void testRequestFavorSSO() throws ComponentInitializationException {
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class);
        final List<Principal> principals = Arrays.<Principal> asList(new TestPrincipal("test3"), new TestPrincipal(
                "test2"));
        final RequestedPrincipalContext rpc = new RequestedPrincipalContext();
        rpc.getPrincipalEvalPredicateFactoryRegistry().register(TestPrincipal.class, "exact",
                new ExactPrincipalEvalPredicateFactory());
        rpc.setOperator("exact");
        rpc.setRequestedPrincipals(principals);
        authCtx.addSubcontext(rpc, true);
        final AuthenticationResult active = new AuthenticationResult("test2", new Subject());
        active.getSubject().getPrincipals().add(new TestPrincipal("test2"));
        authCtx.setActiveResults(Arrays.asList(active));
        authCtx.getPotentialFlows().get("test3").setSupportedPrincipals(ImmutableList.of(principals.get(0)));

        action = new SelectAuthenticationFlow();
        action.setFavorSSO(true);
        action.initialize();
        final Event event = action.execute(src);

        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertEquals(active, authCtx.getAuthenticationResult());
    }

}
