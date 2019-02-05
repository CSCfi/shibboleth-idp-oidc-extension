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
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.PreferredPrincipalContext;
import net.shibboleth.idp.authn.context.RequestedPrincipalContext;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.Subject;

import org.geant.idpextension.oidc.authn.principal.AuthenticationContextClassReferencePrincipal;
import org.opensaml.profile.action.EventIds;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.Test;

import com.nimbusds.openid.connect.sdk.claims.ACR;

/** {@link SetAuthenticationContextClassReferenceToResponseContext} unit test. */
public class SetAuthenticationContextClassReferenceToResponseContextTest extends BaseOIDCResponseActionTest {

    private SetAuthenticationContextClassReferenceToResponseContext action;

    private List<Principal> principals;

    private void init() throws ComponentInitializationException {
        action = new SetAuthenticationContextClassReferenceToResponseContext();
        action.initialize();
        profileRequestCtx.addSubcontext(new AuthenticationContext());
        principals = new ArrayList<>();
        principals.add(new AuthenticationContextClassReferencePrincipal("1"));
        principals.add(new AuthenticationContextClassReferencePrincipal("2"));
        principals.add(new AuthenticationContextClassReferencePrincipal("3"));
        final RequestedPrincipalContext rpCtx = new RequestedPrincipalContext();
        rpCtx.setOperator(AuthnContextComparisonTypeEnumeration.EXACT.toString());
        rpCtx.setRequestedPrincipals(principals);
        profileRequestCtx.getSubcontext(AuthenticationContext.class, true).addSubcontext(rpCtx, true);
        Subject authSubject = new Subject();
        authSubject.getPrincipals().add(new AuthenticationContextClassReferencePrincipal("2"));
        authSubject.getPrincipals().add(new AuthenticationContextClassReferencePrincipal("4"));
        AuthenticationResult result = new AuthenticationResult("flowId", authSubject);
        profileRequestCtx.getSubcontext(AuthenticationContext.class).setAuthenticationResult(result);
    }

    /**
     * Test that action handles case of requested acr of 1,2 and 3 while the result contains 2 and 4.
     */
    @Test
    public void testSuccessRequestedACR() throws ComponentInitializationException {
        init();
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertEquals(respCtx.getAcr(), new ACR("2"));
    }

    /**
     * Test that action handles case of preferred acr of 1,2 and 3 while the result contains 2 and 4.
     */
    @Test
    public void testSuccessPrefereddedACR() throws ComponentInitializationException {
        init();
        profileRequestCtx.getSubcontext(AuthenticationContext.class).removeSubcontext(RequestedPrincipalContext.class);
        final PreferredPrincipalContext ppCtx = new PreferredPrincipalContext();
        ppCtx.setPreferredPrincipals(principals);
        profileRequestCtx.getSubcontext(AuthenticationContext.class, true).addSubcontext(ppCtx, true);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertEquals(respCtx.getAcr(), new ACR("2"));
    }

    /**
     * Test that action handles case of preferred acr of 1 while the result contains 2 and 4.
     */
    @Test
    public void testSuccessPrefereddedACRNotMatching() throws ComponentInitializationException {
        init();
        profileRequestCtx.getSubcontext(AuthenticationContext.class).removeSubcontext(RequestedPrincipalContext.class);
        final PreferredPrincipalContext ppCtx = new PreferredPrincipalContext();
        principals.clear();
        principals.add(new AuthenticationContextClassReferencePrincipal("1"));
        ppCtx.setPreferredPrincipals(principals);
        profileRequestCtx.getSubcontext(AuthenticationContext.class, true).addSubcontext(ppCtx, true);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertTrue(respCtx.getAcr().equals(new ACR("2")) || respCtx.getAcr().equals(new ACR("4")));
    }

    /**
     * Test that action handles case of preferred acr of 1 while the result contains none.
     */
    @Test
    public void testSuccessPrefereddedACRNotMatching2() throws ComponentInitializationException {
        init();
        profileRequestCtx.getSubcontext(AuthenticationContext.class).removeSubcontext(RequestedPrincipalContext.class);
        final PreferredPrincipalContext ppCtx = new PreferredPrincipalContext();
        principals.clear();
        principals.add(new AuthenticationContextClassReferencePrincipal("1"));
        ppCtx.setPreferredPrincipals(principals);
        profileRequestCtx.getSubcontext(AuthenticationContext.class, true).addSubcontext(ppCtx, true);
        AuthenticationResult result = new AuthenticationResult("flowId", new Subject());
        profileRequestCtx.getSubcontext(AuthenticationContext.class).setAuthenticationResult(result);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNull(respCtx.getAcr());
    }

    /**
     * Test that action handles case of missing auth context.
     */
    @Test
    public void testFailNoAuthContext() throws ComponentInitializationException {
        init();
        profileRequestCtx.removeSubcontext(AuthenticationContext.class);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_PROFILE_CTX);

    }

}