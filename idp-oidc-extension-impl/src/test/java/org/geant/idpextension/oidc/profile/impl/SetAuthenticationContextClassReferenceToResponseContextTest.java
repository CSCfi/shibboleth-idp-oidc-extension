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