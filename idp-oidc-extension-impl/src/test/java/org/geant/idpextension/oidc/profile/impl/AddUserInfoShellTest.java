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
import net.shibboleth.idp.profile.IdPEventIds;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.idp.profile.context.navigate.ResponderIdLookupFunction;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;

import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.jose.JWSAlgorithm;

/** {@link AddUserInfoShell} unit test. */
public class AddUserInfoShellTest extends BaseOIDCResponseActionTest {

    private AddUserInfoShell action;

    @BeforeMethod
    public void init() throws ComponentInitializationException {
        action = new AddUserInfoShell();
        action.setIssuerLookupStrategy(new ResponderIdLookupFunction());
        action.initialize();
    }

    /**
     * Test that user info shell is generated.
     */
    @Test
    public void testSuccess() {
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertEquals(respCtx.getUserInfo().getClaim("sub"), subject);
        Assert.assertNull(respCtx.getUserInfo().getClaim("aud"));
        Assert.assertNull(respCtx.getUserInfo().getIssuer());
    }

    /**
     * Test that user info shell is generated for signed response.
     */
    @Test
    public void testSuccessForSigned() {
        metadataCtx.getClientInformation().getOIDCMetadata().setUserInfoJWSAlg(JWSAlgorithm.HS256);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertEquals(respCtx.getUserInfo().getClaim("sub"), subject);
        Assert.assertNotNull(respCtx.getUserInfo().getClaim("sub"));
        Assert.assertNotNull(respCtx.getUserInfo().getIssuer());
    }

    /**
     * Test no relying party context.
     */
    @Test
    public void testFailNoRPContext() {
        profileRequestCtx.removeSubcontext(RelyingPartyContext.class);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, IdPEventIds.INVALID_RELYING_PARTY_CTX);
    }

    /** Test setting null stategy. */
    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testNullIssuerLookupStrategy() {
        action = new AddUserInfoShell();
        action.setIssuerLookupStrategy(null);
    }

    /** Test setting null strategy. */
    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testNullRelyingPartyContextLookupStrategy() {
        action = new AddUserInfoShell();
        action.setRelyingPartyContextLookupStrategy(null);
    }

    /** Test setting null strategy. */
    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testNulltUserInfoSigningAlgLookupStrategy() {
        action = new AddUserInfoShell();
        action.setUserInfoSigningAlgLookupStrategy(null);
    }

}