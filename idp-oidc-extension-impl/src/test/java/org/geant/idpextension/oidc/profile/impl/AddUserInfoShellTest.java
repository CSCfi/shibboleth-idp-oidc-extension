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