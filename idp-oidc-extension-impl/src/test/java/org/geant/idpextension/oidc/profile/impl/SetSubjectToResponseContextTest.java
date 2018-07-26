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

import net.shibboleth.idp.consent.context.impl.ConsentContext;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.UnmodifiableComponentException;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import org.geant.idpextension.oidc.profile.context.navigate.TokenRequestSubjectLookupFunction;
import org.geant.idpextension.oidc.token.support.AccessTokenClaimsSet;
import org.geant.idpextension.oidc.token.support.TokenClaimsSet;
import org.opensaml.profile.action.EventIds;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.Test;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.ACR;

/** {@link SetSubjectToResponseContext} unit test. */
public class SetSubjectToResponseContextTest extends BaseOIDCResponseActionTest {

    private SetSubjectToResponseContext action;

    private void init() throws ComponentInitializationException {
        action = new SetSubjectToResponseContext();
        action.initialize();
    }

    /**
     * Test that action handles case of no subject available.
     * 
     * @throws ComponentInitializationException
     */
    @Test
    public void testNoSubject() throws ComponentInitializationException {
        init();
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_PROFILE_CTX);
    }

    /**
     * Test that action throws error when null strategy is set.
     * 
     * @throws ComponentInitializationException
     * @throws NoSuchAlgorithmException
     */
    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testNoStrategy() throws NoSuchAlgorithmException, ComponentInitializationException {
        action = new SetSubjectToResponseContext();
        action.setSubjectLookupStrategy(null);
    }
    
    /**
     * Test that action throws error when strategy is being set when already initialized.
     * 
     * @throws ComponentInitializationException
     * @throws NoSuchAlgorithmException
     */
    @Test(expectedExceptions = UnmodifiableComponentException.class)
    public void testInitialized() throws NoSuchAlgorithmException, ComponentInitializationException {
        init();
        action.setSubjectLookupStrategy(new TokenRequestSubjectLookupFunction());
    }

    /**
     * Test that action copies subject to response ctx.
     * 
     * @throws ComponentInitializationException
     * @throws URISyntaxException
     */
    @Test
    public void testSuccess() throws ComponentInitializationException, URISyntaxException {
        init();
        TokenClaimsSet claims = new AccessTokenClaimsSet(new idStrat(), new ClientID(), "issuer", "userPrin", "subject",
                new ACR("0"), new Date(), new Date(), new Nonce(), new Date(), new URI("http://example.com"),
                new Scope(), "id", null, null, null, null, null);
        respCtx.setTokenClaimsSet(claims);
        profileRequestCtx.removeSubcontext(ConsentContext.class);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertEquals(respCtx.getSubject(), "subject");

    }

}