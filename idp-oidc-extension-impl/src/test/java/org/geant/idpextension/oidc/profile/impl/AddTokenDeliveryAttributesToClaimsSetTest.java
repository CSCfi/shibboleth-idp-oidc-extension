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

import java.util.Date;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseTokenClaimsContext;
import org.opensaml.profile.action.EventIds;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.ParseException;

/** {@link AddTokenDeliveryAttributesToClaimsSet} unit test. */
public class AddTokenDeliveryAttributesToClaimsSetTest extends BaseOIDCResponseActionTest {

    private AddTokenDeliveryAttributesToClaimsSet action;

    private OIDCAuthenticationResponseTokenClaimsContext tokenClaimsCtx;

    private void init() throws ComponentInitializationException {
        action = new AddTokenDeliveryAttributesToClaimsSet();
        action.setTargetIDToken(true);
        action.initialize();
        tokenClaimsCtx = (OIDCAuthenticationResponseTokenClaimsContext) respCtx
                .addSubcontext(new OIDCAuthenticationResponseTokenClaimsContext());
        tokenClaimsCtx.getClaims().setClaim("gen", "value1");
        tokenClaimsCtx.getIdtokenClaims().setClaim("idtoken", "value2");
        tokenClaimsCtx.getUserinfoClaims().setClaim("userinfo", "value3");
    }

    /**
     * Test that action copes with no id token in response context.
     * 
     * @throws ComponentInitializationException
     * @throws ParseException
     */
    @Test
    public void testNoIdToken() throws ComponentInitializationException, ParseException {
        init();
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_MSG_CTX);
    }

    /**
     * Test action with not claims set.
     * 
     * @throws ComponentInitializationException
     * @throws ParseException
     */
    @Test
    public void testNoTokenDeliveryAttributes() throws ComponentInitializationException, ParseException {
        init();
        setIdTokenToResponseContext("iss", "sub", "aud", new Date(), new Date());
        respCtx.removeSubcontext(tokenClaimsCtx);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
    }

    /**
     * Test action with no items in token delivery context.
     * 
     * @throws ComponentInitializationException
     * @throws ParseException
     */

    @Test
    public void testNoTokenDeliveryAttributes2() throws ComponentInitializationException, ParseException {
        init();
        setIdTokenToResponseContext("iss", "sub", "aud", new Date(), new Date());
        respCtx.addSubcontext(new OIDCAuthenticationResponseTokenClaimsContext(), true);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
    }

    /**
     * Test action with id token mode.
     * 
     * @throws ComponentInitializationException
     * @throws ParseException
     */

    @Test
    public void testIdTokenDeliveryAttributes() throws ComponentInitializationException, ParseException {
        init();
        setIdTokenToResponseContext("iss", "sub", "aud", new Date(), new Date());
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertTrue(respCtx.getIDToken().getClaim("gen").equals("value1"));
        Assert.assertTrue(respCtx.getIDToken().getClaim("idtoken").equals("value2"));
        Assert.assertNull(respCtx.getIDToken().getClaim("userinfo"));
    }

    /**
     * Test action with userinfo mode.
     * 
     * @throws ComponentInitializationException
     * @throws ParseException
     */

    @Test
    public void testUserInfoDeliveryAttributes() throws ComponentInitializationException, ParseException {
        init();
        setIdTokenToResponseContext("iss", "sub", "aud", new Date(), new Date());
        action.setTargetIDToken(false);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertTrue(respCtx.getIDToken().getClaim("gen").equals("value1"));
        Assert.assertTrue(respCtx.getIDToken().getClaim("userinfo").equals("value3"));
        Assert.assertNull(respCtx.getIDToken().getClaim("idtoken"));
    }

}