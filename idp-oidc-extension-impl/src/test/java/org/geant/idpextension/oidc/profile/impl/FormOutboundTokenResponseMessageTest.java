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

import java.net.URISyntaxException;
import java.util.Date;

import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.action.EventIds;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenResponse;

/** {@link FormOutboundTokenResponseMessage} unit test. */
public class FormOutboundTokenResponseMessageTest extends BaseOIDCResponseActionTest {

    private FormOutboundTokenResponseMessage action;

    @BeforeMethod
    public void init() throws ComponentInitializationException, URISyntaxException, ParseException, JOSEException {
        action = new FormOutboundTokenResponseMessage();
        respCtx.setAccessToken("access_token", 50);
        setIdTokenToResponseContext("iss", "sub", "aud", new Date(), new Date());
        signIdTokenInResponseContext();
        action.initialize();
    }

    /**
     * Test that action is able to form success message.
     */
    @Test
    public void testSuccessMessage()
            throws ComponentInitializationException, URISyntaxException, ParseException, JOSEException {
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        TokenResponse resp = (TokenResponse) ((MessageContext<?>) respCtx.getParent()).getMessage();
        Assert.assertTrue(resp instanceof TokenResponse);
    }

    /**
     * Test that action fails if there is no id token.
     */
    @Test
    public void testFailNoIdToken()
            throws ComponentInitializationException, URISyntaxException, ParseException, JOSEException {
        respCtx.setProcessedToken(null);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_PROFILE_CTX);
    }

    /**
     * Test that action fails if there is no access token.
     */
    @Test
    public void testFailNoAccessToken()
            throws ComponentInitializationException, URISyntaxException, ParseException, JOSEException {
        respCtx.setAccessToken(null, 0);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_PROFILE_CTX);
    }

}