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
import com.nimbusds.openid.connect.sdk.UserInfoResponse;

/** {@link FormOutboundUserInfoResponseMessage} unit test. */
public class FormOutboundUserInfoResponseMessageTest extends BaseOIDCResponseActionTest {

    private FormOutboundUserInfoResponseMessage action;

    @BeforeMethod
    public void init() throws ComponentInitializationException, URISyntaxException, ParseException, JOSEException {
        action = new FormOutboundUserInfoResponseMessage();
        action.initialize();
        setUserInfoResponseToResponseContext("joe");
        signUserInfoResponseInResponseContext();
    }

    /**
     * Test that action is able to pick to form success message from signed response.
     */
    @Test
    public void testSuccessMessageSigned()
            throws ComponentInitializationException, URISyntaxException, ParseException, JOSEException {
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        UserInfoResponse resp = (UserInfoResponse) ((MessageContext<?>) respCtx.getParent()).getMessage();
        Assert.assertNotNull(resp);
        // a signed jwt
        Assert.assertNotNull(resp.toSuccessResponse().getUserInfoJWT());
        Assert.assertNull(resp.toSuccessResponse().getUserInfo());
    }

    /**
     * Test that action is able to pick to form success message from plaintext response.
     */
    @Test
    public void testSuccessMessagePlain()
            throws ComponentInitializationException, URISyntaxException, ParseException, JOSEException {
        respCtx.setProcessedToken(null);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        UserInfoResponse resp = (UserInfoResponse) ((MessageContext<?>) respCtx.getParent()).getMessage();
        Assert.assertNotNull(resp);
        // a plain text response
        Assert.assertNotNull(resp.toSuccessResponse().getUserInfo());
        Assert.assertNull(resp.toSuccessResponse().getUserInfoJWT());
    }

    /**
     * Test that action is able to handle case of having no input to message.
     */
    @Test
    public void testFailNoMessage()
            throws ComponentInitializationException, URISyntaxException, ParseException, JOSEException {
        respCtx.setProcessedToken(null);
        respCtx.setUserInfo(null);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_PROFILE_CTX);
    }

}