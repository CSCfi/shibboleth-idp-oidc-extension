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
        Assert.assertTrue(((MessageContext<?>) respCtx.getParent()).getMessage() instanceof TokenResponse);
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