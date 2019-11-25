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