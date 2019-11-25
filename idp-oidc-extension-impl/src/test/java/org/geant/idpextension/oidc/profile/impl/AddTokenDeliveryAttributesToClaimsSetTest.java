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