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
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Date;

import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseTokenClaimsContext;
import org.geant.idpextension.oidc.token.support.AuthorizeCodeClaimsSet;
import org.geant.idpextension.oidc.token.support.TokenDeliveryClaimsClaimsSet;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;

/** {@link SetTokenDeliveryAttributesFromTokenToResponseContext} unit test. */
public class SetTokenDeliveryAttributesFromTokenToResponseContextTest extends BaseOIDCResponseActionTest {

    private SetTokenDeliveryAttributesFromTokenToResponseContext action;

    private void init() throws ComponentInitializationException, URISyntaxException {
        action = new SetTokenDeliveryAttributesFromTokenToResponseContext();
        action.initialize();
        Date now = new Date();
        ClaimsSet dlClaims = new TokenDeliveryClaimsClaimsSet();
        dlClaims.setClaim("deliveryClaim", "deliveryClaimValue");
        ClaimsSet dlClaimsUI = new TokenDeliveryClaimsClaimsSet();
        dlClaimsUI.setClaim("deliveryClaimUI", "deliveryClaimUIValue");
        ClaimsSet dlClaimsID = new TokenDeliveryClaimsClaimsSet();
        dlClaimsID.setClaim("deliveryClaimID", "deliveryClaimIDValue");
        AuthorizeCodeClaimsSet acClaims =
                new AuthorizeCodeClaimsSet.Builder(idGenerator, new ClientID(clientId), "issuer", "userPrin", "subject",
                        now, new Date(now.getTime() + 100000), now, new URI("http://example.com"), new Scope())
                                .setDlClaims(dlClaims).setDlClaimsID(dlClaimsID).setDlClaimsUI(dlClaimsUI).build();
        respCtx.setTokenClaimsSet(acClaims);
    }

    /**
     * Test that action creates the context.
     * 
     * @throws URISyntaxException
     * @throws ComponentInitializationException
     */
    @Test
    public void testSuccess() throws ComponentInitializationException, URISyntaxException {
        init();
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        OIDCAuthenticationResponseTokenClaimsContext respTokenClaims =
                respCtx.getSubcontext(OIDCAuthenticationResponseTokenClaimsContext.class);
        Assert.assertNotNull(respTokenClaims);
        Assert.assertEquals(respTokenClaims.getUserinfoClaims().getClaim("deliveryClaimUI"), "deliveryClaimUIValue");
        Assert.assertEquals(respTokenClaims.getIdtokenClaims().getClaim("deliveryClaimID"), "deliveryClaimIDValue");
        Assert.assertEquals(respTokenClaims.getClaims().getClaim("deliveryClaim"), "deliveryClaimValue");
    }

    /**
     * Test that action is able to cope with no input.
     * 
     * @throws URISyntaxException
     * @throws ComponentInitializationException
     */
    @Test
    public void testSuccessNoInput() throws ComponentInitializationException, URISyntaxException {
        init();
        respCtx.setTokenClaimsSet(null);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        OIDCAuthenticationResponseTokenClaimsContext respTokenClaims =
                respCtx.getSubcontext(OIDCAuthenticationResponseTokenClaimsContext.class);
        Assert.assertNull(respTokenClaims);
    }

    /**
     * Test setting null strategy for delivery claims.
     */
    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testNullStrategyDClaims() {
        action = new SetTokenDeliveryAttributesFromTokenToResponseContext();
        action.setDeliveryClaimsLookupStrategy(null);
    }

    /**
     * Test setting null strategy for id token delivery claims.
     */
    @Test
    public void testNullStrategyIDTokenDClaims() throws ComponentInitializationException, URISyntaxException {
        init();
        action = new SetTokenDeliveryAttributesFromTokenToResponseContext();
        action.setIDTokenDeliveryClaimsLookupStrategy(null);
        action.initialize();
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        OIDCAuthenticationResponseTokenClaimsContext respTokenClaims =
                respCtx.getSubcontext(OIDCAuthenticationResponseTokenClaimsContext.class);
        Assert.assertNotNull(respTokenClaims);
        Assert.assertEquals(respTokenClaims.getUserinfoClaims().getClaim("deliveryClaimUI"), "deliveryClaimUIValue");
        Assert.assertNull(respTokenClaims.getIdtokenClaims().getClaim("deliveryClaimID"));
        Assert.assertEquals(respTokenClaims.getClaims().getClaim("deliveryClaim"), "deliveryClaimValue");
    }

    /**
     * Test setting null strategy for ui delivery claims.
     */
    @Test
    public void testNullStrategyUIDClaims() throws ComponentInitializationException, URISyntaxException {
        init();
        action = new SetTokenDeliveryAttributesFromTokenToResponseContext();
        action.setUserinfoDeliveryClaimsLookupStrategy(null);
        action.initialize();
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        OIDCAuthenticationResponseTokenClaimsContext respTokenClaims =
                respCtx.getSubcontext(OIDCAuthenticationResponseTokenClaimsContext.class);
        Assert.assertNotNull(respTokenClaims);
        Assert.assertNull(respTokenClaims.getUserinfoClaims().getClaim("deliveryClaimUI"));
        Assert.assertEquals(respTokenClaims.getIdtokenClaims().getClaim("deliveryClaimID"), "deliveryClaimIDValue");
        Assert.assertEquals(respTokenClaims.getClaims().getClaim("deliveryClaim"), "deliveryClaimValue");
    }
}