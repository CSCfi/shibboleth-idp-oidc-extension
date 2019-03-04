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
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.ACR;
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
        AuthorizeCodeClaimsSet acClaims = new AuthorizeCodeClaimsSet(idGenerator, new ClientID(clientId), "issuer",
                "userPrin", "subject", new ACR("0"), now, new Date(now.getTime() + 100000), new Nonce(), now,
                new URI("http://example.com"), new Scope(), null, dlClaims, dlClaimsID, dlClaimsUI, null, null);
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