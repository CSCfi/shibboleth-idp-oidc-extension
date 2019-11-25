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

import net.minidev.json.JSONArray;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Date;
import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseConsentContext;
import org.geant.idpextension.oidc.token.support.AuthorizeCodeClaimsSet;
import org.geant.idpextension.oidc.token.support.TokenClaimsSet;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;

/** {@link SetConsentFromTokenToResponseContext} unit test. */
public class SetConsentFromTokenToResponseContextTest extends BaseOIDCResponseActionTest {

    private SetConsentFromTokenToResponseContext action;

    private void init() throws ComponentInitializationException {
        action = new SetConsentFromTokenToResponseContext();
        action.initialize();
    }

    /**
     * Test that action handles no consent being available.
     */
    @Test
    public void testSuccessNoConsent() throws ComponentInitializationException {
        init();
        final Event event = action.execute(requestCtx);
        respCtx.removeSubcontext(OIDCAuthenticationResponseConsentContext.class);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNull(respCtx.getSubcontext(OIDCAuthenticationResponseConsentContext.class, false));
    }

    /**
     * Test basic success case.
     */
    @Test
    public void testSuccess() throws ComponentInitializationException, URISyntaxException {
        init();
        JSONArray consentableClaims = new JSONArray();
        consentableClaims.add("1");
        consentableClaims.add("2");
        JSONArray consentedClaims = new JSONArray();
        consentedClaims.add("1");
        TokenClaimsSet claims = new AuthorizeCodeClaimsSet.Builder(idGenerator, new ClientID(), "issuer", "userPrin",
                "subject", new Date(), new Date(), new Date(), new URI("http://example.com"), new Scope())
                        .setConsentableClaims(consentableClaims).setConsentedClaims(consentedClaims).build();
        respCtx.setTokenClaimsSet(claims);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        OIDCAuthenticationResponseConsentContext ctx =
                respCtx.getSubcontext(OIDCAuthenticationResponseConsentContext.class, false);
        Assert.assertNotNull(ctx);
        Assert.assertEquals(ctx.getConsentableAttributes(), consentableClaims);
        Assert.assertEquals(ctx.getConsentedAttributes(), consentedClaims);
    }

}