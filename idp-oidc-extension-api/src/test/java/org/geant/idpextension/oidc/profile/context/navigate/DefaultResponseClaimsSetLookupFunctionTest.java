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

package org.geant.idpextension.oidc.profile.context.navigate;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;

import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;

/** Tests for {@link DefaultResponseClaimsSetLookupFunction}. */
public class DefaultResponseClaimsSetLookupFunctionTest {

    private DefaultResponseClaimsSetLookupFunction lookup;

    @SuppressWarnings("rawtypes")
    private ProfileRequestContext prc;

    private OIDCAuthenticationResponseContext oidcCtx;

    @SuppressWarnings({"unchecked", "rawtypes"})
    @BeforeMethod
    protected void setUp() throws Exception {
        lookup = new DefaultResponseClaimsSetLookupFunction();
        final RequestContext requestCtx = new RequestContextBuilder().buildRequestContext();
        prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        prc.setOutboundMessageContext(new MessageContext());
        oidcCtx = new OIDCAuthenticationResponseContext();
        prc.getOutboundMessageContext().addSubcontext(oidcCtx);
        Issuer issuer = new Issuer("iss");
        Subject sub = new Subject("sub");
        List<Audience> aud = new ArrayList<Audience>();
        aud.add(new Audience("aud"));
        oidcCtx.setIDToken(new IDTokenClaimsSet(issuer, sub, aud, new Date(), new Date()));
    }

    @Test
    public void testSuccess() {
        Assert.assertEquals("sub", (String) lookup.apply(prc).getClaim("sub"));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testNoInput() {
        // No profile context
        Assert.assertNull(lookup.apply(null));
        // No ID token
        oidcCtx.setIDToken(null);
        Assert.assertNull(lookup.apply(prc));
        // No oidc context
        prc.getOutboundMessageContext().removeSubcontext(OIDCAuthenticationResponseContext.class);
        Assert.assertNull(lookup.apply(prc));
        // No outbound message context
        prc.setOutboundMessageContext(null);
        Assert.assertNull(lookup.apply(prc));
    }

}