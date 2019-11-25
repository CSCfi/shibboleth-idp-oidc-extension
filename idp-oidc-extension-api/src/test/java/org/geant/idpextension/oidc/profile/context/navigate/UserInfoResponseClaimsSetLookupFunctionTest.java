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

import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;

/** Tests for {@link UserInfoResponseClaimsSetLookupFunction}. */
public class UserInfoResponseClaimsSetLookupFunctionTest {

    private UserInfoResponseClaimsSetLookupFunction lookup;

    @SuppressWarnings("rawtypes")
    private ProfileRequestContext prc;

    private OIDCAuthenticationResponseContext oidcCtx;

    @SuppressWarnings({"unchecked", "rawtypes"})
    @BeforeMethod
    protected void setUp() throws Exception {
        lookup = new UserInfoResponseClaimsSetLookupFunction();
        final RequestContext requestCtx = new RequestContextBuilder().buildRequestContext();
        prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        prc.setOutboundMessageContext(new MessageContext());
        oidcCtx = new OIDCAuthenticationResponseContext();
        prc.getOutboundMessageContext().addSubcontext(oidcCtx);
        Subject sub = new Subject("sub");
        UserInfo info = new UserInfo(sub);
        oidcCtx.setUserInfo(info);
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
        // No user info
        oidcCtx.setUserInfo(null);
        Assert.assertNull(lookup.apply(prc));
        // No oidc context
        prc.getOutboundMessageContext().removeSubcontext(OIDCAuthenticationResponseContext.class);
        Assert.assertNull(lookup.apply(prc));
        // No outbound message context
        prc.setOutboundMessageContext(null);
        Assert.assertNull(lookup.apply(prc));
    }

}