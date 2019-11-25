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

import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.utilities.java.support.security.SecureRandomIdentifierGenerationStrategy;

import java.net.URI;
import java.util.Date;

import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseContext;
import org.geant.idpextension.oidc.token.support.AccessTokenClaimsSet;
import org.geant.idpextension.oidc.token.support.TokenClaimsSet;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.RequestContext;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;

import junit.framework.Assert;

@SuppressWarnings({"unchecked", "rawtypes"})
public class AbstractTokenClaimsLookupFunctionTest {

    protected ProfileRequestContext prc;

    protected OIDCAuthenticationResponseContext oidcCtx;

    protected MockSubLookupFunction mock = new MockSubLookupFunction();

    @BeforeMethod
    protected void setUpCtxs() throws Exception {
        final RequestContext requestCtx = new RequestContextBuilder().buildRequestContext();
        prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        prc.setOutboundMessageContext(new MessageContext());
        oidcCtx = new OIDCAuthenticationResponseContext();
        prc.getOutboundMessageContext().addSubcontext(oidcCtx);
        oidcCtx.setTokenClaimsSet(
                new AccessTokenClaimsSet.Builder(new SecureRandomIdentifierGenerationStrategy(), new ClientID(),
                        "issuer", "userPrin", "subject", new Date(), new Date(System.currentTimeMillis() + 1000),
                        new Date(), new URI("http://example.com"), new Scope()).build());
    }

    @Test
    public void testSubjectSuccess() {
        Assert.assertEquals("subject", mock.apply(prc));
    }

    @Test
    public void testNoCtxts() {
        // No profile context
        Assert.assertNull(mock.apply(null));
        // No out bound message context
        prc.setOutboundMessageContext(null);
        Assert.assertNull(mock.apply(prc));
        // No response context
        prc.setOutboundMessageContext(new MessageContext());
        Assert.assertNull(mock.apply(prc));
        // No token claims set
        prc.getOutboundMessageContext().addSubcontext(new OIDCAuthenticationResponseContext());
        Assert.assertNull(mock.apply(prc));
    }

    class MockSubLookupFunction extends AbstractTokenClaimsLookupFunction {

        @Override
        Object doLookup(TokenClaimsSet tokenClaims) {
            return tokenClaims.getClaimsSet().getClaim("sub");
        }
    }

}