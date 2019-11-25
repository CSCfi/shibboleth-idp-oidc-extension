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

import java.net.URI;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;

/** Tests for {@link DefaultValidRedirectUrisLookupFunction}. */
public class DefaultValidRedirectUrisLookupFunctionTest {

    private DefaultValidRedirectUrisLookupFunction lookup;

    @SuppressWarnings("rawtypes")
    private ProfileRequestContext prc;

    private OIDCMetadataContext ctx;

    @SuppressWarnings({"unchecked", "rawtypes"})
    @BeforeMethod
    protected void setUp() throws Exception {
        lookup = new DefaultValidRedirectUrisLookupFunction();
        final RequestContext requestCtx = new RequestContextBuilder().buildRequestContext();
        prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        prc.setInboundMessageContext(new MessageContext());
        ctx = prc.getInboundMessageContext().getSubcontext(OIDCMetadataContext.class, true);
        ctx.setClientInformation(
                new OIDCClientInformation(new ClientID("id"), new Date(), new OIDCClientMetadata(), new Secret()));
        Set<URI> redirectURIs = new HashSet<URI>();
        redirectURIs.add(new URI("http://example.com"));
        ctx.getClientInformation().getOIDCMetadata().setRedirectionURIs(redirectURIs);
    }

    @Test
    public void testSuccess() {
        Assert.assertNotNull(lookup.apply(prc));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testNoInput() {
        // No profile context
        Assert.assertNull(lookup.apply(null));
        // No client information
        ctx.setClientInformation(null);
        Assert.assertNull(lookup.apply(prc));
        // No metadata context
        prc.getInboundMessageContext().removeSubcontext(OIDCMetadataContext.class);
        Assert.assertNull(lookup.apply(prc));
        // No inbound message context
        prc.setInboundMessageContext(null);
        Assert.assertNull(lookup.apply(prc));
    }

}