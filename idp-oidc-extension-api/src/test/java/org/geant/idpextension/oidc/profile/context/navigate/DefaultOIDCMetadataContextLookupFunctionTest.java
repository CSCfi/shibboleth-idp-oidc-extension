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

import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.openid.connect.sdk.AuthenticationRequest;

public class DefaultOIDCMetadataContextLookupFunctionTest {

    private DefaultOIDCMetadataContextLookupFunction lookup;
    @SuppressWarnings("rawtypes")
    private ProfileRequestContext prc;

    @SuppressWarnings("unchecked")
    @BeforeMethod
    protected void setUp() throws Exception {
        lookup = new DefaultOIDCMetadataContextLookupFunction();
        final RequestContext requestCtx = new RequestContextBuilder().buildRequestContext();
        prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        final MessageContext<AuthenticationRequest> msgCtx = new MessageContext<AuthenticationRequest>();
        prc.setInboundMessageContext(msgCtx);
        msgCtx.addSubcontext(new OIDCMetadataContext());
    }

    
    @Test
    public void testSuccess() {
        OIDCMetadataContext ctx = lookup.apply(prc);
        Assert.assertNotNull(ctx);
    }

    @Test
    public void testNoMetadataCtx() {
        prc.getInboundMessageContext().removeSubcontext(OIDCMetadataContext.class);
        Assert.assertNull(lookup.apply(prc));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testNoMessageCtx() {
        prc.setInboundMessageContext(null);
        Assert.assertNull(lookup.apply(prc));
    }

    @Test
    public void testNoPrc() {
        Assert.assertNull(lookup.apply(null));
    }
   
}