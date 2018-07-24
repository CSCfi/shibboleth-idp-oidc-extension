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