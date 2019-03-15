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

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.geant.idpextension.oidc.messaging.JSONSuccessResponse;
import org.geant.idpextension.oidc.metadata.impl.DynamicFilesystemProviderMetadataResolver;
import org.geant.idpextension.oidc.metadata.impl.FilesystemProviderMetadataResolver;
import org.geant.idpextension.oidc.metadata.resolver.MetadataValueResolver;
import org.geant.idpextension.oidc.metadata.resolver.ProviderMetadataResolver;
import org.mockito.Mockito;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import net.minidev.json.JSONObject;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

/**
 * Unit tests for {@link FormOutboundDiscoveryResponse}.
 */
public class FormOutboundDiscoveryResponseTest {

    protected FormOutboundDiscoveryResponse action;

    protected RequestContext requestCtx;

    @SuppressWarnings("rawtypes")
    protected ProfileRequestContext profileRequestCtx;

    protected Resource opfile;

    protected String dynamicClaim;

    protected String dynamicClaimValue;

    @BeforeMethod
    protected void setUpContext() throws ComponentInitializationException {
        action = buildAction();
        requestCtx = new RequestContextBuilder().buildRequestContext();
        profileRequestCtx = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        opfile = new ClassPathResource("/org/geant/idpextension/oidc/metadata/impl/openid-configuration.json");
        dynamicClaim = "dynamicClaimName";
        dynamicClaimValue = "dynamicClaimValue";
    }

    protected FormOutboundDiscoveryResponse buildAction() {
        action = new FormOutboundDiscoveryResponse();
        action.setHttpServletRequest(new MockHttpServletRequest());
        action.setHttpServletResponse(new MockHttpServletResponse());
        return action;
    }

    protected ProviderMetadataResolver initMetadataResolver() throws Exception {
        final FilesystemProviderMetadataResolver resolver = new FilesystemProviderMetadataResolver(opfile);
        resolver.setId("mockStaticResolver");
        resolver.initialize();
        return resolver;
    }

    @Test
    public void testStatic() throws Exception {
        action.setMetadataResolver(initMetadataResolver());
        action.initialize();
        ActionTestingSupport.assertProceedEvent(action.execute(requestCtx));
        Assert.assertTrue(profileRequestCtx.getOutboundMessageContext().getMessage() instanceof JSONSuccessResponse);
        final JSONSuccessResponse resp =
                (JSONSuccessResponse) profileRequestCtx.getOutboundMessageContext().getMessage();
        Assert.assertTrue(resp.indicatesSuccess());
        final JSONObject jsonObject = resp.toHTTPResponse().getContentAsJSONObject();
        Assert.assertEquals(jsonObject.size(), 17);
        Assert.assertNull(jsonObject.get(dynamicClaim));
    }

    @Test
    public void testDynamic() throws Exception {
        final Map<String, MetadataValueResolver> map = new HashMap<>();
        map.put(dynamicClaim, initMockResolver(dynamicClaimValue));
        action.setMetadataResolver(initMetadataResolver(map));
        action.initialize();
        ActionTestingSupport.assertProceedEvent(action.execute(requestCtx));
        final JSONSuccessResponse resp =
                (JSONSuccessResponse) profileRequestCtx.getOutboundMessageContext().getMessage();
        Assert.assertTrue(resp.indicatesSuccess());
        final JSONObject jsonObject = resp.toHTTPResponse().getContentAsJSONObject();
        Assert.assertEquals(jsonObject.size(), 18);
        Assert.assertNotNull(jsonObject.get(dynamicClaim));
        Assert.assertEquals(jsonObject.get(dynamicClaim), dynamicClaimValue);
    }

    protected ProviderMetadataResolver initMetadataResolver(final Map<String, MetadataValueResolver> map)
            throws Exception {
        final DynamicFilesystemProviderMetadataResolver resolver =
                new DynamicFilesystemProviderMetadataResolver(opfile);
        resolver.setDynamicValueResolvers(map);
        resolver.setId("mockDynamicResolver");
        resolver.initialize();
        return resolver;
    }

    @SuppressWarnings("rawtypes")
    protected MetadataValueResolver initMockResolver(final Object value) throws Exception {
        MetadataValueResolver resolver = Mockito.mock(MetadataValueResolver.class);
        Mockito.when(resolver.resolve((ProfileRequestContext) Mockito.any())).thenReturn(Arrays.asList(value));
        Mockito.when(resolver.resolveSingle((ProfileRequestContext) Mockito.any())).thenReturn(value);
        return resolver;
    }
}
