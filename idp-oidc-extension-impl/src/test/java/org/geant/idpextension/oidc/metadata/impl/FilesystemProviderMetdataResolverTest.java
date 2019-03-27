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

package org.geant.idpextension.oidc.metadata.impl;

import org.geant.idpextension.oidc.metadata.resolver.ProviderMetadataResolver;
import org.mockito.Mockito;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.idp.relyingparty.RelyingPartyConfiguration;

/**
 * Unit tests for {@link FilesystemProviderMetadataResolver}.
 */
public class FilesystemProviderMetdataResolverTest {

    ProviderMetadataResolver resolver;
    
    Resource file;
    
    @BeforeMethod
    public void initTests() throws Exception {
        file = new ClassPathResource("/org/geant/idpextension/oidc/metadata/impl/openid-configuration.json");
        resolver = new FilesystemProviderMetadataResolver(file);
        ((FilesystemProviderMetadataResolver)resolver).setId("mockId");
        ((FilesystemProviderMetadataResolver)resolver).initialize();
    }
    
    @Test
    public void testNotFound() throws Exception {
        final OIDCProviderMetadata metadata = resolver.resolveSingle(initMockWithRpId("not_found"));
        Assert.assertNull(metadata);
    }
    
    @Test
    public void testSuccess() throws Exception {
        final String issuer = "http://idp.example.org";
        final OIDCProviderMetadata metadata = resolver.resolveSingle(initMockWithRpId(issuer));
        Assert.assertNotNull(metadata);
        Assert.assertEquals(metadata.getIssuer().getValue(), issuer);
    }
    
    @SuppressWarnings("rawtypes")
    protected ProfileRequestContext initMockWithRpId(final String id) {
        final ProfileRequestContext profileRequestContext = new ProfileRequestContext();
        final RelyingPartyContext rpCtx = profileRequestContext.getSubcontext(RelyingPartyContext.class, true);
        RelyingPartyConfiguration configuration = Mockito.mock(RelyingPartyConfiguration.class);
        Mockito.when(configuration.getResponderId()).thenReturn(id);
        rpCtx.setConfiguration(configuration);
        return profileRequestContext;
    }
    
}
