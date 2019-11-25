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
