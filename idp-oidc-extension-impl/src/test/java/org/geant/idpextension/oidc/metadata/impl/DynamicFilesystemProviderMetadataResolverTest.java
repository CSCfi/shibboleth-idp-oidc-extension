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

import java.util.HashMap;

import org.geant.idpextension.oidc.metadata.resolver.RefreshableMetadataValueResolver;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.core.io.ClassPathResource;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

/**
 * Unit tests for {@link DynamicFilesystemProviderMetadataResolver}.
 */
public class DynamicFilesystemProviderMetadataResolverTest extends FilesystemProviderMetdataResolverTest {
    
    String name;
    
    String value;

    @BeforeMethod
    public void initTests() throws Exception {
        super.initTests();
        resolver = new DynamicFilesystemProviderMetadataResolver(file);
        ((DynamicFilesystemProviderMetadataResolver)resolver).setId("mockId");
        ((DynamicFilesystemProviderMetadataResolver)resolver).initialize();
        name = "mockName";
        value = "mockValue";
        FilesystemMetadataValueResolver valueResolver = new FilesystemMetadataValueResolver(
                new ClassPathResource("/org/geant/idpextension/oidc/metadata/impl/dyn-value1.json"));
        valueResolver.setId("mock");
        valueResolver.initialize();
        final HashMap<String, RefreshableMetadataValueResolver> map = new HashMap<>();
        map.put(name, valueResolver);
        ((DynamicFilesystemProviderMetadataResolver)resolver).setDynamicValueResolvers(map);
    }
    
    @Test
    public void testDynamic() throws Exception {
        OIDCProviderMetadata metadata = resolver.resolveSingle(new ProfileRequestContext());
        Assert.assertNotNull(metadata);
        Assert.assertEquals(metadata.getIssuer().getValue(), "http://idp.example.org");
        ((DynamicFilesystemProviderMetadataResolver)resolver).refresh();
        metadata = resolver.resolveSingle(new ProfileRequestContext());
        Assert.assertNotNull(metadata.getCustomParameter(name));
        Assert.assertEquals(metadata.getCustomParameter(name), value);
    }
}
