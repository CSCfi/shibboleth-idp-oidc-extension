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

import java.io.File;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.testng.Assert;
import org.testng.annotations.Test;

import net.minidev.json.JSONObject;

/**
 * Unit tests for {@link FilesystemMetadataValueResolver}.
 */
public class FilesystemMetadataValueResolverTest {
    
    public FilesystemMetadataValueResolver initTests(final String filename) throws Exception {
        final Resource file = new ClassPathResource(filename);
        final FilesystemMetadataValueResolver resolver = new FilesystemMetadataValueResolver(file);
        resolver.setId("mockId");
        resolver.initialize();
        return resolver;
    }
    
    @Test
    public void testString() throws Exception {
        final FilesystemMetadataValueResolver resolver = 
                initTests("/org/geant/idpextension/oidc/metadata/impl/dyn-value1.json");
        final Object value = resolver.resolveSingle(null);
        Assert.assertNotNull(value);
        Assert.assertTrue(value instanceof String);
        Assert.assertEquals(value, "mockValue");
    }

    @Test
    public void testJson() throws Exception {
        final FilesystemMetadataValueResolver resolver = 
                initTests("/org/geant/idpextension/oidc/metadata/impl/dyn-value2.json");
        final Object value = resolver.resolveSingle(null);
        Assert.assertNotNull(value);
        Assert.assertTrue(value instanceof JSONObject);
        final JSONObject jsonValue = (JSONObject) value;
        Assert.assertEquals(jsonValue.size(), 1);
        Assert.assertEquals(jsonValue.get("mockKey"), "mockValue");
    }

}
