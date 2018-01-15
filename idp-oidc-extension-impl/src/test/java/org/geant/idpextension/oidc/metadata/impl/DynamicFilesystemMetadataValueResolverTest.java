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

import java.io.File;

import org.testng.Assert;
import org.testng.annotations.Test;

import net.minidev.json.JSONObject;

/**
 * Unit tests for {@link DynamicFilesystemMetadataValueResolver}.
 */
public class DynamicFilesystemMetadataValueResolverTest {
    
    public FilesystemDynamicMetadataValueResolver initTests(final String filename) throws Exception {
        final File file = new File(filename);
        final FilesystemDynamicMetadataValueResolver resolver = new FilesystemDynamicMetadataValueResolver(file);
        resolver.setId("mockId");
        resolver.initialize();
        return resolver;
    }
    
    @Test
    public void testString() throws Exception {
        final FilesystemDynamicMetadataValueResolver resolver = 
                initTests("src/test/resources/org/geant/idpextension/oidc/metadata/impl/dyn-value1.json");
        final Object value = resolver.resolveSingle(null);
        Assert.assertNotNull(value);
        Assert.assertTrue(value instanceof String);
        Assert.assertEquals(value, "mockValue");
    }

    @Test
    public void testJson() throws Exception {
        final FilesystemDynamicMetadataValueResolver resolver = 
                initTests("src/test/resources/org/geant/idpextension/oidc/metadata/impl/dyn-value2.json");
        final Object value = resolver.resolveSingle(null);
        Assert.assertNotNull(value);
        Assert.assertTrue(value instanceof JSONObject);
        final JSONObject jsonValue = (JSONObject) value;
        Assert.assertEquals(jsonValue.size(), 1);
        Assert.assertEquals(jsonValue.get("mockKey"), "mockValue");
    }

}
