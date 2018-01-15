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
import java.util.HashMap;

import org.geant.idpextension.oidc.criterion.IssuerCriterion;
import org.geant.idpextension.oidc.metadata.resolver.DynamicMetadataValueResolver;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;

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
        FilesystemDynamicMetadataValueResolver valueResolver = new FilesystemDynamicMetadataValueResolver(
                new File("src/test/resources/org/geant/idpextension/oidc/metadata/impl/dyn-value1.json"));
        valueResolver.setId("mock");
        valueResolver.initialize();
        final HashMap<String, DynamicMetadataValueResolver> map = new HashMap<>();
        map.put(name, valueResolver);
        ((DynamicFilesystemProviderMetadataResolver)resolver).setDynamicValueResolvers(map);
    }
    
    @Test
    public void testDynamic() throws Exception {
        final IssuerCriterion criterion = new IssuerCriterion(new Issuer(issuer));
        OIDCProviderMetadata metadata = resolver.resolveSingle(new CriteriaSet(criterion));
        Assert.assertNotNull(metadata);
        Assert.assertEquals(metadata.getIssuer().getValue(), issuer);
        ((DynamicFilesystemProviderMetadataResolver)resolver).refresh();
        metadata = resolver.resolveSingle(new CriteriaSet(criterion));
        Assert.assertNotNull(metadata.getCustomParameter(name));
        Assert.assertEquals(metadata.getCustomParameter(name), value);
    }
}
