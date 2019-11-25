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

package org.geant.idpextension.oidc.profile.impl;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.Set;

import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

/**
 * Unit tests for {@link AddRedirectUrisToClientMetadata}.
 */
public class AddRedirectUrisToClientMetadataTest extends BaseOIDCClientMetadataPopulationTest {

    AddRedirectUrisToClientMetadata action;
    
    URI redirectUri1;
    URI redirectUri2;
    
    @BeforeMethod
    public void setUp() throws ComponentInitializationException, URISyntaxException {
        action = new AddRedirectUrisToClientMetadata();
        action.initialize();
        redirectUri1 = new URI("https://example.org/cb1");
        redirectUri2 = new URI("https://example.org/cb2");
    }
    
    @Override
    protected AbstractOIDCClientMetadataPopulationAction constructAction() {
        return new AddRedirectUrisToClientMetadata();
    }
    
    @Test
    public void testOne() throws ComponentInitializationException {
        OIDCClientMetadata input = new OIDCClientMetadata();
        input.setRedirectionURI(redirectUri1);
        OIDCClientMetadata output = new OIDCClientMetadata();
        setUpContext(input, output);
        Assert.assertNull(action.execute(requestCtx));
        Set<URI> resultUris = output.getRedirectionURIs();
        Assert.assertEquals(resultUris.size(), 1);
        Assert.assertEquals(resultUris.iterator().next(), redirectUri1);
    }

    @Test
    public void testSet() throws ComponentInitializationException {
        OIDCClientMetadata input = new OIDCClientMetadata();
        HashSet<URI> uris = new HashSet<URI>();
        uris.add(redirectUri1);
        uris.add(redirectUri2);
        input.setRedirectionURIs(uris);
        OIDCClientMetadata output = new OIDCClientMetadata();
        setUpContext(input, output);
        Assert.assertNull(action.execute(requestCtx));
        Set<URI> resultUris = output.getRedirectionURIs();
        Assert.assertEquals(resultUris, uris);
    }

}
