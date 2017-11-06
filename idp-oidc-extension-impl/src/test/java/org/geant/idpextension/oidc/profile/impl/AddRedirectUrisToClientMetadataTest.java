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
