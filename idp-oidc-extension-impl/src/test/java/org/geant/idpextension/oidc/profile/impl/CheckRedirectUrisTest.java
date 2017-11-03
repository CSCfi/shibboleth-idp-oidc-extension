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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.Set;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpUriRequest;
import org.geant.idpextension.oidc.profile.OidcEventIds;
import org.mockito.Mockito;
import org.opensaml.profile.action.EventIds;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationRequest;

import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.httpclient.HttpClientBuilder;

/**
 * Unit tests for {@link CheckRedirectURIs}.
 */
public class CheckRedirectUrisTest extends BaseOIDCRegistrationRequestTest {

    CheckRedirectURIs action;
    URI redirectUri1;
    URI redirectUri2;
    
    @BeforeMethod
    public void setUp() throws ComponentInitializationException, URISyntaxException {
        action = new CheckRedirectURIs();
        action.initialize();
        redirectUri1 = new URI("https://example.org/cb1");
        redirectUri2 = new URI("https://example.org/cb2");
    }
    
    @Test
    public void testNoMessage() throws ComponentInitializationException {
        setUpContext(null);
        ActionTestingSupport.assertEvent(action.execute(requestCtx), EventIds.INVALID_MSG_CTX);
    }
    
    @Test
    public void testNullRedirectUris() throws ComponentInitializationException {
        OIDCClientMetadata metadata = new OIDCClientMetadata();
        setUpContext(new OIDCClientRegistrationRequest(null, metadata, null));
        ActionTestingSupport.assertEvent(action.execute(requestCtx), OidcEventIds.MISSING_REDIRECT_URIS);
    }

    @Test
    public void testEmptyRedirectUris() throws ComponentInitializationException {
        assertEvent(OidcEventIds.MISSING_REDIRECT_URIS, new OIDCClientMetadata(), (URI[])null);
    }
    
    @Test
    public void testSingleRedirectUri() throws ComponentInitializationException {
        assertEvent(null, new OIDCClientMetadata(), redirectUri1);
    }

    @Test
    public void testTwoRedirectUris() throws ComponentInitializationException {
        assertEvent(null, new OIDCClientMetadata(), redirectUri1, redirectUri2);
    }

    @Test
    public void testFailingSectorIdUriContents() throws Exception {
        OIDCClientMetadata metadata = new OIDCClientMetadata();
        metadata.setSectorIDURI(new URI("https://invalid.scheme.org/cb"));
        initializeActionWithBuilder(initializeMockBuilder(null));
        assertEvent(OidcEventIds.INVALID_REDIRECT_URIS, metadata, redirectUri1);
    }

    
    @Test
    public void testEmptySectorIdUriContents() throws Exception {
        OIDCClientMetadata metadata = new OIDCClientMetadata();
        metadata.setSectorIDURI(new URI("https://invalid.scheme.org/cb"));
        initializeActionWithBuilder(initializeMockBuilder(""));
        assertEvent(OidcEventIds.INVALID_REDIRECT_URIS, metadata, redirectUri1);
    }
    
    @Test
    public void testInvalidSectorIdUriContents() throws Exception {
        OIDCClientMetadata metadata = new OIDCClientMetadata();
        metadata.setSectorIDURI(new URI("https://invalid.scheme.org/cb"));
        initializeActionWithBuilder(initializeMockBuilder("[ \"https://not.existing.uri.org/\" ]"));
        assertEvent(OidcEventIds.INVALID_REDIRECT_URIS, metadata, redirectUri1);
    }

    @Test
    public void testValidSectorIdUriContents() throws Exception {
        OIDCClientMetadata metadata = new OIDCClientMetadata();
        metadata.setSectorIDURI(new URI("https://invalid.scheme.org/cb"));
        initializeActionWithBuilder(initializeMockBuilder("[ \"" + redirectUri1 + "\", \"" + redirectUri2 + "\" ]"));
        assertEvent(null, metadata, redirectUri1);
    }

    protected HttpClientBuilder initializeMockBuilder(String result) throws Exception {
        HttpClientBuilder httpBuilder = Mockito.mock(HttpClientBuilder.class);
        HttpClient httpClient = Mockito.mock(HttpClient.class);
        if (result == null) {
            Mockito.when(httpClient.execute((HttpUriRequest)Mockito.any())).thenThrow(new IOException("mock"));
        } else {
            HttpResponse httpResponse = Mockito.mock(HttpResponse.class);
            HttpEntity httpEntity = Mockito.mock(HttpEntity.class);
            Mockito.when(httpEntity.getContent()).thenReturn(new ByteArrayInputStream(result.getBytes()));
            Mockito.when(httpResponse.getEntity()).thenReturn(httpEntity);
            Mockito.when(httpClient.execute((HttpUriRequest)Mockito.any())).thenReturn(httpResponse);            
        }
        Mockito.when(httpBuilder.buildClient()).thenReturn(httpClient);
        return httpBuilder;
    }
    
    protected void initializeActionWithBuilder(HttpClientBuilder httpBuilder) throws ComponentInitializationException {
        action = new CheckRedirectURIs();
        action.setHttpClientBuilder(httpBuilder);
        action.initialize();
    }

    protected void assertEvent(String expectedEvent, OIDCClientMetadata metadata, URI... redirectUris) 
            throws ComponentInitializationException {
        Set<URI> uris = new HashSet<URI>();
        if (redirectUris != null) {
            uris = new HashSet<URI>();
            for (URI uri : redirectUris) {
                uris.add(uri);
            }
        }
        metadata.setRedirectionURIs(uris);
        setUpContext(new OIDCClientRegistrationRequest(null, metadata, null));
        if (expectedEvent != null) {
            ActionTestingSupport.assertEvent(action.execute(requestCtx), expectedEvent);
        } else {
            Assert.assertNull(action.execute(requestCtx));
        }
    }
}
