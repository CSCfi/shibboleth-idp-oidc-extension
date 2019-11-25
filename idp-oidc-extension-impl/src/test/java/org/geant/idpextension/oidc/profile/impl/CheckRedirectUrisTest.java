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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.Set;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.protocol.HttpContext;
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

/**
 * Unit tests for {@link CheckRedirectURIs}.
 */
public class CheckRedirectUrisTest extends BaseOIDCRegistrationRequestTest {

    CheckRedirectURIs action;
    URI redirectUri1;
    URI redirectUri2;
    
    @BeforeMethod
    public void setUp() throws ComponentInitializationException, URISyntaxException, ClientProtocolException, 
        IOException {
        action = new CheckRedirectURIs();
        action.setHttpClient(buildMockHttpClient("mock"));
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
        initializeActionWithClient(buildMockHttpClient(null));
        assertEvent(OidcEventIds.INVALID_REDIRECT_URIS, metadata, redirectUri1);
    }

    
    @Test
    public void testEmptySectorIdUriContents() throws Exception {
        OIDCClientMetadata metadata = new OIDCClientMetadata();
        metadata.setSectorIDURI(new URI("https://invalid.scheme.org/cb"));
        initializeActionWithClient(buildMockHttpClient(""));
        assertEvent(OidcEventIds.INVALID_REDIRECT_URIS, metadata, redirectUri1);
    }

    @Test
    public void testInvalidJsonSectorIdUri() throws Exception {
        OIDCClientMetadata metadata = new OIDCClientMetadata();
        metadata.setSectorIDURI(new URI("https://invalid.scheme.org/cb"));
        initializeActionWithClient(buildMockHttpClient("Not_JSON"));
        assertEvent(OidcEventIds.INVALID_REDIRECT_URIS, metadata, redirectUri1);
    }

    @Test
    public void testInvalidSectorIdUriContents() throws Exception {
        OIDCClientMetadata metadata = new OIDCClientMetadata();
        metadata.setSectorIDURI(new URI("https://invalid.scheme.org/cb"));
        initializeActionWithClient(buildMockHttpClient("[ \"https://not.existing.uri.org/\" ]"));
        assertEvent(OidcEventIds.INVALID_REDIRECT_URIS, metadata, redirectUri1);
    }

    @Test
    public void testValidSectorIdUriContents() throws Exception {
        OIDCClientMetadata metadata = new OIDCClientMetadata();
        metadata.setSectorIDURI(new URI("https://invalid.scheme.org/cb"));
        initializeActionWithClient(buildMockHttpClient("[ \"" + redirectUri1 + "\", \"" + redirectUri2 + "\" ]"));
        assertEvent(null, metadata, redirectUri1);
    }

    protected void initializeActionWithClient(HttpClient httpClient) throws ComponentInitializationException {
        action = new CheckRedirectURIs();
        action.setHttpClient(httpClient);
        action.initialize();
    }
    
    protected HttpClient buildMockHttpClient(String contents) throws ClientProtocolException, IOException {
        HttpClient mockClient = Mockito.mock(HttpClient.class);
        if (contents == null) {
            Mockito.when(mockClient.execute((HttpUriRequest)Mockito.any())).thenThrow(new IOException("mock"));
        } else {
            HttpResponse httpResponse = Mockito.mock(HttpResponse.class);
            HttpEntity httpEntity = Mockito.mock(HttpEntity.class);
            Mockito.when(httpEntity.getContent()).thenReturn(new ByteArrayInputStream(contents.getBytes()));
            Mockito.when(httpResponse.getEntity()).thenReturn(httpEntity);
            Mockito.when(mockClient.execute((HttpUriRequest)Mockito.any(), 
                    (HttpContext)Mockito.any())).thenReturn(httpResponse);
        }
        return mockClient;
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
