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

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collections;

import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.StringEntity;
import org.apache.http.protocol.HttpContext;
import org.mockito.Mockito;
import org.opensaml.profile.action.EventIds;
import org.opensaml.security.httpclient.HttpClientSecurityParameters;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.shibboleth.idp.profile.ActionTestingSupport;

/**
 * Unit tests for {@link AddJwksToClientMetadata}.
 */
public class AddJwksToClientMetadataTest extends BaseOIDCClientMetadataPopulationTest {
    
    URI MOCK_URI = URI.create("https://mock.com");

    @Override
    protected AbstractOIDCClientMetadataPopulationAction constructAction() {
        AddJwksToClientMetadata action = new AddJwksToClientMetadata();
        try {
            ((AddJwksToClientMetadata) action).setHttpClient(buildMockHttpClient("mock"));
        } catch (IOException e) {
            return null;
        }
        return action;
    }

    @BeforeMethod
    public void setUp() throws Exception {
        action = constructAction();
        action.initialize();
    }
    
    protected HttpClient buildMockHttpClient(String contents) throws ClientProtocolException, IOException {
        HttpResponse mockResponse = Mockito.mock(HttpResponse.class);
        Mockito.when(mockResponse.getEntity()).thenReturn(new StringEntity(contents));
        HttpClient mockClient = Mockito.mock(HttpClient.class);
        Mockito.when(mockClient.execute((HttpUriRequest) Mockito.any(),
                (HttpContext) Mockito.any())).thenReturn(mockResponse);
        return mockClient;
    }
    
    protected AddJwksToClientMetadata constructWithProperties(String contents) throws Exception {
        AddJwksToClientMetadata action = new AddJwksToClientMetadata();
        action.setHttpClient(buildMockHttpClient(contents));
        final HttpClientSecurityParameters params = new HttpClientSecurityParameters();
        params.setTLSProtocols(Collections.singleton("TLSv1"));
        action.setHttpClientSecurityParameters(params);
        action.initialize();
        return action;
    }
    
    @Test
    public void testEmptyContents() throws Exception {
        action = constructWithProperties("");
        OIDCClientMetadata request = new OIDCClientMetadata();
        request.setJWKSetURI(MOCK_URI);
        OIDCClientMetadata result = new OIDCClientMetadata();
        setUpContext(request, result);
        Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_MESSAGE);
    }
    
    @Test
    public void testInvalidJson() throws Exception {
        action = constructWithProperties("not json");
        OIDCClientMetadata request = new OIDCClientMetadata();
        request.setJWKSetURI(MOCK_URI);
        OIDCClientMetadata result = new OIDCClientMetadata();
        setUpContext(request, result);
        Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_MESSAGE);
    }
    
    @Test
    public void testValidJsonNoKeys() throws Exception {
        action = constructWithProperties("{ \"mock\" : \"mock\" }");
        OIDCClientMetadata request = new OIDCClientMetadata();
        request.setJWKSetURI(MOCK_URI);
        OIDCClientMetadata result = new OIDCClientMetadata();
        setUpContext(request, result);
        Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_MESSAGE);
    }

    @Test
    public void testValidJwks() throws Exception {
        String json = new String(Files.readAllBytes(Paths.get(getClass().getResource(
                "/org/geant/idpextension/oidc/metadata/impl/public_keys.jwks").toURI())));
        action = constructWithProperties(json);
        OIDCClientMetadata request = new OIDCClientMetadata();
        request.setJWKSetURI(MOCK_URI);
        OIDCClientMetadata result = new OIDCClientMetadata();
        setUpContext(request, result);
        Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertEquals(result.getJWKSetURI(), MOCK_URI);
    }

}
