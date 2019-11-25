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
