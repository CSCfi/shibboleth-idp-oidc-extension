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

package org.geant.idpextension.oidc.profile.flow;

import static org.testng.Assert.assertEquals;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;

import org.opensaml.storage.StorageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.webflow.executor.FlowExecutionResult;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;

/**
 * Unit tests for the token flow.
 */
public class TokenFlowTest extends AbstractOidcFlowTest<OIDCTokenResponse> {
    
    String FLOW_ID = "oidc/token";
    
    String redirectUri = "https://example.org/cb";
    String clientId = "mockClientId";
    String clientSecret = "mockClientSecret";
    
    @Autowired
    @Qualifier("shibboleth.StorageService")
    StorageService storageService;
    
    @Test
    public void testNoClientId() throws IOException, ParseException {
        setHttpFormRequest("POST", createRequestParameters(redirectUri, "authorization_code", "mockCode", null));
        final FlowExecutionResult result = flowExecutor.launchExecution(FLOW_ID, null, externalContext);
        assertEquals(result.getOutcome().getId(), "CommitResponse");
        assertErrorCode("invalid_request");
        assertErrorDescriptionContains("UnableToDecode");
    }

    @Test
    public void testNoGrantType() throws IOException, ParseException {
        setHttpFormRequest("POST", createRequestParameters(redirectUri, null, "mockCode", clientId));
        final FlowExecutionResult result = flowExecutor.launchExecution(FLOW_ID, null, externalContext);
        assertEquals(result.getOutcome().getId(), "CommitResponse");
        assertErrorCode("invalid_request");
        assertErrorDescriptionContains("UnableToDecode");
    }

    @Test
    public void testUntrustedClient() throws IOException, ParseException {
        setHttpFormRequest("POST", createRequestParameters(null, "authorization_code", "mockCode", clientId + "2"));
        final FlowExecutionResult result = flowExecutor.launchExecution(FLOW_ID, null, externalContext);
        assertEquals(result.getOutcome().getId(), "CommitResponse");
        assertErrorCode("invalid_request");
        assertErrorDescriptionContains("InvalidProfileConfiguration");
    }
    
    @Test
    public void testUnauthorized() throws IOException, ParseException {
        setHttpFormRequest("POST", createRequestParameters(redirectUri, "authorization_code", "mockCode", clientId));
        storeMetadata(storageService, clientId, clientSecret);
        final FlowExecutionResult result = flowExecutor.launchExecution(FLOW_ID, null, externalContext);
        removeMetadata(storageService, clientId);
        assertEquals(result.getOutcome().getId(), "CommitResponse");
        assertErrorCode("invalid_request");
        assertErrorDescriptionContains("AccessDenied");
    }

    @Test
    public void testInvalidGrant() throws ParseException, IOException {
        setHttpFormRequest("POST", createRequestParameters(redirectUri, "authorization_code", "mockCode", clientId));
        storeMetadata(storageService, clientId, clientSecret);
        setBasicAuth(clientId, clientSecret);
        final FlowExecutionResult result = flowExecutor.launchExecution(FLOW_ID, null, externalContext);
        removeMetadata(storageService, clientId);
        assertEquals(result.getOutcome().getId(), "CommitResponse");
        assertErrorCode("invalid_grant");
    }
    
    //TODO: add tests with valid grants
    
    protected Map<String, String> createRequestParameters(String redirectUri, String grantType, String code, String clientId) {
        Map<String, String> parameters = new HashMap<>();
        addNonNullValue(parameters, "redirect_uri", redirectUri);
        addNonNullValue(parameters, "grant_type", grantType);
        addNonNullValue(parameters, "code", code);
        addNonNullValue(parameters, "client_id", clientId);
        return parameters;
    }
    
    private void addNonNullValue(Map<String, String> map, String key, String value) {
        if (value != null) {
            map.put(key, value);
        }
    }
    
    /** {@inheritDoc} */
    @Override
    protected OIDCTokenResponse parseSuccessResponse() throws ParseException, UnsupportedEncodingException {
        return OIDCTokenResponse.parse(super.parseResponse());
    }
}
