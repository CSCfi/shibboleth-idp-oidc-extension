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

import org.geant.idpextension.oidc.metadata.impl.BaseStorageServiceClientInformationComponent;
import org.opensaml.storage.StorageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.webflow.executor.FlowExecutionResult;
import org.testng.Assert;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformationResponse;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;

/**
 * Some tests for the dynamic registration flow.
 */
public class RegistrationFlowTest extends AbstractOidcFlowTest<OIDCClientInformationResponse> {
    
    String FLOW_ID = "oidc/register";
    
    String redirectUri = "https://example.org/cb";
    
    @Autowired
    @Qualifier("shibboleth.StorageService")
    StorageService storageService;

    @Test
    public void testNoRedirectUri() throws UnsupportedEncodingException, ParseException {
        setJsonRequest("POST", "{ \"test\":false }");
        final FlowExecutionResult result = flowExecutor.launchExecution(FLOW_ID, null, externalContext);
        assertEquals(result.getOutcome().getId(), "CommitResponse");
        assertErrorCode("invalid_redirect_uri");
    }

    @Test
    public void testInvalidMessage() throws UnsupportedEncodingException, ParseException {
        setJsonRequest("POST", "{ \"test\":not_json");
        final FlowExecutionResult result = flowExecutor.launchExecution(FLOW_ID, null, externalContext);
        assertEquals(result.getOutcome().getId(), "CommitResponse");
        assertErrorCode("invalid_request");
    }
    
    @Test
    public void testSuccess() throws ParseException, IOException, net.minidev.json.parser.ParseException {
        setJsonRequest("POST", "{ \"redirect_uris\":[\"" + redirectUri + "\"] }");
        final FlowExecutionResult result = flowExecutor.launchExecution(FLOW_ID, null, externalContext);
        assertEquals(result.getOutcome().getId(), "CommitResponse");
        assertSuccess();
        OIDCClientInformationResponse parsedResponse = parseSuccessResponse();
        OIDCClientInformation clientInfo = parsedResponse.getOIDCClientInformation();
        OIDCClientMetadata metadata = clientInfo.getOIDCMetadata();
        String record = storageService.read(BaseStorageServiceClientInformationComponent.CONTEXT_NAME, 
                clientInfo.getID().toString()).getValue();
        Assert.assertNotNull(record);
        JSONParser parser = new JSONParser(JSONParser.DEFAULT_PERMISSIVE_MODE);
        OIDCClientInformation storedInfo = OIDCClientInformation.parse((JSONObject) parser.parse(record));
        Assert.assertEquals(storedInfo.getID(), clientInfo.getID());
        Assert.assertEquals(storedInfo.getSecret(), clientInfo.getSecret());
        Assert.assertEquals(storedInfo.getOIDCMetadata().getRedirectionURIStrings(), metadata.getRedirectionURIStrings());
        Assert.assertTrue(metadata.getRedirectionURIStrings().contains(redirectUri));
    }

    protected OIDCClientInformationResponse parseSuccessResponse() throws ParseException, UnsupportedEncodingException {
        return OIDCClientInformationResponse.parse(super.parseResponse());
    }   
}
