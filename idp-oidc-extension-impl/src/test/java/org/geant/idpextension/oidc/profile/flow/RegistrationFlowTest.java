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

package org.geant.idpextension.oidc.profile.flow;

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
public class RegistrationFlowTest extends AbstractOidcFlowTest {
    
    public static final String FLOW_ID = "oidc/register";
    
    String redirectUri = "https://example.org/cb";
    
    @Autowired
    @Qualifier("shibboleth.StorageService")
    StorageService storageService;
    
    public RegistrationFlowTest() {
        super(FLOW_ID);
    }

    @Test
    public void testNoRedirectUri() throws UnsupportedEncodingException, ParseException {
        setJsonRequest("POST", "{ \"test\":false }");
        final FlowExecutionResult result = flowExecutor.launchExecution(FLOW_ID, null, externalContext);
        assertErrorCode(result, "invalid_redirect_uri");
    }

    @Test
    public void testInvalidMessage() throws UnsupportedEncodingException, ParseException {
        setJsonRequest("POST", "{ \"test\":not_json");
        final FlowExecutionResult result = flowExecutor.launchExecution(FLOW_ID, null, externalContext);
        assertErrorCode(result, "invalid_request");
    }
    
    @Test
    public void testSuccess() throws ParseException, IOException, net.minidev.json.parser.ParseException {
        setJsonRequest("POST", "{ \"redirect_uris\":[\"" + redirectUri + "\"] }");
        final FlowExecutionResult result = flowExecutor.launchExecution(FLOW_ID, null, externalContext);
        OIDCClientInformationResponse parsedResponse = parseSuccessResponse(result, OIDCClientInformationResponse.class);
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

}
