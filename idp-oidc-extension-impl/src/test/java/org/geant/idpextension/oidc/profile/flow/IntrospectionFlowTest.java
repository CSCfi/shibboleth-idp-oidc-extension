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
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;

import org.opensaml.storage.StorageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.webflow.executor.FlowExecutionResult;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenIntrospectionErrorResponse;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.security.DataSealerException;

/**
 * Unit tests for the OAuth2 introspection flow.
 */
public class IntrospectionFlowTest extends AbstractOidcApiFlowTest {

    public static final String FLOW_ID = "oauth2/introspection";

    String clientId = "mockClientId";

    String clientSecret = "mockClientSecret";

    @Autowired
    @Qualifier("shibboleth.StorageService")
    StorageService storageService;
    
    public IntrospectionFlowTest() {
        super(FLOW_ID);
    }

    @BeforeMethod
    public void setup() throws IOException, NoSuchAlgorithmException, URISyntaxException, DataSealerException,
            ComponentInitializationException {
        removeMetadata(storageService, clientId);
    }

    @Test
    public void testUntrustedClient() throws IOException, NoSuchAlgorithmException, URISyntaxException,
            DataSealerException, ComponentInitializationException {
        setBasicAuth(clientId, clientSecret);
        setHttpFormRequest("POST", Collections.singletonMap("token",
                super.buildToken(clientId, "sub", Scope.parse("openid")).toJSONObject().getAsString("access_token")));
        final FlowExecutionResult result = flowExecutor.launchExecution(FLOW_ID, null, externalContext);
        assertErrorCode(result, "invalid_request");
        assertErrorDescriptionContains(result, "InvalidProfileConfiguration");
    }
    
    @Test
    public void testInvalidMessage() throws IOException, NoSuchAlgorithmException, URISyntaxException,
            DataSealerException, ComponentInitializationException {
        storeMetadata(storageService, clientId, clientSecret);
        setBasicAuth(clientId, clientSecret);
        setHttpFormRequest("POST", Collections.singletonMap("token_not",
                super.buildToken(clientId, "sub", Scope.parse("openid")).toJSONObject().getAsString("access_token")));
        final FlowExecutionResult result = flowExecutor.launchExecution(FLOW_ID, null, externalContext);
        assertErrorCode(result, "invalid_request");
    }

    @Test
    public void testSuccess() throws IOException, NoSuchAlgorithmException, URISyntaxException, DataSealerException,
            ComponentInitializationException {
        storeMetadata(storageService, clientId, clientSecret);
        setBasicAuth(clientId, clientSecret);
        setHttpFormRequest("POST", Collections.singletonMap("token",
                super.buildToken(clientId, "sub", Scope.parse("openid")).toJSONObject().getAsString("access_token")));
        final FlowExecutionResult result = flowExecutor.launchExecution(FLOW_ID, null, externalContext);
        TokenIntrospectionSuccessResponse resp = parseSuccessResponse(result, TokenIntrospectionSuccessResponse.class);
        Assert.assertEquals(resp.getClientID().getValue(), clientId);
        Assert.assertTrue(resp.isActive());
    }

    @Test
    public void testUnidentifiedToken() throws IOException, NoSuchAlgorithmException, URISyntaxException,
            DataSealerException, ComponentInitializationException {
        storeMetadata(storageService, clientId, clientSecret);
        setBasicAuth(clientId, clientSecret);
        setHttpFormRequest("POST", Collections.singletonMap("token", "unknowntoken"));
        final FlowExecutionResult result = flowExecutor.launchExecution(FLOW_ID, null, externalContext);
        TokenIntrospectionSuccessResponse resp = parseSuccessResponse(result, TokenIntrospectionSuccessResponse.class);
        Assert.assertNull(resp.getClientID());
        Assert.assertFalse(resp.isActive());
    }
    
    @Test
    public void testFailedAuthentication() throws IOException, NoSuchAlgorithmException, URISyntaxException,
            DataSealerException, ComponentInitializationException {
        storeMetadata(storageService, clientId, clientSecret);
        setBasicAuth(clientId, clientSecret + "X");
        setHttpFormRequest("POST", Collections.singletonMap("token",
                super.buildToken(clientId, "sub", Scope.parse("openid")).toJSONObject().getAsString("access_token")));
        final FlowExecutionResult result = flowExecutor.launchExecution(FLOW_ID, null, externalContext);
        TokenIntrospectionErrorResponse resp = (TokenIntrospectionErrorResponse) parseErrorResponse(result);
        Assert.assertEquals(resp.getErrorObject().getCode(), "invalid_client");
    }
}
