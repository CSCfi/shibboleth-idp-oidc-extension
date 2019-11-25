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

import org.opensaml.storage.StorageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.webflow.executor.FlowExecutionResult;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;

import net.shibboleth.idp.session.SessionException;

/**
 * Tests for the authorize-flow.
 */
public class AuthorizeFlowTest extends AbstractOidcFlowTest {
    
    public static final String FLOW_ID = "oidc/authorize";
    
    String redirectUri = "https://example.org/cb";
    String clientId = "mockClientId";
    String clientSecret = "mockClientSecret";
    
    @Autowired
    @Qualifier("shibboleth.StorageService")
    StorageService storageService;
    
    public AuthorizeFlowTest() {
        super(FLOW_ID);
    }
    
    @BeforeMethod
    public void setup() {
        setBasicAuth("jdoe", "changeit");
    }

    @Test
    public void testWithAuthorizationCodeFlow() throws IOException, ParseException, SessionException {
        request.setMethod("GET");
        request.setQueryString("client_id=mockClientId&response_type=code&scope=openid%20profile&redirect_uri="
                + redirectUri);
        storeMetadata(storageService, clientId, clientSecret, redirectUri);

        initializeThreadLocals();
        
        FlowExecutionResult result = flowExecutor.launchExecution(FLOW_ID, null, externalContext);
        AuthenticationResponse responseMessage = parseSuccessResponse(result, AuthenticationResponse.class);
        AuthenticationSuccessResponse successResponse = responseMessage.toSuccessResponse();
        Assert.assertEquals(successResponse.getRedirectionURI().toString(), redirectUri);
        Assert.assertNull(successResponse.getIDToken());
        Assert.assertNull(successResponse.getAccessToken());
        Assert.assertNotNull(successResponse.getAuthorizationCode());
    }

}
