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

import org.geant.idpextension.oauth2.messaging.impl.OAuth2RevocationSuccessResponse;
import org.opensaml.storage.StorageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.webflow.executor.FlowExecutionResult;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.Scope;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.security.DataSealerException;

/**
 * Unit tests for the OAuth2 revocation flow.
 */
public class RevocationFlowTest extends AbstractOidcApiFlowTest {

    public static final String FLOW_ID = "oauth2/revocation";
    
    String clientId = "mockClientId";
    String clientSecret = "mockClientSecret";
    
    @Autowired
    @Qualifier("shibboleth.StorageService")
    StorageService storageService;
    
    public RevocationFlowTest() {
        super(FLOW_ID);
    }

    @BeforeMethod
    public void setup() throws IOException {
        removeMetadata(storageService, clientId);
    }

    @Test
    public void testUntrustedClient() throws IOException, NoSuchAlgorithmException, URISyntaxException,
        DataSealerException, ComponentInitializationException {
        setBasicAuth(clientId, clientSecret);
        setHttpFormRequest("POST", Collections.singletonMap("token", super.buildToken(clientId, "sub", 
                Scope.parse("openid")).toJSONObject().getAsString("access_token")));
        final FlowExecutionResult result = flowExecutor.launchExecution(FLOW_ID, null, externalContext);
        assertErrorCode(result, "invalid_request");
        assertErrorDescriptionContains(result, "InvalidProfileConfiguration");
    }

    @Test
    public void testSuccess() throws IOException, NoSuchAlgorithmException, URISyntaxException,
        DataSealerException, ComponentInitializationException {
        setBasicAuth(clientId, clientSecret);
        setHttpFormRequest("POST", Collections.singletonMap("token", super.buildToken(clientId, "sub", 
                Scope.parse("openid")).toJSONObject().getAsString("access_token")));
        storeMetadata(storageService, clientId, clientSecret);
        final FlowExecutionResult result = flowExecutor.launchExecution(FLOW_ID, null, externalContext);
        parseSuccessResponse(result, OAuth2RevocationSuccessResponse.class);
    }
}
