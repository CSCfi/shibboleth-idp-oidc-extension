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
