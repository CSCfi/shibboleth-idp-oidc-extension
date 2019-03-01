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
