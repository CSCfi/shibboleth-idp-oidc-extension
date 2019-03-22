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
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.geant.idpextension.oidc.metadata.impl.BaseStorageServiceClientInformationComponent;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.storage.StorageService;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.webflow.executor.FlowExecutionResult;
import org.springframework.webflow.test.MockExternalContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;

import com.nimbusds.oauth2.sdk.ErrorResponse;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.shibboleth.idp.test.flows.AbstractFlowTest;
import net.shibboleth.utilities.java.support.net.HttpServletRequestResponseContext;

/**
 * Abstract unit test for the OIDC flows.
 */
public abstract class AbstractOidcFlowTest extends AbstractFlowTest {
    
    public static final String END_STATE_ID = "CommitResponse";
    
    private String flowId;
    
    protected AbstractOidcFlowTest(String flowId) {
        this.flowId = flowId;
    }
    
    /**
     * Initialize mock request, response, and external context. Overrides to remove authorization header.
     */
    @BeforeMethod public void initializeMocks() {
        overrideEndStateOutput(flowId, END_STATE_ID);

        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        externalContext = new MockExternalContext();
        externalContext.setNativeRequest(request);
        externalContext.setNativeResponse(response);
    }
    
    /**
     * {@link HttpServletRequestResponseContext#loadCurrent(HttpServletRequest, HttpServletResponse)}
     */
    @BeforeMethod public void initializeThreadLocals() {
        HttpServletRequestResponseContext.loadCurrent((HttpServletRequest) request, (HttpServletResponse) response);
    }
    
    protected Response parseResponse(final FlowExecutionResult result) {
        assertFlowExecutionOutcome(result.getOutcome(), END_STATE_ID);
        ProfileRequestContext<?, ?> prc = retrieveProfileRequestContext(result);
        Assert.assertNotNull(prc);
        Assert.assertNotNull(prc.getOutboundMessageContext());
        Object responseMessage = prc.getOutboundMessageContext().getMessage();
        Assert.assertNotNull(responseMessage);
        Assert.assertTrue(responseMessage instanceof Response);
        return (Response) responseMessage;
    }
    
    protected ErrorResponse parseErrorResponse(final FlowExecutionResult result) {
        Response response = parseResponse(result);
        Assert.assertFalse(response.indicatesSuccess());
        Assert.assertTrue(response instanceof ErrorResponse);
        return (ErrorResponse) response;
    }
    
    protected <AResponseType extends Response> AResponseType parseSuccessResponse(final FlowExecutionResult result,
            Class<AResponseType> clazz) {
        Response response = parseResponse(result);
        Assert.assertTrue(response.indicatesSuccess());
        Assert.assertTrue(clazz.isInstance(response));
        return clazz.cast(response);
    }
    
    protected void assertErrorCode(final FlowExecutionResult result, String errorCode) {
        ErrorResponse errorResponse = parseErrorResponse(result);
        Assert.assertEquals(errorResponse.getErrorObject().getCode(), errorCode);
    }

    protected void assertErrorDescriptionContains(final FlowExecutionResult result, String errorDescription) {
        ErrorResponse errorResponse = parseErrorResponse(result);
        Assert.assertNotNull(errorResponse.getErrorObject().getDescription());
        Assert.assertTrue(errorResponse.getErrorObject().getDescription().contains(errorDescription));
    }
    
    protected void setJsonRequest(String method, String body) {
        setRequest(method, body, "application/json");
    }
    
    protected void setHttpFormRequest(String method, Map<String, String> parameters) {
        setRequest(method, "", "application/x-www-form-urlencoded");
        request.setParameters(parameters);
    }
    
    protected void setBasicAuth(String username, String password) {
        request.addHeader("Authorization",
                "Basic " + new String(Base64.encodeBase64(new String(username + ":" + password).getBytes())));
    }
    
    protected void setRequest(String method, String body, String contentType) {
        request.setMethod(method);
        request.setContentType(contentType);
        request.setContent(body.getBytes());   
    }
    
    protected void storeMetadata(StorageService storageService, String clientId, String secret, String... redirectUri)
            throws IOException {
        OIDCClientMetadata metadata = new OIDCClientMetadata();
        metadata.setGrantTypes(new HashSet<GrantType>(Arrays.asList(GrantType.AUTHORIZATION_CODE)));
        HashSet<URI> uris = new HashSet<>();
        for (String uri : redirectUri) {
            try {
                uris.add(new URI(uri));
            } catch (URISyntaxException e) {
                e.printStackTrace();
            }
        }
        HashSet<ResponseType> responseTypes = new HashSet<>();
        responseTypes.add(new ResponseType("code"));
        metadata.setResponseTypes(responseTypes);
        metadata.setRedirectionURIs(uris);
        metadata.setScope(Scope.parse("openid profile email"));
        OIDCClientInformation information = new OIDCClientInformation(new ClientID(clientId), new Date(), metadata, 
                new Secret(secret));
        storageService.create(BaseStorageServiceClientInformationComponent.CONTEXT_NAME, clientId, 
                information.toJSONObject().toJSONString(), System.currentTimeMillis() + 60000);
    }
    
    protected void removeMetadata(StorageService storageService, String clientId) throws IOException {
        storageService.delete(BaseStorageServiceClientInformationComponent.CONTEXT_NAME, clientId);
    }

}
