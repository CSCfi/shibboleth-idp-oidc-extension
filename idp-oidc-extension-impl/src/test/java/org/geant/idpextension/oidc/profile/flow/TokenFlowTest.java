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
import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import org.geant.idpextension.oidc.profile.impl.ValidateGrantTest;
import org.opensaml.storage.StorageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.webflow.executor.FlowExecutionResult;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.ClientSecretJWT;
import com.nimbusds.oauth2.sdk.auth.JWTAuthentication;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.security.DataSealerException;

/**
 * Unit tests for the token flow.
 */
public class TokenFlowTest extends AbstractOidcFlowTest {
    
    public static final String FLOW_ID = "oidc/token";
    
    String redirectUri = "https://example.org/cb";
    String clientId = "mockClientId";
    String clientSecret = "mockClientSecretmockClientSecretmockClientSecret";
    
    @Autowired
    @Qualifier("shibboleth.StorageService")
    StorageService storageService;
    
    public TokenFlowTest() {
        super(FLOW_ID);
    }
    
    @BeforeMethod
    public void setup() throws IOException {
        removeMetadata(storageService, clientId);
    }
    
    @Test
    public void testNoClientId() throws IOException, ParseException {
        setHttpFormRequest("POST", createRequestParameters(redirectUri, "authorization_code", "mockCode", null));
        final FlowExecutionResult result = flowExecutor.launchExecution(FLOW_ID, null, externalContext);
        assertErrorCode(result, "invalid_request");
        assertErrorDescriptionContains(result, "UnableToDecode");
    }

    @Test
    public void testNoGrantType() throws IOException, ParseException {
        setHttpFormRequest("POST", createRequestParameters(redirectUri, null, "mockCode", clientId));
        final FlowExecutionResult result = flowExecutor.launchExecution(FLOW_ID, null, externalContext);
        assertErrorCode(result, "invalid_request");
        assertErrorDescriptionContains(result, "UnableToDecode");
    }

    @Test
    public void testUntrustedClient() throws IOException, ParseException {
        setHttpFormRequest("POST", createRequestParameters(null, "authorization_code", "mockCode", clientId + "2"));
        final FlowExecutionResult result = flowExecutor.launchExecution(FLOW_ID, null, externalContext);
        assertErrorCode(result, "invalid_request");
        assertErrorDescriptionContains(result, "InvalidProfileConfiguration");
    }
    
    @Test
    public void testUnauthorized() throws IOException, ParseException {
        setHttpFormRequest("POST", createRequestParameters(redirectUri, "authorization_code", "mockCode", clientId));
        storeMetadata(storageService, clientId, clientSecret);
        final FlowExecutionResult result = flowExecutor.launchExecution(FLOW_ID, null, externalContext);
        assertErrorCode(result, "invalid_request");
        assertErrorDescriptionContains(result, "AccessDenied");
    }

    @Test
    public void testInvalidGrant() throws ParseException, IOException {
        setHttpFormRequest("POST", createRequestParameters(redirectUri, "authorization_code", "mockCode", clientId));
        storeMetadata(storageService, clientId, clientSecret);
        setBasicAuth(clientId, clientSecret);
        final FlowExecutionResult result = flowExecutor.launchExecution(FLOW_ID, null, externalContext);
        assertErrorCode(result, "invalid_grant");
    }

    @Test
    public void testValidGrant() throws ParseException, IOException, NoSuchAlgorithmException, URISyntaxException,
        DataSealerException, ComponentInitializationException {
        String code = ValidateGrantTest.buildAuthorizationCode(clientId, "https://op.example.org", "jdoe", "mock",
                redirectUri).toString();
        setHttpFormRequest("POST", createRequestParameters(redirectUri, "authorization_code", code, clientId));
        storeMetadata(storageService, clientId, clientSecret);
        setBasicAuth(clientId, clientSecret);
        final FlowExecutionResult result = flowExecutor.launchExecution(FLOW_ID, null, externalContext);
        OIDCTokenResponse response = parseSuccessResponse(result, OIDCTokenResponse.class);
        Assert.assertNotNull(response.getTokens().getAccessToken());
    }

    @Test
    public void testValidSecretJWT() throws ParseException, IOException, NoSuchAlgorithmException, URISyntaxException,
        DataSealerException, ComponentInitializationException, JOSEException {
        ClientSecretJWT clientAuth = buildSecretJwtAuth(clientSecret);
        final FlowExecutionResult result = launchWithJwtAuthentication(clientAuth, JWSAlgorithm.HS256);
        OIDCTokenResponse response = parseSuccessResponse(result, OIDCTokenResponse.class);
        Assert.assertNotNull(response.getTokens().getAccessToken());
    }

    @Test
    public void testValidSecretJWTNoAlg() throws ParseException, IOException, NoSuchAlgorithmException, URISyntaxException,
        DataSealerException, ComponentInitializationException, JOSEException {
        ClientSecretJWT clientAuth = buildSecretJwtAuth(clientSecret);
        final FlowExecutionResult result = launchWithJwtAuthentication(clientAuth, null);
        OIDCTokenResponse response = parseSuccessResponse(result, OIDCTokenResponse.class);
        Assert.assertNotNull(response.getTokens().getAccessToken());
    }

    @Test
    public void testInvalidSecretJWT() throws ParseException, IOException, NoSuchAlgorithmException, URISyntaxException,
        DataSealerException, ComponentInitializationException, JOSEException {
        ClientSecretJWT clientAuth = buildSecretJwtAuth(clientSecret + "invalid");
        final FlowExecutionResult result = launchWithJwtAuthentication(clientAuth, JWSAlgorithm.HS256);
        assertErrorCode(result, "invalid_request");
        assertErrorDescriptionContains(result, "AccessDenied");
    }
    
    protected FlowExecutionResult launchWithJwtAuthentication(final JWTAuthentication authnMethod, final JWSAlgorithm algorithm)
            throws NoSuchAlgorithmException, URISyntaxException, DataSealerException, ComponentInitializationException,
            IOException {
        String code = ValidateGrantTest.buildAuthorizationCode(clientId, "https://op.example.org", "jdoe", "mock",
                redirectUri).toString();
        storeMetadata(storageService, clientId, clientSecret, JWSAlgorithm.HS256,
                ClientAuthenticationMethod.CLIENT_SECRET_JWT);
        Map<String, String> requestParameters = createRequestParameters(redirectUri, "authorization_code", code, clientId);
        populateClientAssertionParams(requestParameters, authnMethod);
        setHttpFormRequest("POST", requestParameters);
        return flowExecutor.launchExecution(FLOW_ID, null, externalContext);
    }
    
    protected ClientSecretJWT buildSecretJwtAuth(String secret) throws JOSEException, URISyntaxException {
        return new ClientSecretJWT(new ClientID(clientId), new URI("https://op.example.org"),
                JWSAlgorithm.HS256, new Secret(secret));
    }
    
    protected void populateClientAssertionParams(final Map<String, String> requestParameters, 
            final JWTAuthentication clientAuth) {
        requestParameters.put("client_assertion", clientAuth.getClientAssertion().serialize());
        requestParameters.put("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
    }

    protected Map<String, String> createRequestParameters(String redirectUri, String grantType, String code, 
            String clientId) {
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
}
