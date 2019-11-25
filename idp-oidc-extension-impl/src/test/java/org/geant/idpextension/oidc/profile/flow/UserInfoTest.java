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

import org.geant.idpextension.oidc.token.support.TokenDeliveryClaimsClaimsSet;
import org.opensaml.storage.StorageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.webflow.executor.FlowExecutionResult;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.security.DataSealerException;

/**
 * Unit tests for the OIDC UserInfo flow.
 */
public class UserInfoTest extends AbstractOidcApiFlowTest {

    public static final String FLOW_ID = "oidc/userinfo";
    
    String clientId = "mockClientId";
    String subject = "mockSubject";
    
    @Autowired
    @Qualifier("shibboleth.StorageService")
    StorageService storageService;

    public UserInfoTest() {
        super(FLOW_ID);
    }
    
    @BeforeMethod
    public void init() throws IOException {
        request.setMethod("GET");
        removeMetadata(storageService, clientId);
    }

    @Test
    public void testNoAccessToken() {
        final FlowExecutionResult result = flowExecutor.launchExecution(FLOW_ID, null, externalContext);
        assertErrorCode(result, "invalid_request");
        assertErrorDescriptionContains(result, "UnableToDecode");
    }

    @Test
    public void testUnparseableAccessToken() {
        request.addHeader("Authorization", "Bearer mockAccessToken");
        final FlowExecutionResult result = flowExecutor.launchExecution(FLOW_ID, null, externalContext);
        assertErrorCode(result, "invalid_grant");
    }
    
    @Test
    public void testFailsUntrustedClient() throws URISyntaxException, NoSuchAlgorithmException, DataSealerException,
        ComponentInitializationException {
        BearerAccessToken token = buildToken(idGenerator.generateIdentifier(), subject, new Scope());
        request.addHeader("Authorization", token.toAuthorizationHeader());
        final FlowExecutionResult result = flowExecutor.launchExecution(FLOW_ID, null, externalContext);
        assertErrorCode(result, "invalid_request");
    }

    @Test
    public void testSuccessOnlySubject() throws URISyntaxException, NoSuchAlgorithmException, DataSealerException,
        ComponentInitializationException, IOException {
        BearerAccessToken token = buildToken(clientId, subject, new Scope("openid"));
        storeMetadata(storageService, clientId, "mockSecret");
        request.addHeader("Authorization", token.toAuthorizationHeader());
        final FlowExecutionResult result = flowExecutor.launchExecution(FLOW_ID, null, externalContext);
        UserInfoSuccessResponse response = parseSuccessResponse(result, UserInfoSuccessResponse.class);
        Assert.assertEquals(response.getUserInfo().getSubject().getValue(), subject);
        UserInfo userInfo = response.getUserInfo();
        Assert.assertNotNull(userInfo);
        Assert.assertNull(userInfo.getEmailAddress());
        Assert.assertNull(userInfo.getNickname());
        Assert.assertNull(response.getUserInfoJWT());
    }

    @Test
    public void testSuccessEmailResolution() throws URISyntaxException, NoSuchAlgorithmException, DataSealerException,
        ComponentInitializationException, IOException {
        BearerAccessToken token = buildToken(clientId, subject, new Scope("openid", "email", "profile"));
        storeMetadata(storageService, clientId, "mockSecret");
        request.addHeader("Authorization", token.toAuthorizationHeader());
        final FlowExecutionResult result = flowExecutor.launchExecution(FLOW_ID, null, externalContext);
        UserInfoSuccessResponse response = parseSuccessResponse(result, UserInfoSuccessResponse.class);
        UserInfo userInfo = response.getUserInfo();
        Assert.assertNotNull(userInfo);
        Assert.assertEquals(userInfo.getSubject().getValue(), subject);
        Assert.assertEquals(userInfo.getEmailAddress(), "jdoe@example.org");
        Assert.assertNull(userInfo.getNickname());
        Assert.assertNull(response.getUserInfoJWT());
    }

    @Test
    public void testSuccessNicknameInToken() throws URISyntaxException, NoSuchAlgorithmException, DataSealerException,
        ComponentInitializationException, IOException {
        TokenDeliveryClaimsClaimsSet set = new TokenDeliveryClaimsClaimsSet();
        set.setClaim("nickname", "mockNickname");
        BearerAccessToken token = buildToken(clientId, subject, new Scope("openid", "profile"), set);
        storeMetadata(storageService, clientId, "mockSecret");
        request.addHeader("Authorization", token.toAuthorizationHeader());
        final FlowExecutionResult result = flowExecutor.launchExecution(FLOW_ID, null, externalContext);
        UserInfoSuccessResponse response = parseSuccessResponse(result, UserInfoSuccessResponse.class);
        UserInfo userInfo = response.getUserInfo();
        Assert.assertNotNull(userInfo);
        Assert.assertEquals(userInfo.getSubject().getValue(), subject);
        Assert.assertNull(userInfo.getEmailAddress());
        Assert.assertEquals(userInfo.getNickname(), "mockNickname");
        Assert.assertNull(response.getUserInfoJWT());
    }
}
