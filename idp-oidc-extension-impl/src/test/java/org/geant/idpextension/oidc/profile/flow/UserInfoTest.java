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
