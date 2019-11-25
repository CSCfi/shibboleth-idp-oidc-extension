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

package org.geant.idpextension.oidc.decoding.impl;

import java.io.IOException;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest.Method;

/**
 * Unit tests for {@link OIDCTokenRequestDecoder}.
 */
public class OIDCTokenRequestDecoderTest {

    private MockHttpServletRequest httpRequest;

    private OIDCTokenRequestDecoder decoder;

    @BeforeMethod
    protected void setUp() throws Exception {
        httpRequest = new MockHttpServletRequest();
        httpRequest.setMethod(Method.POST.toString());
        decoder = new OIDCTokenRequestDecoder();
        decoder.setHttpServletRequest(httpRequest);
        decoder.initialize();
    }

    @Test(expectedExceptions = MessageDecodingException.class)
    public void testInvalidJson() throws MessageDecodingException {
        httpRequest.setContent("\"test\" : \"test\" }".getBytes());
        httpRequest.setContentType("application/json");
        decoder.decode();
    }

    @Test
    public void testRequestDecoding() throws MessageDecodingException, IOException {
        httpRequest.addHeader("Authorization", "Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW");
        httpRequest.setContentType("application/x-www-form-urlencoded");
        httpRequest.addParameter("grant_type", "authorization_code");
        httpRequest.addParameter("code", "SplxlOBeZQQYbYS6WxSbIA");
        httpRequest.addParameter("redirect_uri", "https://client.example.org/cb");
        decoder.decode();
        final MessageContext<TokenRequest> messageContext = decoder.getMessageContext();
        final TokenRequest message = messageContext.getMessage();
        Assert.assertEquals(message.getAuthorizationGrant().getType().getValue(), "authorization_code");
    }
}