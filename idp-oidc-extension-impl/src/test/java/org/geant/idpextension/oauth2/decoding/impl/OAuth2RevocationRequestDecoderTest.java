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

package org.geant.idpextension.oauth2.decoding.impl;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import com.nimbusds.oauth2.sdk.TokenRevocationRequest;

/**
 * Unit tests for {@link OAuth2RevocationRequestDecoder}.
 */
public class OAuth2RevocationRequestDecoderTest {

    private MockHttpServletRequest httpRequest;

    private OAuth2RevocationRequestDecoder decoder;

    @BeforeMethod
    protected void setUp() throws Exception {
        httpRequest = new MockHttpServletRequest();
        httpRequest.setMethod("POST");
        httpRequest.addHeader("Content-Type", "application/x-www-form-urlencoded");
        httpRequest.addParameter("token", "45ghiukldjahdnhzdauz");
        httpRequest.addParameter("token_type_hint", "refresh_token");
        httpRequest.addParameter("client_id", "123456");
        decoder = new OAuth2RevocationRequestDecoder();
        decoder.setHttpServletRequest(httpRequest);
        decoder.initialize();
    }

    @Test
    public void testRequestDecoding() throws MessageDecodingException {
        decoder.decode();
        MessageContext<TokenRevocationRequest> messageContext = decoder.getMessageContext();
        // We are not testing nimbus itself here, i.e. we are happy to decode
        // one parameter successfully
        Assert.assertEquals(messageContext.getMessage().getClientID().toString(), "123456");

    }

    @Test(expectedExceptions = MessageDecodingException.class)
    public void testInvalidRequestDecoding() throws MessageDecodingException {
        httpRequest.removeParameter("token");
        decoder.decode();
    }
}