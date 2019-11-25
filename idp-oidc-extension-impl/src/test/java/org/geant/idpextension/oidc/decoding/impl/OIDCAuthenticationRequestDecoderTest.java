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

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;

/**
 * Unit tests for {@link OIDCAuthenticationRequestDecoder}.
 */
public class OIDCAuthenticationRequestDecoderTest {

	private MockHttpServletRequest httpRequest;
	private OIDCAuthenticationRequestDecoder decoder;

	@BeforeMethod
	protected void setUp() throws Exception {
		httpRequest = new MockHttpServletRequest();
		httpRequest.setMethod("GET");
		decoder = new OIDCAuthenticationRequestDecoder();
		decoder.setHttpServletRequest(httpRequest);
		decoder.initialize();
	}

    @Test
	public void testRequestDecoding() throws MessageDecodingException {
		httpRequest
				.setQueryString("response_type=code&client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid%20profile&state=af0ifjsldkj&nonce=n-0S6_WzA2Mj");
		decoder.decode();
		MessageContext<AuthenticationRequest> messageContext = decoder
				.getMessageContext();
		// We are not testing nimbus itself here, i.e. we are happy to decode
		// one parameter successfully
		Assert.assertEquals(messageContext.getMessage().getResponseType()
				.toString(), ResponseType.Value.CODE.toString());

	}

	@Test(expectedExceptions = MessageDecodingException.class)
	public void testInvalidRequestDecoding() throws MessageDecodingException {
		// Mandatory response_type parameter removed, decoding should fail
		httpRequest
				.setQueryString("client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid%20profile&state=af0ifjsldkj&nonce=n-0S6_WzA2Mj");
		decoder.decode();
	}
}