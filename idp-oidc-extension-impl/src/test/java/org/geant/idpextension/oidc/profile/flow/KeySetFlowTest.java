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
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.webflow.executor.FlowExecutionResult;
import org.testng.Assert;
import org.testng.annotations.Test;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Response;

/**
 * Unit tests for the OIDC keyset flow.
 */
public class KeySetFlowTest extends AbstractOidcFlowTest {

    public static final String FLOW_ID = "oidc/keyset";
    
    Resource rsaSigKey = new FileSystemResource("src/test/resources/credentials/idp-signing-rs.jwk");
    Resource rsaEncKey = new FileSystemResource("src/test/resources/credentials/idp-encryption-rsa.jwk");
    Resource ecSigKey = new FileSystemResource("src/test/resources/credentials/idp-signing-es.jwk");

    public KeySetFlowTest() {
        super(FLOW_ID);
    }
    
    @Test
    public void test() throws ParseException, IOException, java.text.ParseException {
        final FlowExecutionResult result = flowExecutor.launchExecution(FLOW_ID, null, externalContext);
        final Response response = parseResponse(result);
        Assert.assertTrue(response.indicatesSuccess());
        final JWKSet jwkSet = JWKSet.parse(response.toHTTPResponse().getContent());
        final List<JWK> keys = jwkSet.getKeys();
        Assert.assertNotNull(keys);
        Assert.assertEquals(keys.size(), 3);
        final JWK rsaSigJwk = JWK.parse(IOUtils.toString(rsaSigKey.getInputStream(), "UTF-8"));
        Assert.assertTrue(listContainsPublicJwk(keys, rsaSigJwk));
        final JWK rsaEncJwk = JWK.parse(IOUtils.toString(rsaEncKey.getInputStream(), "UTF-8"));
        Assert.assertTrue(listContainsPublicJwk(keys, rsaEncJwk));
        final JWK ecSigJwk = JWK.parse(IOUtils.toString(ecSigKey.getInputStream(), "UTF-8"));
        Assert.assertTrue(listContainsPublicJwk(keys, ecSigJwk));
    }
    
    protected boolean listContainsPublicJwk(final List<JWK> list, final JWK jwk) {
        for (final JWK item : list) {
            Assert.assertEquals(item.toJSONString(), item.toPublicJWK().toJSONString());
            if (jwk.getKeyType().equals(item.getKeyType())
                    && jwk.getKeyUse().equals(item.getKeyUse())
                    && jwk.getKeyID().equals(item.getKeyID())) {
                if (jwk.getKeyType().equals(KeyType.EC)) {
                    Assert.assertNull(item.toJSONObject().get("d"));
                    if (jsonValueEquals(jwk, item, "crv")
                            && jsonValueEquals(jwk, item, "x")
                            && jsonValueEquals(jwk, item, "y")) {
                        return true;
                    }
                } else if (jwk.getKeyType().equals(KeyType.RSA)) {
                    Assert.assertNull(item.toJSONObject().get("d"));
                    if (jsonValueEquals(jwk, item, "e")
                            && jsonValueEquals(jwk, item, "n")) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
    
    protected boolean jsonValueEquals(final JWK first, final JWK another, final String key) {
        return first.toJSONObject().getAsString(key).equals(another.toJSONObject().getAsString(key));
    }
}
