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

package org.geant.idpextension.oidc.profile.impl;

import java.util.Arrays;
import java.util.List;

import org.geant.idpextension.oidc.crypto.support.EncryptionConstants;
import org.geant.idpextension.oidc.crypto.support.KeyManagementConstants;
import org.geant.idpextension.oidc.crypto.support.SignatureConstants;
import org.opensaml.profile.action.EventIds;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

/**
 * Unit tests for {@link AddRequestObjectSecurityConfigurationToClientMetadata}.
 */
public class AddRequestObjectSecurityConfigurationToClientMetadataTest extends BaseOIDCClientMetadataPopulationTest {

    AddRequestObjectSecurityConfigurationToClientMetadata action;

    @BeforeMethod
    public void setUp() throws ComponentInitializationException {
        action = new AddRequestObjectSecurityConfigurationToClientMetadata();
        action.initialize();
    }

    @Override
    protected AddRequestObjectSecurityConfigurationToClientMetadata constructAction() {
        return new AddRequestObjectSecurityConfigurationToClientMetadata();
    }

    protected void setUpContext(final OIDCClientMetadata input, final OIDCClientMetadata output,
            final List<String> signingAlgs, final List<String> encryptionAlgs, final List<String> encryptionEncs) throws ComponentInitializationException {
        super.setUpContext(input, output);
        AddSecurityConfigurationToClientMetadataTest.initializeRpCtx(profileRequestCtx, signingAlgs, encryptionAlgs, encryptionEncs);
    }

    @Test
    public void testEmptySignatureAlgorithmsListWithoutRequest() throws ComponentInitializationException {
        OIDCClientMetadata input = new OIDCClientMetadata();
        OIDCClientMetadata output = new OIDCClientMetadata();
        setUpContext(input, output);
        Assert.assertNull(action.execute(requestCtx));
        Assert.assertNull(output.getRequestObjectJWSAlg());
    }

    @Test
    public void testSignatureAlgorithmsListWithRS256Request() throws ComponentInitializationException {
        OIDCClientMetadata input = new OIDCClientMetadata();
        input.setRequestObjectJWSAlg(JWSAlgorithm.RS256);
        OIDCClientMetadata output = new OIDCClientMetadata();
        setUpContext(input, output, Arrays.asList(SignatureConstants.ALGO_ID_SIGNATURE_RS_256), null, null);
        Assert.assertNull(action.execute(requestCtx));
        Assert.assertEquals(output.getRequestObjectJWSAlg(), JWSAlgorithm.RS256);
    }

    @Test
    public void testSignatureAlgorithmsListWithES512Request() throws ComponentInitializationException {
        OIDCClientMetadata input = new OIDCClientMetadata();
        input.setRequestObjectJWSAlg(JWSAlgorithm.ES512);
        OIDCClientMetadata output = new OIDCClientMetadata();
        setUpContext(input, output, Arrays.asList(SignatureConstants.ALGO_ID_SIGNATURE_RS_256,
                SignatureConstants.ALGO_ID_SIGNATURE_ES_512), null, null);
        Assert.assertNull(action.execute(requestCtx));
        Assert.assertEquals(output.getRequestObjectJWSAlg(), JWSAlgorithm.ES512);
    }
    
    @Test
    public void testInvalidEncryptionConfig() throws ComponentInitializationException {
        OIDCClientMetadata input = new OIDCClientMetadata();
        input.setRequestObjectJWEAlg(null);
        input.setRequestObjectJWEEnc(EncryptionMethod.A128CBC_HS256);
        OIDCClientMetadata output = new OIDCClientMetadata();
        setUpContext(input, output, Arrays.asList(SignatureConstants.ALGO_ID_SIGNATURE_RS_256), null, null);
        ActionTestingSupport.assertEvent(action.execute(requestCtx), EventIds.INVALID_MESSAGE);
    }

    @Test
    public void testUnsupportedKeyTransportEncryptionConfig() throws ComponentInitializationException {
        OIDCClientMetadata input = new OIDCClientMetadata();
        input.setRequestObjectJWEAlg(new JWEAlgorithm(KeyManagementConstants.ALGO_ID_ALG_RSA_1_5));
        input.setRequestObjectJWEEnc(EncryptionMethod.A256CBC_HS512);
        OIDCClientMetadata output = new OIDCClientMetadata();
        setUpContext(input, output, Arrays.asList(SignatureConstants.ALGO_ID_SIGNATURE_RS_256), Arrays.asList(KeyManagementConstants.ALGO_ID_ALG_RSA_1_5), Arrays.asList(EncryptionConstants.ALGO_ID_ENC_ALG_A128CBC_HS256));
        ActionTestingSupport.assertEvent(action.execute(requestCtx), EventIds.INVALID_MESSAGE);
    }

    @Test
    public void testUnsupportedEncryptionConfig() throws ComponentInitializationException {
        OIDCClientMetadata input = new OIDCClientMetadata();
        input.setRequestObjectJWEAlg(new JWEAlgorithm(KeyManagementConstants.ALGO_ID_ALG_AES_128_GCM_KW));
        input.setRequestObjectJWEEnc(EncryptionMethod.A128CBC_HS256);
        OIDCClientMetadata output = new OIDCClientMetadata();
        setUpContext(input, output, Arrays.asList(SignatureConstants.ALGO_ID_SIGNATURE_RS_256), Arrays.asList(KeyManagementConstants.ALGO_ID_ALG_RSA_1_5), Arrays.asList(EncryptionConstants.ALGO_ID_ENC_ALG_A128CBC_HS256));
        ActionTestingSupport.assertEvent(action.execute(requestCtx), EventIds.INVALID_MESSAGE);
    }

    @Test
    public void testValidEncryptionConfig() throws ComponentInitializationException {
        OIDCClientMetadata input = new OIDCClientMetadata();
        input.setRequestObjectJWEAlg(new JWEAlgorithm(KeyManagementConstants.ALGO_ID_ALG_RSA_1_5));
        input.setRequestObjectJWEEnc(EncryptionMethod.A128CBC_HS256);
        OIDCClientMetadata output = new OIDCClientMetadata();
        setUpContext(input, output, Arrays.asList(SignatureConstants.ALGO_ID_SIGNATURE_RS_256), Arrays.asList(KeyManagementConstants.ALGO_ID_ALG_RSA_1_5), Arrays.asList(EncryptionConstants.ALGO_ID_ENC_ALG_A128CBC_HS256));
        Assert.assertNull(action.execute(requestCtx));
        Assert.assertEquals(output.getRequestObjectJWEAlg(), new JWEAlgorithm(KeyManagementConstants.ALGO_ID_ALG_RSA_1_5));
        Assert.assertEquals(output.getRequestObjectJWEEnc(), EncryptionMethod.A128CBC_HS256);
    }

}
