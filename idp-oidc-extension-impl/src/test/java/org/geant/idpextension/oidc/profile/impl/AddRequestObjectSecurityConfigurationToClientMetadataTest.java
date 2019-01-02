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
