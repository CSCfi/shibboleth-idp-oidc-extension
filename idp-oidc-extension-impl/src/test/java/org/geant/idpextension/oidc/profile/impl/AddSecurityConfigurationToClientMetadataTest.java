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
import org.mockito.Mockito;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.SignatureSigningConfiguration;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.idp.profile.config.ProfileConfiguration;
import net.shibboleth.idp.profile.config.SecurityConfiguration;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

/**
 * Unit tests for {@link AddSecurityConfigurationToClientMetadata}.
 */
public class AddSecurityConfigurationToClientMetadataTest extends BaseOIDCClientMetadataPopulationTest {

    AddSecurityConfigurationToClientMetadata action;

    @BeforeMethod
    public void setUp() throws ComponentInitializationException {
        action = new AddSecurityConfigurationToClientMetadata();
        action.initialize();
    }

    @Override
    protected AbstractOIDCClientMetadataPopulationAction constructAction() {
        return new AddSecurityConfigurationToClientMetadata();
    }

    protected static void initializeRpCtx(final ProfileRequestContext profileRequestCtx, final List<String> signingAlgs,
            final List<String> encyrptionAlgs, final List<String> encryptionEncs) {
        final RelyingPartyContext rpCtx = profileRequestCtx.getSubcontext(RelyingPartyContext.class);
        final ProfileConfiguration profileConfig = Mockito.mock(ProfileConfiguration.class);
        final SecurityConfiguration secConfig = Mockito.mock(SecurityConfiguration.class);
        final SignatureSigningConfiguration signingConfig = Mockito.mock(SignatureSigningConfiguration.class);
        Mockito.when(signingConfig.getSignatureAlgorithms()).thenReturn(signingAlgs);
        Mockito.when(secConfig.getSignatureSigningConfiguration()).thenReturn(signingConfig);
        final EncryptionConfiguration encryptionConfig = Mockito.mock(EncryptionConfiguration.class);
        Mockito.when(encryptionConfig.getDataEncryptionAlgorithms()).thenReturn(encryptionEncs);
        Mockito.when(encryptionConfig.getKeyTransportEncryptionAlgorithms()).thenReturn(encyrptionAlgs);
        Mockito.when(secConfig.getEncryptionConfiguration()).thenReturn(encryptionConfig);
        Mockito.when(profileConfig.getSecurityConfiguration()).thenReturn(secConfig);
        rpCtx.setProfileConfig(profileConfig);
    }

    protected void setUpContext(final OIDCClientMetadata input, final OIDCClientMetadata output,
            final List<String> signingAlgs, final List<String> encryptionAlgs, final List<String> encryptionEncs)
            throws ComponentInitializationException {
        super.setUpContext(input, output);
        initializeRpCtx(profileRequestCtx, signingAlgs, encryptionAlgs, encryptionEncs);
    }

    @Test
    public void testEmptySignatureAlgorithmsListWithoutRequest() throws ComponentInitializationException {
        OIDCClientMetadata input = new OIDCClientMetadata();
        OIDCClientMetadata output = new OIDCClientMetadata();
        setUpContext(input, output);
        ActionTestingSupport.assertEvent(action.execute(requestCtx), EventIds.INVALID_MESSAGE);
    }

    @Test
    public void testSignatureAlgorithmsListWithEmptyRequest() throws ComponentInitializationException {
        OIDCClientMetadata input = new OIDCClientMetadata();
        OIDCClientMetadata output = new OIDCClientMetadata();
        setUpContext(input, output, Arrays.asList(SignatureConstants.ALGO_ID_SIGNATURE_RS_256), null, null);
        Assert.assertNull(action.execute(requestCtx));
        Assert.assertEquals(output.getIDTokenJWSAlg(), JWSAlgorithm.RS256);
        Assert.assertNull(output.getIDTokenJWEEnc());
        Assert.assertNull(output.getIDTokenJWEAlg());
    }

    @Test
    public void testIDTokenSignatureAlgorithmsListWithRS256Request() throws ComponentInitializationException {
        OIDCClientMetadata input = new OIDCClientMetadata();
        input.setIDTokenJWSAlg(JWSAlgorithm.RS256);
        OIDCClientMetadata output = new OIDCClientMetadata();
        setUpContext(input, output, Arrays.asList(SignatureConstants.ALGO_ID_SIGNATURE_RS_256), null, null);
        Assert.assertNull(action.execute(requestCtx));
        Assert.assertEquals(output.getIDTokenJWSAlg(), JWSAlgorithm.RS256);
        Assert.assertNull(output.getIDTokenJWEEnc());
        Assert.assertNull(output.getIDTokenJWEAlg());
    }

    @Test
    public void testIDTokenSignatureAlgorithmsListWithES512Request() throws ComponentInitializationException {
        OIDCClientMetadata input = new OIDCClientMetadata();
        input.setIDTokenJWSAlg(JWSAlgorithm.ES512);
        OIDCClientMetadata output = new OIDCClientMetadata();
        setUpContext(input, output,
                Arrays.asList(SignatureConstants.ALGO_ID_SIGNATURE_RS_256, SignatureConstants.ALGO_ID_SIGNATURE_ES_512),
                null, null);
        Assert.assertNull(action.execute(requestCtx));
        Assert.assertEquals(output.getIDTokenJWSAlg(), JWSAlgorithm.ES512);
        Assert.assertNull(output.getIDTokenJWEEnc());
        Assert.assertNull(output.getIDTokenJWEAlg());
    }

    @Test
    public void testIDTokenInvalidEncryptionConfig() throws ComponentInitializationException {
        OIDCClientMetadata input = new OIDCClientMetadata();
        input.setIDTokenJWEAlg(null);
        input.setIDTokenJWEEnc(EncryptionMethod.A128CBC_HS256);
        OIDCClientMetadata output = new OIDCClientMetadata();
        setUpContext(input, output, Arrays.asList(SignatureConstants.ALGO_ID_SIGNATURE_RS_256), null, null);
        ActionTestingSupport.assertEvent(action.execute(requestCtx), EventIds.INVALID_MESSAGE);
    }

    @Test
    public void testIDTokenUnsupportedKeyTransportEncryptionConfig() throws ComponentInitializationException {
        OIDCClientMetadata input = new OIDCClientMetadata();
        input.setIDTokenJWEAlg(new JWEAlgorithm(KeyManagementConstants.ALGO_ID_ALG_RSA_1_5));
        input.setIDTokenJWEEnc(EncryptionMethod.A256CBC_HS512);
        OIDCClientMetadata output = new OIDCClientMetadata();
        setUpContext(input, output, Arrays.asList(SignatureConstants.ALGO_ID_SIGNATURE_RS_256),
                Arrays.asList(KeyManagementConstants.ALGO_ID_ALG_RSA_1_5),
                Arrays.asList(EncryptionConstants.ALGO_ID_ENC_ALG_A128CBC_HS256));
        ActionTestingSupport.assertEvent(action.execute(requestCtx), EventIds.INVALID_MESSAGE);
    }

    @Test
    public void testIDTokenUnsupportedEncryptionConfig() throws ComponentInitializationException {
        OIDCClientMetadata input = new OIDCClientMetadata();
        input.setIDTokenJWEAlg(new JWEAlgorithm(KeyManagementConstants.ALGO_ID_ALG_AES_128_GCM_KW));
        input.setIDTokenJWEEnc(EncryptionMethod.A128CBC_HS256);
        OIDCClientMetadata output = new OIDCClientMetadata();
        setUpContext(input, output, Arrays.asList(SignatureConstants.ALGO_ID_SIGNATURE_RS_256),
                Arrays.asList(KeyManagementConstants.ALGO_ID_ALG_RSA_1_5),
                Arrays.asList(EncryptionConstants.ALGO_ID_ENC_ALG_A128CBC_HS256));
        ActionTestingSupport.assertEvent(action.execute(requestCtx), EventIds.INVALID_MESSAGE);
    }

    @Test
    public void testIDTokenValidEncryptionConfig() throws ComponentInitializationException {
        OIDCClientMetadata input = new OIDCClientMetadata();
        input.setIDTokenJWEAlg(new JWEAlgorithm(KeyManagementConstants.ALGO_ID_ALG_RSA_1_5));
        input.setIDTokenJWEEnc(EncryptionMethod.A128CBC_HS256);
        OIDCClientMetadata output = new OIDCClientMetadata();
        setUpContext(input, output, Arrays.asList(SignatureConstants.ALGO_ID_SIGNATURE_RS_256),
                Arrays.asList(KeyManagementConstants.ALGO_ID_ALG_RSA_1_5),
                Arrays.asList(EncryptionConstants.ALGO_ID_ENC_ALG_A128CBC_HS256));
        Assert.assertNull(action.execute(requestCtx));
        Assert.assertEquals(output.getIDTokenJWSAlg(), JWSAlgorithm.RS256);
        Assert.assertEquals(output.getIDTokenJWEAlg(),
                new JWEAlgorithm(KeyManagementConstants.ALGO_ID_ALG_RSA_1_5));
        Assert.assertEquals(output.getIDTokenJWEEnc(), EncryptionMethod.A128CBC_HS256);

    }

    @Test
    public void testUserInfoSignatureAlgorithmsListWithRS256Request() throws ComponentInitializationException {
        OIDCClientMetadata input = new OIDCClientMetadata();
        input.setUserInfoJWSAlg(JWSAlgorithm.RS256);
        OIDCClientMetadata output = new OIDCClientMetadata();
        setUpContext(input, output, Arrays.asList(SignatureConstants.ALGO_ID_SIGNATURE_RS_256), null, null);
        Assert.assertNull(action.execute(requestCtx));
        Assert.assertEquals(output.getUserInfoJWSAlg(), JWSAlgorithm.RS256);
        Assert.assertNull(output.getUserInfoJWEEnc());
        Assert.assertNull(output.getUserInfoJWEAlg());
    }

    @Test
    public void testUserInfoSignatureAlgorithmsListWithES512Request() throws ComponentInitializationException {
        OIDCClientMetadata input = new OIDCClientMetadata();
        input.setUserInfoJWSAlg(JWSAlgorithm.ES512);
        OIDCClientMetadata output = new OIDCClientMetadata();
        setUpContext(input, output,
                Arrays.asList(SignatureConstants.ALGO_ID_SIGNATURE_RS_256, SignatureConstants.ALGO_ID_SIGNATURE_ES_512),
                null, null);
        Assert.assertNull(action.execute(requestCtx));
        Assert.assertEquals(output.getUserInfoJWSAlg(), JWSAlgorithm.ES512);
        Assert.assertNull(output.getUserInfoJWEEnc());
        Assert.assertNull(output.getUserInfoJWEAlg());
    }

    @Test
    public void testUserInfoInvalidEncryptionConfig() throws ComponentInitializationException {
        OIDCClientMetadata input = new OIDCClientMetadata();
        input.setUserInfoJWEAlg(null);
        input.setUserInfoJWEEnc(EncryptionMethod.A128CBC_HS256);
        OIDCClientMetadata output = new OIDCClientMetadata();
        setUpContext(input, output, Arrays.asList(SignatureConstants.ALGO_ID_SIGNATURE_RS_256), null, null);
        ActionTestingSupport.assertEvent(action.execute(requestCtx), EventIds.INVALID_MESSAGE);
    }

    @Test
    public void testUserInfoUnsupportedKeyTransportEncryptionConfig() throws ComponentInitializationException {
        OIDCClientMetadata input = new OIDCClientMetadata();
        input.setUserInfoJWEAlg(new JWEAlgorithm(KeyManagementConstants.ALGO_ID_ALG_RSA_1_5));
        input.setUserInfoJWEEnc(EncryptionMethod.A256CBC_HS512);
        OIDCClientMetadata output = new OIDCClientMetadata();
        setUpContext(input, output, Arrays.asList(SignatureConstants.ALGO_ID_SIGNATURE_RS_256),
                Arrays.asList(KeyManagementConstants.ALGO_ID_ALG_RSA_1_5),
                Arrays.asList(EncryptionConstants.ALGO_ID_ENC_ALG_A128CBC_HS256));
        ActionTestingSupport.assertEvent(action.execute(requestCtx), EventIds.INVALID_MESSAGE);
    }

    @Test
    public void testUserInfoUnsupportedEncryptionConfig() throws ComponentInitializationException {
        OIDCClientMetadata input = new OIDCClientMetadata();
        input.setUserInfoJWEAlg(new JWEAlgorithm(KeyManagementConstants.ALGO_ID_ALG_AES_128_GCM_KW));
        input.setUserInfoJWEEnc(EncryptionMethod.A128CBC_HS256);
        OIDCClientMetadata output = new OIDCClientMetadata();
        setUpContext(input, output, Arrays.asList(SignatureConstants.ALGO_ID_SIGNATURE_RS_256),
                Arrays.asList(KeyManagementConstants.ALGO_ID_ALG_RSA_1_5),
                Arrays.asList(EncryptionConstants.ALGO_ID_ENC_ALG_A128CBC_HS256));
        ActionTestingSupport.assertEvent(action.execute(requestCtx), EventIds.INVALID_MESSAGE);
    }

    @Test
    public void testUserInfoValidEncryptionConfig() throws ComponentInitializationException {
        OIDCClientMetadata input = new OIDCClientMetadata();
        input.setUserInfoJWEAlg(new JWEAlgorithm(KeyManagementConstants.ALGO_ID_ALG_RSA_1_5));
        input.setUserInfoJWEEnc(EncryptionMethod.A128CBC_HS256);
        OIDCClientMetadata output = new OIDCClientMetadata();
        setUpContext(input, output, Arrays.asList(SignatureConstants.ALGO_ID_SIGNATURE_RS_256),
                Arrays.asList(KeyManagementConstants.ALGO_ID_ALG_RSA_1_5),
                Arrays.asList(EncryptionConstants.ALGO_ID_ENC_ALG_A128CBC_HS256));
        Assert.assertNull(action.execute(requestCtx));
        Assert.assertEquals(output.getUserInfoJWEAlg(),
                new JWEAlgorithm(KeyManagementConstants.ALGO_ID_ALG_RSA_1_5));
        Assert.assertEquals(output.getUserInfoJWEEnc(), EncryptionMethod.A128CBC_HS256);

    }
}
