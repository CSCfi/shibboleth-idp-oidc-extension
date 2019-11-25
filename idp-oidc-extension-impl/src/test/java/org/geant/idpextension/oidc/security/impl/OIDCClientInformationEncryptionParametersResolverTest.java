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

/** Unit tests for {@link OAuth2TokenRevocationConfiguration}. */

package org.geant.idpextension.oidc.security.impl;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.geant.idpextension.oidc.criterion.ClientInformationCriterion;
import org.geant.idpextension.oidc.profile.spring.factory.BasicJWKCredentialFactoryBean;
import org.geant.idpextension.oidc.security.impl.OIDCClientInformationEncryptionParametersResolver.ParameterType;
import org.mockito.Mockito;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.EncryptionParameters;
import org.opensaml.xmlsec.criterion.EncryptionConfigurationCriterion;
import org.springframework.core.io.ClassPathResource;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * Tests for {@link OIDCClientInformationEncryptionParametersResolver}.
 */
public class OIDCClientInformationEncryptionParametersResolverTest {

    private OIDCClientInformationEncryptionParametersResolver resolver;

    private CriteriaSet criteria;

    private OIDCClientMetadata metaData;

    @BeforeMethod
    protected void setUp() throws Exception {
        resolver = new OIDCClientInformationEncryptionParametersResolver();
        // Encryption configuration
        List<EncryptionConfiguration> configs = new ArrayList<EncryptionConfiguration>();
        EncryptionConfiguration encConfig = Mockito.mock(EncryptionConfiguration.class);
        Mockito.when(encConfig.getDataEncryptionAlgorithms()).thenReturn(
                Arrays.asList("A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM", "A192GCM", "A256GCM"));
        Mockito.when(encConfig.getKeyTransportEncryptionAlgorithms()).thenReturn(
                Arrays.asList("ECDH-ES", "RSA1_5", "RSA-OAEP", "RSA-OAEP-256", "A128GCMKW", "A192GCMKW", "A256GCMKW"));
        List<Credential> encCreds = new ArrayList<Credential>();
        BasicJWKCredentialFactoryBean factory = new BasicJWKCredentialFactoryBean();
        factory.setJWKResource(new ClassPathResource("credentials/idp-encryption-rsa.jwk"));
        factory.afterPropertiesSet();
        encCreds.add(factory.getObject());
        Mockito.when(encConfig.getKeyTransportEncryptionCredentials()).thenReturn(encCreds);
        configs.add(encConfig);
        criteria = new CriteriaSet(new EncryptionConfigurationCriterion(configs));
        metaData = new OIDCClientMetadata();
        metaData.setIDTokenJWEAlg(JWEAlgorithm.RSA_OAEP_256);
        metaData.setIDTokenJWEEnc(EncryptionMethod.A192CBC_HS384);
        metaData.setUserInfoJWEAlg(JWEAlgorithm.A128GCMKW);
        metaData.setUserInfoJWEEnc(EncryptionMethod.A128GCM);
        metaData.setRequestObjectJWEAlg(JWEAlgorithm.RSA_OAEP_256);
        metaData.setRequestObjectJWEEnc(EncryptionMethod.A192GCM);
        JWKSet jwkSet = JWKSet.parse("{\n" + "  \"keys\": [\n" + "    {\n" + "      \"kty\": \"EC\",\n"
                + "      \"d\": \"MeEUizlBfHEfftMzSUYmtltJr87NUn2WZqxKDVPMlxM\",\n" + "      \"crv\": \"P-256\",\n"
                + "      \"x\": \"psUf_1U4lV0u2zSRjVepDMyLV4JeLoWNcz3F3C91z4Y\",\n"
                + "      \"y\": \"z29JaoRl_1wgGPEKq7-5qvts9vbEwA7hk5Vg01h8ESc\"\n" + "    },\n" + "    {\n"
                + "      \"kty\": \"RSA\",\n"
                + "      \"d\": \"RBl-MjdugxTrjVbbWSeArOV7HUiZPX5LWmyB9p3P1OLSSYjK9A42KYPsdcLpa78Den5_fcpLv-1pm8161ATE9Y_O2aIkeg0_IRlM-FLo-KHvtGkEuHcbERPGhrvmsyMsqkVGADhEwvcGsWZ9PZSHo8OK8EsHZWmE2kHN_rG_8n9-ymAvdsHHv5WhyppHtScLWR1UoIQVbnmcw0cauBy-6SYL2pnweWMeI5UDB6eYyeUyA8BuV-_40K0XqJgJ--6zkNdsSrAMbOejfSyAgK7ezCCP-gmS2P3tBLqwJKjCcoDGFihHj6qLUFNWDY5flp3vA02Z8DQKroeAtIN0_PSBIQ\",\n"
                + "      \"e\": \"AQAB\",\n"
                + "      \"n\": \"xC18p5gfcin62WKas_DlmwUE0ySwmgW51gDQhqucBBSyHMvzRXzRY1cYkox4WCLreC3X8YbNgAv9fjkagX35aNyafnJxEd3Cipf6-h_tZ8Ky5mtdKrxpJdGW1mom7Ha8nMAFGmElDtQny2U8pzDUAUvOcOjiI-JRd6WH3wyQtpCtG6YYxhS9SvnvDaNlYN_afPgFdTHt5yn-q854bjF6uG-uZt3J7jf7P6dvqVizDVO9xtCHrjeet4v62yscMZXYi110aMJdtA4nxKGUi9RWCnBoLVRMBei5ZqmsLCozT5KpfVNkjVzZU3vYBKdGw49pIgRqQP-Jx8Sg7JFaaXMBsQ\"\n"
                + "    }" + "  ]\n" + "}");
        metaData.setJWKSet(jwkSet);
        OIDCClientInformation clientInformation =
                new OIDCClientInformation(new ClientID(), new Date(), metaData, new Secret("abcdefgh"));
        criteria.add(new ClientInformationCriterion(clientInformation));
    }

    @Test
    public void testIdTokenParameters() throws ResolverException {
        EncryptionParameters params = resolver.resolveSingle(criteria);
        Assert.assertEquals("RSA-OAEP-256", params.getKeyTransportEncryptionAlgorithm());
        Assert.assertEquals("A192CBC-HS384", params.getDataEncryptionAlgorithm());
        Assert.assertNotNull(params.getKeyTransportEncryptionCredential().getPublicKey());
    }

    @Test
    public void testIdTokenParametersDefaultEnc() throws ResolverException {
        metaData.setIDTokenJWEEnc(null);
        EncryptionParameters params = resolver.resolveSingle(criteria);
        Assert.assertEquals("RSA-OAEP-256", params.getKeyTransportEncryptionAlgorithm());
        Assert.assertEquals("A128CBC-HS256", params.getDataEncryptionAlgorithm());
        Assert.assertNotNull(params.getKeyTransportEncryptionCredential().getPublicKey());
    }

    @Test
    public void testUserInfoParameters() throws ResolverException {
        resolver.setParameterType(ParameterType.USERINFO_ENCRYPTION);
        EncryptionParameters params = resolver.resolveSingle(criteria);
        Assert.assertEquals("A128GCMKW", params.getKeyTransportEncryptionAlgorithm());
        Assert.assertEquals("A128GCM", params.getDataEncryptionAlgorithm());
        Assert.assertNotNull(params.getKeyTransportEncryptionCredential().getSecretKey());
    }

    @Test
    public void testRequesrObjectParameters() throws ResolverException {
        resolver.setParameterType(ParameterType.REQUEST_OBJECT_DECRYPTION);
        EncryptionParameters params = resolver.resolveSingle(criteria);
        Assert.assertEquals("RSA-OAEP-256", params.getKeyTransportEncryptionAlgorithm());
        Assert.assertEquals("A192GCM", params.getDataEncryptionAlgorithm());
        Assert.assertNotNull(
                ((OIDCDecryptionParameters) params).getKeyTransportDecryptionCredentials().get(0).getPrivateKey());
    }
}