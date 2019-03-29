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

/** Unit tests for {@link OAuth2TokenRevocationConfiguration}. */

package org.geant.idpextension.oidc.security.impl;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.geant.idpextension.oidc.criterion.ClientInformationCriterion;
import org.geant.idpextension.oidc.security.impl.OIDCClientInformationSignatureValidationParametersResolver.ParameterType;
import org.mockito.Mockito;
import org.opensaml.xmlsec.SignatureSigningConfiguration;
import org.opensaml.xmlsec.criterion.SignatureSigningConfigurationCriterion;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * Tests for {@link OIDCClientInformationSignatureValidationParametersResolver}.
 */
public class OIDCClientInformationSignatureValidationParametersResolverTest {

    private OIDCClientInformationSignatureValidationParametersResolver resolver;

    private CriteriaSet criteria;

    private OIDCClientMetadata metaData;

    @BeforeMethod
    protected void setUp() throws Exception {
        resolver = new OIDCClientInformationSignatureValidationParametersResolver();
        // Signing configuration
        List<SignatureSigningConfiguration> configs = new ArrayList<SignatureSigningConfiguration>();
        SignatureSigningConfiguration signConfig = Mockito.mock(SignatureSigningConfiguration.class);
        Mockito.when(signConfig.getSignatureAlgorithms())
                .thenReturn(Arrays.asList("RS256", "HS256", "HS384", "HS512", "ES256", "ES384", "ES512"));
        configs.add(signConfig);
        criteria = new CriteriaSet(new SignatureSigningConfigurationCriterion(configs));
        metaData = new OIDCClientMetadata();
        metaData.setRequestObjectJWSAlg(JWSAlgorithm.ES256);
        metaData.setTokenEndpointAuthJWSAlg(JWSAlgorithm.ES256);
        JWKSet jwkSet = JWKSet.parse("{\n" + "   \"keys\":[\n" + "      {\n" + "         \"kty\":\"RSA\",\n"
                + "         \"e\":\"AQAB\",\n" + "         \"use\":\"enc\",\n"
                + "         \"kid\":\"testkeyRSAEncryption\",\n"
                + "         \"n\":\"47mkdLGrenv7QFkAWv1JryydVjq8HsEVCKz-qRttVe2II1-lQc-4sObf-9X0LtAwdtK0g1_EpRzZNuGaK2nFISr9uZQQ5evNHETgUKE2oKJs3r0wnfgvEZVHV6wXg4B7NRmDBgphExIYndBt__L-tC9_S_isaJOXQ_PAx17621pmxdyg8WEnJx9Azc23vH-Cii0ttMxDLNqUTu-tdgtZ8eo0IX7VPBWAnXVi0bRKHJuuvzJ4B8QqwsZsj8hGrwqNkRMoJVEiz-5M6ACLo-rgGNjtCBJRaezolrHSCc-r-hZbAaBKq0dOPRNPcMtRm8TUdmuRKBY7rXaFi7zGV7XDdw\"\n"
                + "      },\n" + "      {\n" + "         \"kty\":\"RSA\",\n" + "         \"e\":\"AQAB\",\n"
                + "         \"use\":\"sig\",\n" + "         \"kid\":\"testkeyRS\",\n"
                + "         \"n\":\"pNf03ghVzMAw5sWrwDAMAZdSYNY2q7OVlxMInljMgz8XB5mf8XKH3EtP7AKrb8IAf7rGhfuH3T1N1C7F-jwIeYjXxMm2nIAZ0hXApgbccvBpf4n2H7IZflMjt4A3tt587QQSxQ069drCP4sYevxhTcLplJy6RWA0cLj-5CHyWy94zPeeA4GRd6xgHFLz0RNiSF0pF0kE4rmRgQVZ-b4_BmD9SsWnIpwhms5Ihciw36WyAGQUeZqULGsfwAMwlNLIaTCBLAoRgv370p-XsLrgz86pTkNBJqXP5GwI-ZfgiLmJuHjQ9l85KqHM87f-QdsqiV8KoRcslgXPqb6VOTJBVw\"\n"
                + "      },\n" + "      {\n" + "         \"kty\":\"EC\",\n" + "         \"use\":\"sig\",\n"
                + "         \"crv\":\"P-256\",\n" + "         \"kid\":\"testkeyES256\",\n"
                + "         \"x\":\"2uzfE1oK0cf1_c11SFc9vFdGLnJoH3e0AKTrGPAmUis\",\n"
                + "         \"y\":\"14410NGKqwLM58b26ZcvGOruFixpHt_SJTw8I5wwgLQ\"\n" + "      },\n" + "      {\n"
                + "         \"kty\":\"EC\",\n" + "         \"use\":\"sig\",\n" + "         \"crv\":\"P-384\",\n"
                + "         \"kid\":\"testkeyES384\",\n"
                + "         \"x\":\"-loVdvssxvUq_jCPULEk0cMkF4uvEGfHfbh8az8T9J_er6frv0jhosDLCxoLE7E6\",\n"
                + "         \"y\":\"Er9Blt5x5ADxQXmezf3OEmQbLjjblgB9XwbXXcQyEOQ2qXNv659AgdZiq4UJBnPH\"\n" + "      },\n"
                + "      {\n" + "         \"kty\":\"EC\",\n" + "         \"use\":\"sig\",\n"
                + "         \"crv\":\"P-521\",\n" + "         \"kid\":\"testkeyES512\",\n"
                + "         \"x\":\"AVjIdU6xZBwRdC9yZYyqT583EM3GbxdVyGwinPqeba0EildGZWM1L7HfJXV_r_cOBcuCsEZcuSqFO3v5KRLY5Wj-\",\n"
                + "         \"y\":\"ATeLywfo7kLDEwUCm8ZQFynqH36WXSdQClAz2cZ63tHfjSumm_SfMOfdWEDmdtgkbVDrBXWYqWoYaofigmDZkxok\"\n"
                + "      },\n" + "      {\n" + "         \"kty\":\"EC\",\n" + "         \"crv\":\"P-521\",\n"
                + "         \"kid\":\"testkeyES512-2\",\n"
                + "         \"x\":\"AQL7ZCkzcAyuUdaqYiCSAf2u2MR_l4rqSppQ8lvEEjmjy7ETiPB77BqeH7glJ6xtkK1YhmHxKDKz0E0zdmqWWVYp\",\n"
                + "         \"y\":\"AXI7UFlH-Zy2jEf1XoY3NHblkJDsOK4kiv82fRrKtHAoKM_ud25XNzT3lrfbJ--zZlmWUB7fV2jHR0pbmjOOrEF_\"\n"
                + "      }\n" + "   ]\n" + "}");
        metaData.setJWKSet(jwkSet);
        OIDCClientInformation clientInformation =
                new OIDCClientInformation(new ClientID(), new Date(), metaData, new Secret("abcdefgh"));
        criteria.add(new ClientInformationCriterion(clientInformation));
    }

    @Test
    public void testRequestObjectParameters() throws ResolverException {
        testSigningValidationES256(ParameterType.REQUEST_OBJECT_VALIDATION);
    }

    @Test
    public void testRequestObjectParametersES384() throws ResolverException {
        metaData.setRequestObjectJWSAlg(JWSAlgorithm.ES384);
        testSigningValidationES384(ParameterType.REQUEST_OBJECT_VALIDATION);
    }

    @Test
    public void testRequestObjectParametersES512() throws ResolverException {
        metaData.setRequestObjectJWSAlg(JWSAlgorithm.ES512);
        testSigningValidationES512(ParameterType.REQUEST_OBJECT_VALIDATION);
    }

    @Test
    public void testRequestObjectParametersHS256() throws ResolverException {
        metaData.setRequestObjectJWSAlg(JWSAlgorithm.HS256);
        testSigningValidationHS256(ParameterType.REQUEST_OBJECT_VALIDATION);
    }

    @Test
    public void testRequestObjectParametersHS384() throws ResolverException {
        metaData.setRequestObjectJWSAlg(JWSAlgorithm.HS384);
        testSigningValidationHS384(ParameterType.REQUEST_OBJECT_VALIDATION);
    }

    @Test
    public void testRequestObjectParametersHS512() throws ResolverException {
        metaData.setRequestObjectJWSAlg(JWSAlgorithm.HS512);
        testSigningValidationHS512(ParameterType.REQUEST_OBJECT_VALIDATION);
    }

    @Test
    public void testTokenEndpointJwtParameters() throws ResolverException {
        testSigningValidationES256(ParameterType.TOKEN_ENDPOINT_JWT_VALIDATION);
    }

    @Test
    public void testTokenEndpointJwtParametersES384() throws ResolverException {
        metaData.setTokenEndpointAuthJWSAlg(JWSAlgorithm.ES384);
        testSigningValidationES384(ParameterType.TOKEN_ENDPOINT_JWT_VALIDATION);
    }

    @Test
    public void testTokenEndpointJwtParametersES512() throws ResolverException {
        metaData.setTokenEndpointAuthJWSAlg(JWSAlgorithm.ES512);
        testSigningValidationES512(ParameterType.TOKEN_ENDPOINT_JWT_VALIDATION);
    }

    @Test
    public void testTokenEndpointJwtParametersHS256() throws ResolverException {
        metaData.setTokenEndpointAuthJWSAlg(JWSAlgorithm.HS256);
        testSigningValidationHS256(ParameterType.TOKEN_ENDPOINT_JWT_VALIDATION);
    }

    @Test
    public void testTokenEndpointJwtParametersHS384() throws ResolverException {
        metaData.setTokenEndpointAuthJWSAlg(JWSAlgorithm.HS384);
        testSigningValidationHS384(ParameterType.TOKEN_ENDPOINT_JWT_VALIDATION);
    }

    @Test
    public void testTokenEndpointJwtParametersHS512() throws ResolverException {
        metaData.setTokenEndpointAuthJWSAlg(JWSAlgorithm.HS512);
        testSigningValidationHS512(ParameterType.TOKEN_ENDPOINT_JWT_VALIDATION);
    }

    protected void testSigningValidationHS256(ParameterType parameterType) throws ResolverException {
        resolver.setParameterType(parameterType);
        OIDCSignatureValidationParameters params = (OIDCSignatureValidationParameters) resolver.resolveSingle(criteria);
        Assert.assertEquals(params.getSignatureAlgorithm(), "HS256");
        Assert.assertTrue(params.getValidationCredentials().size() == 1);
        Assert.assertNotNull(params.getValidationCredentials().get(0).getSecretKey());
    }

    protected void testSigningValidationHS384(ParameterType parameterType) throws ResolverException {
        resolver.setParameterType(parameterType);
        OIDCSignatureValidationParameters params = (OIDCSignatureValidationParameters) resolver.resolveSingle(criteria);
        Assert.assertEquals(params.getSignatureAlgorithm(), "HS384");
        Assert.assertTrue(params.getValidationCredentials().size() == 1);
        Assert.assertNotNull(params.getValidationCredentials().get(0).getSecretKey());
    }

    protected void testSigningValidationHS512(ParameterType parameterType) throws ResolverException {
        resolver.setParameterType(parameterType);
        OIDCSignatureValidationParameters params = (OIDCSignatureValidationParameters) resolver.resolveSingle(criteria);
        Assert.assertEquals(params.getSignatureAlgorithm(), "HS512");
        Assert.assertTrue(params.getValidationCredentials().size() == 1);
        Assert.assertNotNull(params.getValidationCredentials().get(0).getSecretKey());
    }

    protected void testSigningValidationES256(ParameterType parameterType) throws ResolverException {
        resolver.setParameterType(parameterType);
        OIDCSignatureValidationParameters params = (OIDCSignatureValidationParameters) resolver.resolveSingle(criteria);
        Assert.assertEquals(params.getSignatureAlgorithm(), "ES256");
        Assert.assertTrue(params.getValidationCredentials().size() == 1);
        Assert.assertEquals(Curve.forECParameterSpec(
                ((java.security.interfaces.ECKey) params.getValidationCredentials().get(0).getPublicKey()).getParams()),
                Curve.P_256);
    }

    protected void testSigningValidationES384(ParameterType parameterType) throws ResolverException {
        resolver.setParameterType(parameterType);
        OIDCSignatureValidationParameters params = (OIDCSignatureValidationParameters) resolver.resolveSingle(criteria);
        Assert.assertEquals(params.getSignatureAlgorithm(), "ES384");
        Assert.assertTrue(params.getValidationCredentials().size() == 1);
        Assert.assertEquals(Curve.forECParameterSpec(
                ((java.security.interfaces.ECKey) params.getValidationCredentials().get(0).getPublicKey()).getParams()),
                Curve.P_384);
    }

    protected void testSigningValidationES512(ParameterType parameterType) throws ResolverException {
        resolver.setParameterType(parameterType);
        OIDCSignatureValidationParameters params = (OIDCSignatureValidationParameters) resolver.resolveSingle(criteria);
        Assert.assertEquals(params.getSignatureAlgorithm(), "ES512");
        Assert.assertTrue(params.getValidationCredentials().size() == 2);
        Assert.assertEquals(Curve.forECParameterSpec(
                ((java.security.interfaces.ECKey) params.getValidationCredentials().get(0).getPublicKey()).getParams()),
                Curve.P_521);
        Assert.assertEquals(Curve.forECParameterSpec(
                ((java.security.interfaces.ECKey) params.getValidationCredentials().get(1).getPublicKey()).getParams()),
                Curve.P_521);
    }
}