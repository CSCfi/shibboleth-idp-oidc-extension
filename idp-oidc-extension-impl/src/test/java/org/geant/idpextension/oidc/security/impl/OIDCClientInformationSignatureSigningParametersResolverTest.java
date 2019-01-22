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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;

import org.geant.idpextension.oidc.criterion.ClientInformationCriterion;
import org.geant.idpextension.oidc.security.impl.OIDCClientInformationSignatureSigningParametersResolver.ParameterType;
import org.geant.security.jwk.BasicJWKCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.SignatureSigningConfiguration;
import org.opensaml.xmlsec.criterion.SignatureSigningConfigurationCriterion;
import org.opensaml.xmlsec.keyinfo.NamedKeyInfoGeneratorManager;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * Tests for {@link OIDCClientInformationSignatureSigningParametersResolver}.
 */
public class OIDCClientInformationSignatureSigningParametersResolverTest {

    private OIDCClientInformationSignatureSigningParametersResolver resolver;

    private CriteriaSet criteria;

    private OIDCClientMetadata metaData;

    @BeforeMethod
    protected void setUp() throws Exception {
        resolver = new OIDCClientInformationSignatureSigningParametersResolver();
        // Signing configuration
        List<SignatureSigningConfiguration> configs = new ArrayList<SignatureSigningConfiguration>();
        configs.add(new MockSigningConfiguration());
        criteria = new CriteriaSet(new SignatureSigningConfigurationCriterion(configs));
        metaData = new OIDCClientMetadata();
        metaData.setIDTokenJWSAlg(JWSAlgorithm.RS256);
        metaData.setUserInfoJWSAlg(JWSAlgorithm.ES256);
        metaData.setRequestObjectJWSAlg(JWSAlgorithm.ES256);
        JWKSet jwkSet = JWKSet.parse("{\n" + 
                "  \"keys\": [\n" + 
                "    {\n" + 
                "      \"kty\": \"EC\",\n" + 
                "      \"d\": \"MeEUizlBfHEfftMzSUYmtltJr87NUn2WZqxKDVPMlxM\",\n" + 
                "      \"crv\": \"P-256\",\n" + 
                "      \"x\": \"psUf_1U4lV0u2zSRjVepDMyLV4JeLoWNcz3F3C91z4Y\",\n" + 
                "      \"y\": \"z29JaoRl_1wgGPEKq7-5qvts9vbEwA7hk5Vg01h8ESc\"\n" + 
                "    }\n" + 
                "  ]\n" + 
                "}");
        metaData.setJWKSet(jwkSet);
        OIDCClientInformation clientInformation =
                new OIDCClientInformation(new ClientID(), new Date(), metaData, new Secret("abcdefgh"));
        criteria.add(new ClientInformationCriterion(clientInformation));
    }

    @Test
    public void testIdTokenParameters() throws ResolverException {
        Assert.assertEquals("RS256", resolver.resolveSingle(criteria).getSignatureAlgorithm());
        Assert.assertTrue(
                resolver.resolveSingle(criteria).getSigningCredential().getPrivateKey() instanceof RSAPrivateKey);
    }

    @Test
    public void testDefaultIdTokenParameters() throws ResolverException {
        metaData.setIDTokenJWSAlg(null);
        Assert.assertEquals("RS256", resolver.resolveSingle(criteria).getSignatureAlgorithm());
        Assert.assertTrue(
                resolver.resolveSingle(criteria).getSigningCredential().getPrivateKey() instanceof RSAPrivateKey);
    }

    @Test
    public void testIdTokenParametersHS() throws ResolverException {
        metaData.setIDTokenJWSAlg(JWSAlgorithm.HS256);
        Assert.assertEquals("HS256", resolver.resolveSingle(criteria).getSignatureAlgorithm());
        Assert.assertNotNull(resolver.resolveSingle(criteria).getSigningCredential().getSecretKey());
    }

    @Test
    public void testUserInfoParameters() throws ResolverException {
        resolver.setParameterType(ParameterType.USERINFO_SIGNING);
        Assert.assertEquals("ES256", resolver.resolveSingle(criteria).getSignatureAlgorithm());
        Assert.assertTrue(
                resolver.resolveSingle(criteria).getSigningCredential().getPrivateKey() instanceof ECPrivateKey);
    }

    @Test
    public void testRequestObjectParameters() throws ResolverException {
        resolver.setParameterType(ParameterType.REQUEST_OBJECT_VALIDATION);
        Assert.assertEquals("ES256", resolver.resolveSingle(criteria).getSignatureAlgorithm());
        Assert.assertTrue(
                resolver.resolveSingle(criteria).getSigningCredential().getPublicKey() instanceof ECPublicKey);
    }

    public class MockSigningConfiguration implements SignatureSigningConfiguration {

        private List<Credential> credentials;

        private void initializeCredentials() throws NoSuchAlgorithmException {
            credentials = new ArrayList<Credential>();
            // RSA
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.genKeyPair();
            BasicJWKCredential credential = new BasicJWKCredential();
            credential.setUsageType(UsageType.SIGNING);
            credential.setPrivateKey(keyPair.getPrivate());
            credentials.add(credential);
            // EC
            keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(256);
            keyPair = keyGen.genKeyPair();
            credential = new BasicJWKCredential();
            credential.setUsageType(UsageType.SIGNING);
            credential.setPrivateKey(keyPair.getPrivate());
            credentials.add(credential);
        }

        @Override
        public Collection<String> getWhitelistedAlgorithms() {
            return new HashSet<String>();
        }

        @Override
        public boolean isWhitelistMerge() {
            return false;
        }

        @Override
        public Collection<String> getBlacklistedAlgorithms() {
            return new HashSet<String>();
        }

        @Override
        public boolean isBlacklistMerge() {
            return false;
        }

        @Override
        public Precedence getWhitelistBlacklistPrecedence() {
            return null;
        }

        @Override
        public List<Credential> getSigningCredentials() {
            if (credentials == null) {
                try {
                    initializeCredentials();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
            }
            return credentials;
        }

        @Override
        public List<String> getSignatureAlgorithms() {
            return Arrays.asList("RS256", "ES256", "HS256", "RS384", "ES384", "HS384");
        }

        @Override
        public List<String> getSignatureReferenceDigestMethods() {
            return new ArrayList<String>();
        }

        @Override
        public String getSignatureReferenceCanonicalizationAlgorithm() {
            return null;
        }

        @Override
        public String getSignatureCanonicalizationAlgorithm() {
            return null;
        }

        @Override
        public Integer getSignatureHMACOutputLength() {
            return null;
        }

        @Override
        public NamedKeyInfoGeneratorManager getKeyInfoGeneratorManager() {
            return null;
        }

    }

}