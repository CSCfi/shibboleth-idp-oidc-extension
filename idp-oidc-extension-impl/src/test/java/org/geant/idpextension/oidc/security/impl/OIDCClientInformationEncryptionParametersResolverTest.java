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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;

import org.geant.idpextension.oidc.criterion.ClientInformationCriterion;
import org.geant.idpextension.oidc.security.impl.OIDCClientInformationEncryptionParametersResolver.ParameterType;
import org.geant.security.jwk.BasicJWKCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.EncryptionParameters;
import org.opensaml.xmlsec.KeyTransportAlgorithmPredicate;
import org.opensaml.xmlsec.criterion.EncryptionConfigurationCriterion;
import org.opensaml.xmlsec.encryption.support.RSAOAEPParameters;
import org.opensaml.xmlsec.keyinfo.NamedKeyInfoGeneratorManager;
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
        configs.add(new MockEncryptionConfiguration());
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
        Assert.assertNotNull(
                ((OIDCDecryptionParameters) params).getKeyTransportDecryptionCredentials().get(1).getPrivateKey());
    }

    public class MockEncryptionConfiguration implements EncryptionConfiguration {

        private List<Credential> credentials;

        private void initializeCredentials() throws NoSuchAlgorithmException {
            credentials = new ArrayList<Credential>();
            // RSA
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.genKeyPair();
            BasicJWKCredential credential = new BasicJWKCredential();
            credential.setUsageType(UsageType.ENCRYPTION);
            credential.setPrivateKey(keyPair.getPrivate());
            credentials.add(credential);
            // lets add second RSA key, it's the same but who cares.
            credentials.add(credential);
            // EC
            keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(256);
            keyPair = keyGen.genKeyPair();
            credential = new BasicJWKCredential();
            credential.setUsageType(UsageType.ENCRYPTION);
            credential.setPrivateKey(keyPair.getPrivate());
            credentials.add(credential);
            // lets add second EC key, it's the same but who cares.
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
        public List<Credential> getDataEncryptionCredentials() {
            return null;
        }

        @Override
        public List<String> getDataEncryptionAlgorithms() {
            return Arrays.asList("A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM", "A192GCM", "A256GCM");
        }

        @Override
        public List<Credential> getKeyTransportEncryptionCredentials() {
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
        public List<String> getKeyTransportEncryptionAlgorithms() {
            return Arrays.asList("ECDH-ES", "RSA1_5", "RSA-OAEP", "RSA-OAEP-256", "A128GCMKW", "A192GCMKW",
                    "A256GCMKW");
        }

        @Override
        public NamedKeyInfoGeneratorManager getDataKeyInfoGeneratorManager() {
            return null;
        }

        @Override
        public NamedKeyInfoGeneratorManager getKeyTransportKeyInfoGeneratorManager() {
            return null;
        }

        @Override
        public RSAOAEPParameters getRSAOAEPParameters() {
            return null;
        }

        @Override
        public boolean isRSAOAEPParametersMerge() {
            return false;
        }

        @Override
        public KeyTransportAlgorithmPredicate getKeyTransportAlgorithmPredicate() {
            return null;
        }

    }

}