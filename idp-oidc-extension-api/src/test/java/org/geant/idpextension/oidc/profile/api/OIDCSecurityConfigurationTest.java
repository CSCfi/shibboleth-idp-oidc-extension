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

package org.geant.idpextension.oidc.profile.api;

import java.util.Collection;
import java.util.List;

import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.KeyTransportAlgorithmPredicate;
import org.opensaml.xmlsec.SignatureSigningConfiguration;
import org.opensaml.xmlsec.encryption.support.RSAOAEPParameters;
import org.opensaml.xmlsec.keyinfo.NamedKeyInfoGeneratorManager;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Unit tests for {@link OIDCSecurityConfiguration}
 */
public class OIDCSecurityConfigurationTest {

    private OIDCSecurityConfiguration config;

    @BeforeMethod
    protected void setUp() throws Exception {
        config = new OIDCSecurityConfiguration();
    }

    @Test
    public void testInitialState() {

        Assert.assertNull(config.getRequestObjectDecryptionConfiguration());
        Assert.assertNull(config.getRequestObjectSignatureValidationConfiguration());
    }

    @Test
    public void testSetters() {
        config = new OIDCSecurityConfiguration();
        EncryptionConfiguration confEnc = new mockEncryptionConfiguration();
        config.setRequestObjectDecryptionConfiguration(confEnc);
        Assert.assertEquals(confEnc, config.getRequestObjectDecryptionConfiguration());
        SignatureSigningConfiguration confDec = new mockSignatureSigningConfiguration();
        config.setRequestObjectSignatureValidationConfiguration(confDec);
        Assert.assertEquals(confDec, config.getRequestObjectSignatureValidationConfiguration());
    }

    public class mockSignatureSigningConfiguration implements SignatureSigningConfiguration {

        @Override
        public Collection<String> getWhitelistedAlgorithms() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public boolean isWhitelistMerge() {
            // TODO Auto-generated method stub
            return false;
        }

        @Override
        public Collection<String> getBlacklistedAlgorithms() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public boolean isBlacklistMerge() {
            // TODO Auto-generated method stub
            return false;
        }

        @Override
        public Precedence getWhitelistBlacklistPrecedence() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public List<Credential> getSigningCredentials() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public List<String> getSignatureAlgorithms() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public List<String> getSignatureReferenceDigestMethods() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public String getSignatureReferenceCanonicalizationAlgorithm() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public String getSignatureCanonicalizationAlgorithm() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public Integer getSignatureHMACOutputLength() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public NamedKeyInfoGeneratorManager getKeyInfoGeneratorManager() {
            // TODO Auto-generated method stub
            return null;
        }

    }

    public class mockEncryptionConfiguration implements EncryptionConfiguration {

        @Override
        public Collection<String> getWhitelistedAlgorithms() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public boolean isWhitelistMerge() {
            // TODO Auto-generated method stub
            return false;
        }

        @Override
        public Collection<String> getBlacklistedAlgorithms() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public boolean isBlacklistMerge() {
            // TODO Auto-generated method stub
            return false;
        }

        @Override
        public Precedence getWhitelistBlacklistPrecedence() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public List<Credential> getDataEncryptionCredentials() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public List<String> getDataEncryptionAlgorithms() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public List<Credential> getKeyTransportEncryptionCredentials() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public List<String> getKeyTransportEncryptionAlgorithms() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public NamedKeyInfoGeneratorManager getDataKeyInfoGeneratorManager() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public NamedKeyInfoGeneratorManager getKeyTransportKeyInfoGeneratorManager() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public RSAOAEPParameters getRSAOAEPParameters() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public boolean isRSAOAEPParametersMerge() {
            // TODO Auto-generated method stub
            return false;
        }

        @Override
        public KeyTransportAlgorithmPredicate getKeyTransportAlgorithmPredicate() {
            // TODO Auto-generated method stub
            return null;
        }

    }

}