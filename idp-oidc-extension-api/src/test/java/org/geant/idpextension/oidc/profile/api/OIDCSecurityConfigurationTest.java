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

package org.geant.idpextension.oidc.profile.api;

import org.mockito.Mockito;
import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.SignatureSigningConfiguration;
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
        EncryptionConfiguration confEnc = Mockito.mock(EncryptionConfiguration.class);
        config.setRequestObjectDecryptionConfiguration(confEnc);
        Assert.assertEquals(confEnc, config.getRequestObjectDecryptionConfiguration());
        SignatureSigningConfiguration confDec = Mockito.mock(SignatureSigningConfiguration.class);
        config.setRequestObjectSignatureValidationConfiguration(confDec);
        Assert.assertEquals(confDec, config.getRequestObjectSignatureValidationConfiguration());
    }

}