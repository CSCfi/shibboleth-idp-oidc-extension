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

package org.geant.idpextension.oidc.config;

import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import net.shibboleth.idp.profile.config.SecurityConfiguration;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;

/**
 * Unit tests for {@link AbstractOIDCProfileConfiguration}
 */
public class AbstractOIDCProfileConfigurationTest {

    private AbstractOIDCProfileConfiguration config;

    @BeforeMethod
    protected void setUp() throws Exception {
        config = Mockito.mock(AbstractOIDCProfileConfiguration.class, Mockito.CALLS_REAL_METHODS);
        config.setSecurityConfiguration(new SecurityConfiguration());
    }

    @Test
    public void testInitialization() throws ComponentInitializationException {
        Assert.assertFalse(config.isInitialized());
        config.initialize();
        Assert.assertTrue(config.isInitialized());
    }

    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testInitializationFailureNoSecurityConfig() throws ComponentInitializationException {
        config.setSecurityConfiguration(null);
        Assert.assertFalse(config.isInitialized());
        config.initialize();
    }
}