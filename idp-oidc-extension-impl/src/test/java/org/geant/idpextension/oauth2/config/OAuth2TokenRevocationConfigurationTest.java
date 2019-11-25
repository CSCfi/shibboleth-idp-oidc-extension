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

package org.geant.idpextension.oauth2.config;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import junit.framework.Assert;

/**
 * Tests for {@link OAuth2TokenRevocationConfiguration}, tests only constructors.
 */
public class OAuth2TokenRevocationConfigurationTest {

    private OAuth2TokenRevocationConfiguration conf;

    @BeforeMethod
    protected void setUp() throws Exception {
        conf = new OAuth2TokenRevocationConfiguration();
    }

    @Test
    public void test() {
        Assert.assertEquals(OAuth2TokenRevocationConfiguration.PROFILE_ID, conf.getId());
        conf = new OAuth2TokenRevocationConfiguration("somethingelse");
        Assert.assertEquals("somethingelse", conf.getId());
    }

}