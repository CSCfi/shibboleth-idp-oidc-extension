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

package org.geant.idpextension.oauth2.messaging.impl;

import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Tests for {@link OAuth2RevocationSuccessResponse}.
 */
public class OAuth2RevocationSuccessResponseTest {

    private OAuth2RevocationSuccessResponse resp;

    @BeforeMethod
    protected void setUp() throws Exception {
        resp = new OAuth2RevocationSuccessResponse();
    }

    @Test
    public void test() {
        Assert.assertEquals(200, resp.toHTTPResponse().getStatusCode());
        Assert.assertTrue(resp.indicatesSuccess());
    }

}