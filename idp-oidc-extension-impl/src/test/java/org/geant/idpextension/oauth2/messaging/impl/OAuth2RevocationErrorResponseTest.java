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
import com.nimbusds.oauth2.sdk.ErrorObject;

import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;

/**
 * Tests for {@link OAuth2RevocationErrorResponse}.
 */
public class OAuth2RevocationErrorResponseTest {

    private OAuth2RevocationErrorResponse resp;

    @BeforeMethod
    protected void setUp() throws Exception {
        resp = new OAuth2RevocationErrorResponse(new ErrorObject("error_code", "error_string", 400));
    }

    @Test
    public void test() {
        Assert.assertEquals("error_string", resp.getErrorObject().getDescription());
        Assert.assertEquals("error_code", resp.getErrorObject().getCode());
        Assert.assertEquals(400, resp.toHTTPResponse().getStatusCode());
        Assert.assertFalse(resp.indicatesSuccess());
    }

    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testNull() {
        resp = new OAuth2RevocationErrorResponse(null);
    }

}