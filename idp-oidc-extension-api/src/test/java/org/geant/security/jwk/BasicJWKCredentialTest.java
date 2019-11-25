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

package org.geant.security.jwk;

import junit.framework.Assert;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.jose.Algorithm;

public class BasicJWKCredentialTest {

    private BasicJWKCredential jwk;
    private Algorithm algo;

    @BeforeMethod
    protected void setUp() throws Exception {
        jwk = new BasicJWKCredential();
        algo = new Algorithm("RS256");
    }

    @Test
    public void testInitialState() {
        Assert.assertNull(jwk.getKid());
        Assert.assertNull(jwk.getAlgorithm());
    }

    @Test
    public void testSetters() {
        jwk.setKid("kid");
        jwk.setAlgorithm(algo);
        Assert.assertEquals(jwk.getKid(), "kid");
        Assert.assertEquals(jwk.getAlgorithm(), new Algorithm("RS256"));
    }

}