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

package org.geant.idpextension.oidc.profile.impl;

import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.openid.connect.sdk.rp.ApplicationType;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

/**
 * Unit tests for {@link AddApplicationTypeToClientMetadata}.
 */
public class AddApplicationTypeToClientMetadataTest extends BaseOIDCClientMetadataPopulationTest {

    AddApplicationTypeToClientMetadata action;
    
    @BeforeMethod
    public void setUp() throws ComponentInitializationException {
        action = new AddApplicationTypeToClientMetadata();
        action.initialize();
    }
    
    @Test
    public void testDefault() throws ComponentInitializationException {
        OIDCClientMetadata result = new OIDCClientMetadata();
        setUpContext(new OIDCClientMetadata(), result);
        Assert.assertNull(action.execute(requestCtx));
        Assert.assertEquals(result.getApplicationType(), ApplicationType.getDefault());
    }

    @Test
    public void testWeb() throws ComponentInitializationException {
        OIDCClientMetadata input = new OIDCClientMetadata();
        input.setApplicationType(ApplicationType.WEB);
        OIDCClientMetadata result = new OIDCClientMetadata();
        setUpContext(input, result);
        Assert.assertNull(action.execute(requestCtx));
        Assert.assertEquals(result.getApplicationType(), ApplicationType.WEB);
    }

    @Test
    public void testNative() throws ComponentInitializationException {
        OIDCClientMetadata input = new OIDCClientMetadata();
        input.setApplicationType(ApplicationType.NATIVE);
        OIDCClientMetadata result = new OIDCClientMetadata();
        setUpContext(input, result);
        Assert.assertNull(action.execute(requestCtx));
        Assert.assertEquals(result.getApplicationType(), ApplicationType.NATIVE);
    }

    @Override
    protected AbstractOIDCClientMetadataPopulationAction constructAction() {
        return new AddApplicationTypeToClientMetadata();
    }
}
