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

package org.geant.idpextension.oidc.profile.context.navigate;

import java.util.HashMap;
import java.util.Map;

import org.mockito.Mockito;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.config.ProfileConfiguration;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

/** Tests for {@link ProfileResponderIdLookupFunction}. */
public class ProfileResponderIdLookupFunctionTest {

    private ProfileResponderIdLookupFunction lookup;

    @SuppressWarnings("rawtypes")
    private ProfileRequestContext prc;

    @BeforeMethod
    protected void setUp() throws Exception {
        final RequestContext requestCtx = new RequestContextBuilder().buildRequestContext();
        prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        lookup = new ProfileResponderIdLookupFunction();
        lookup.setId("1");
        lookup.setDefaultResponder("defaultvalue");
        Map<ProfileConfiguration, String> resp = new HashMap<ProfileConfiguration, String>();
        lookup.initialize();
        ProfileConfiguration conf1 = Mockito.mock(ProfileConfiguration.class);
        Mockito.when(conf1.getId()).thenReturn("id1");
        resp.put(conf1, "value1");
        ProfileConfiguration conf2 = Mockito.mock(ProfileConfiguration.class);
        Mockito.when(conf2.getId()).thenReturn("id2");
        resp.put(conf2, "value2");
        lookup.setProfileResponders(resp);
    }

    @Test
    public void testSuccess() throws ComponentInitializationException {
        prc.setProfileId("unknown");
        Assert.assertEquals(lookup.apply(prc), "defaultvalue");
        prc.setProfileId("id1");
        Assert.assertEquals(lookup.apply(prc), "value1");
        prc.setProfileId("id2");
        Assert.assertEquals(lookup.apply(prc), "value2");
    }

    @Test(expectedExceptions = ComponentInitializationException.class)
    public void testInitialization() throws ComponentInitializationException {
        lookup = new ProfileResponderIdLookupFunction();
        lookup.setId("1");
        lookup.initialize();
    }

}