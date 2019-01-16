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

package org.geant.idpextension.oidc.profile.context.navigate;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.config.ProfileConfiguration;
import net.shibboleth.idp.profile.config.SecurityConfiguration;
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
        resp.put(new MockProfileConfiguration("id1"), "value1");
        resp.put(new MockProfileConfiguration("id2"), "value2");
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

    public class MockProfileConfiguration implements ProfileConfiguration {

        public String id;

        MockProfileConfiguration(String id) {
            this.id = id;
        }

        @Override
        public String getId() {
            return id;
        }

        @Override
        public List<String> getInboundInterceptorFlows() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public List<String> getOutboundInterceptorFlows() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public SecurityConfiguration getSecurityConfiguration() {
            // TODO Auto-generated method stub
            return null;
        }

    }

}