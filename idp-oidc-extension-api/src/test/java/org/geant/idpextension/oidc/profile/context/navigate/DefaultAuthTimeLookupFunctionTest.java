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

import net.shibboleth.idp.authn.AuthenticationResult;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;

import java.util.Date;

import javax.security.auth.Subject;

import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/** Tests for {@link DefaultAuthTimeLookupFunctionTest}. */
public class DefaultAuthTimeLookupFunctionTest {

    private DefaultAuthTimeLookupFunction lookup;

    @SuppressWarnings("rawtypes")
    private ProfileRequestContext prc;

    private Date instant = new Date();

    private AuthenticationResult result;

    private AuthenticationContext authCtx;

    @BeforeMethod
    protected void setUp() throws Exception {
        lookup = new DefaultAuthTimeLookupFunction();
        final RequestContext requestCtx = new RequestContextBuilder().buildRequestContext();
        prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        authCtx = prc.getSubcontext(AuthenticationContext.class, true);
        result = new AuthenticationResult("id", new Subject());
        result.setAuthenticationInstant(instant.getTime());
        authCtx.setAuthenticationResult(result);
    }

    @Test
    public void testSuccess() {
        Assert.assertEquals(instant.getTime(), (long) lookup.apply(prc));
    }

    @Test
    public void testNoCtxts() {
        // No profile context
        Assert.assertNull(lookup.apply(null));
        // No result
        authCtx.setAuthenticationResult(null);
        Assert.assertNull(lookup.apply(prc));
        // No authentication context
        prc.removeSubcontext(AuthenticationContext.class);
        Assert.assertNull(lookup.apply(prc));
    }

}