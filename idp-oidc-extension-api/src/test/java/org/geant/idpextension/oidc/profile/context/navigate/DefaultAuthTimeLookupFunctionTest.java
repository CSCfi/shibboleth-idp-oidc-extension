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