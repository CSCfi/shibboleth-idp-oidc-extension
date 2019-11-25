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

import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;

import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;

/** {@link InitializeUnverifiedRelyingPartyContext} unit test. */
public class InitializeUnverifiedRelyingPartyContextTest {

    private InitializeUnverifiedRelyingPartyContext action;

    private RequestContext requestCtx;

    @SuppressWarnings("rawtypes")
    private ProfileRequestContext prc;

    @BeforeMethod
    public void init() throws ComponentInitializationException {
        action = new InitializeUnverifiedRelyingPartyContext();
        action.initialize();
        requestCtx = new RequestContextBuilder().buildRequestContext();
        prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
    }

    /** Test that rp context has been initialized and rp is not verified. */
    @Test
    public void testSuccessUnverified() {
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertFalse(prc.getSubcontext(RelyingPartyContext.class).isVerified());
    }

    /** Test case of setting null strategy. */
    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testFailsNullRelyingPartyContextCreationStrategy() {
        action = new InitializeUnverifiedRelyingPartyContext();
        action.setRelyingPartyContextCreationStrategy(null);
    }

}