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

import net.shibboleth.idp.authn.AuthenticationResult;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import javax.security.auth.Subject;
import org.opensaml.profile.action.EventIds;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.Test;

/** {@link SetAuthenticationTimeToResponseContext} unit test. */
public class SetAuthenticationTimeToResponseContextTest extends BaseOIDCResponseActionTest {

    private SetAuthenticationTimeToResponseContext action;

    private void init() throws ComponentInitializationException {
        action = new SetAuthenticationTimeToResponseContext();
        action.initialize();
    }

    /**
     * Test that action copes with no authentication time available.
     * 
     * @throws ComponentInitializationException
     */
    @Test
    public void testNoAuthTime() throws ComponentInitializationException {
        init();
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_PROFILE_CTX);

    }

    /**
     * Test that authentication time is stored.
     * 
     * @throws ComponentInitializationException
     */
    @Test
    public void testSuccess() throws ComponentInitializationException {
        init();
        AuthenticationContext authCtx = profileRequestCtx.getSubcontext(AuthenticationContext.class, true);
        AuthenticationResult result = new AuthenticationResult("id", new Subject());
        result.setAuthenticationInstant(1000);
        authCtx.setAuthenticationResult(result);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertEquals(respCtx.getAuthTime().getTime(), 1000);

    }

}