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
import net.shibboleth.idp.profile.context.navigate.ResponderIdLookupFunction;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

import org.geant.idpextension.oidc.config.navigate.AudienceRestrictionsLookupFunction;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.id.Audience;

/** {@link AddIDTokenShell} unit test. */
public class AddIDTokenShellTest extends BaseOIDCResponseActionTest {

    private AddIDTokenShell action;

    private void init() throws ComponentInitializationException {
        action = new AddIDTokenShell();
        action.setIssuerLookupStrategy(new ResponderIdLookupFunction());
        action.setAudienceRestrictionsLookupStrategy(new AudienceRestrictionsLookupFunction());
        action.initialize();
    }

    /**
     * Test that id token shell is generated.
     * 
     * @throws ComponentInitializationException
     */
    @Test
    public void testSuccess() throws ComponentInitializationException {
        init();
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertTrue(respCtx.getIDToken().getAudience().contains(new Audience(request.getClientID())));
        Assert.assertEquals(respCtx.getIDToken().getSubject().getValue(), subject);

    }
}