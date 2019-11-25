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
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.testng.Assert;
import org.geant.idpextension.oidc.profile.OidcEventIds;
import org.springframework.webflow.execution.Event;
import org.testng.annotations.Test;

/** {@link VerifyRequestedSubjectIdentifier} unit test. */
public class VerifyRequestedSubjectIdentifierTest extends BaseOIDCResponseActionTest {

    private VerifyRequestedSubjectIdentifier action;

    private void init() throws ComponentInitializationException {
        action = new VerifyRequestedSubjectIdentifier();
        action.initialize();
    }

    /**
     * Test action handles not having requested subject correctly.
     * 
     * @throws ComponentInitializationException
     */
    @Test
    public void testSuccessNoReqSubject() throws ComponentInitializationException {
        init();
        respCtx.setRequestedSubject(null);
        respCtx.setSubject(null);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNull(respCtx.getRequestedSubject());
    }

    /**
     * Test action handles not having generated subject set correctly.
     * 
     * @throws ComponentInitializationException
     */
    @Test
    public void testNoGenSubject() throws ComponentInitializationException {
        init();
        respCtx.setRequestedSubject("reqsub");
        respCtx.setSubject(null);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, OidcEventIds.INVALID_SUBJECT);
    }

    /**
     * Test action handles not having matching generated subject set correctly.
     * 
     * @throws ComponentInitializationException
     */
    @Test
    public void testNoMismatchSubject() throws ComponentInitializationException {
        init();
        respCtx.setRequestedSubject("reqsub");
        respCtx.setSubject("reqsub2");
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, OidcEventIds.INVALID_SUBJECT);
    }

    /**
     * Test action handles having matching generated subject set correctly.
     * 
     * @throws ComponentInitializationException
     */
    @Test
    public void testSuccess() throws ComponentInitializationException {
        init();
        respCtx.setRequestedSubject("reqsub");
        respCtx.setSubject("reqsub");
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
    }

}