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