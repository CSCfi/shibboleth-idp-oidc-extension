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

import net.shibboleth.idp.consent.context.impl.AttributeReleaseContext;
import net.shibboleth.idp.consent.context.impl.ConsentContext;
import net.shibboleth.idp.consent.impl.Consent;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseConsentContext;
import org.opensaml.profile.action.EventIds;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.Test;

/** {@link SetConsentToResponseContext} unit test. */
public class SetConsentToResponseContextTest extends BaseOIDCResponseActionTest {

    private SetConsentToResponseContext action;

    private AttributeReleaseContext attrRelCtx;

    private ConsentContext consCtx;

    private void init() throws ComponentInitializationException {
        attrRelCtx = (AttributeReleaseContext) profileRequestCtx.addSubcontext(new AttributeReleaseContext());
        attrRelCtx.getConsentableAttributes().put("1", null);
        attrRelCtx.getConsentableAttributes().put("2", null);
        consCtx = (ConsentContext) profileRequestCtx.addSubcontext(new ConsentContext());
        Consent yes = new Consent();
        yes.setApproved(true);
        Consent no = new Consent();
        no.setApproved(false);
        consCtx.getPreviousConsents().put("1", yes);
        consCtx.getPreviousConsents().put("2", no);
        consCtx.getCurrentConsents().put("3", yes);
        action = new SetConsentToResponseContext();
        action.initialize();
    }

    /**
     * Test that action handles no consent being available.
     * 
     * @throws ComponentInitializationException
     */
    @Test
    public void testSuccessNoConsent() throws ComponentInitializationException {
        init();
        profileRequestCtx.removeSubcontext(ConsentContext.class);
        respCtx.removeSubcontext(OIDCAuthenticationResponseConsentContext.class);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNull(respCtx.getSubcontext(OIDCAuthenticationResponseConsentContext.class, false));
    }

    /**
     * Test that action handles consent but not attrib release context being available.
     * 
     * @throws ComponentInitializationException
     */
    @Test
    public void testFailNoAttribRelConsent() throws ComponentInitializationException {
        init();
        profileRequestCtx.removeSubcontext(AttributeReleaseContext.class);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_PROFILE_CTX);
    }

    /**
     * Test that action handles basic success case.
     * 
     * @throws ComponentInitializationException
     */
    @Test
    public void testSuccess() throws ComponentInitializationException {
        init();
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        OIDCAuthenticationResponseConsentContext ctx =
                respCtx.getSubcontext(OIDCAuthenticationResponseConsentContext.class, false);
        Assert.assertNotNull(ctx);
        Assert.assertTrue(ctx.getConsentableAttributes().contains("1"));
        Assert.assertTrue(ctx.getConsentableAttributes().contains("2"));
        Assert.assertTrue(ctx.getConsentableAttributes().size() == 2);
        Assert.assertTrue(ctx.getConsentedAttributes().contains("3"));
        Assert.assertTrue(ctx.getConsentedAttributes().size() == 1);
    }

    /**
     * Test that action handles basic success case of having only previous consent.
     * 
     * @throws ComponentInitializationException
     */
    @Test
    public void testSuccessPrev() throws ComponentInitializationException {
        init();
        consCtx.getCurrentConsents().clear();
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        OIDCAuthenticationResponseConsentContext ctx =
                respCtx.getSubcontext(OIDCAuthenticationResponseConsentContext.class, false);
        Assert.assertNotNull(ctx);
        Assert.assertTrue(ctx.getConsentableAttributes().contains("1"));
        Assert.assertTrue(ctx.getConsentableAttributes().contains("2"));
        Assert.assertTrue(ctx.getConsentableAttributes().size() == 2);
        Assert.assertTrue(ctx.getConsentedAttributes().contains("1"));
        Assert.assertTrue(ctx.getConsentedAttributes().size() == 1);
    }

}