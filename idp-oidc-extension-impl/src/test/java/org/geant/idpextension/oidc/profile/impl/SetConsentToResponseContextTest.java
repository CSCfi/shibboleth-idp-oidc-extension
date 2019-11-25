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

import net.shibboleth.idp.consent.context.AttributeReleaseContext;
import net.shibboleth.idp.consent.context.ConsentContext;
import net.shibboleth.idp.consent.Consent;
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