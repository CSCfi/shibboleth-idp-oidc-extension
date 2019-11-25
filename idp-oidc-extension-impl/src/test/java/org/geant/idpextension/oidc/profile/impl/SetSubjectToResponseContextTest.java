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

import net.shibboleth.idp.consent.context.ConsentContext;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.UnmodifiableComponentException;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import org.geant.idpextension.oidc.profile.context.navigate.TokenRequestSubjectLookupFunction;
import org.geant.idpextension.oidc.token.support.AccessTokenClaimsSet;
import org.geant.idpextension.oidc.token.support.TokenClaimsSet;
import org.opensaml.profile.action.EventIds;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.Test;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;

/** {@link SetSubjectToResponseContext} unit test. */
public class SetSubjectToResponseContextTest extends BaseOIDCResponseActionTest {

    private SetSubjectToResponseContext action;

    private void init() throws ComponentInitializationException {
        action = new SetSubjectToResponseContext();
        action.initialize();
    }

    /**
     * Test that action handles case of no subject available.
     */
    @Test
    public void testNoSubject() throws ComponentInitializationException {
        init();
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_PROFILE_CTX);
    }

    /**
     * Test that action throws error when null strategy is set.
     */
    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testNoStrategy() throws NoSuchAlgorithmException, ComponentInitializationException {
        action = new SetSubjectToResponseContext();
        action.setSubjectLookupStrategy(null);
    }

    /**
     * Test that action throws error when strategy is being set when already initialized.
     */
    @Test(expectedExceptions = UnmodifiableComponentException.class)
    public void testInitialized() throws NoSuchAlgorithmException, ComponentInitializationException {
        init();
        action.setSubjectLookupStrategy(new TokenRequestSubjectLookupFunction());
    }

    /**
     * Test that action copies subject to response ctx.
     */
    @Test
    public void testSuccess() throws ComponentInitializationException, URISyntaxException {
        init();
        TokenClaimsSet claims = new AccessTokenClaimsSet.Builder(idGenerator, new ClientID(), "issuer", "userPrin",
                "subject", new Date(), new Date(), new Date(), new URI("http://example.com"), new Scope()).build();
        respCtx.setTokenClaimsSet(claims);
        profileRequestCtx.removeSubcontext(ConsentContext.class);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertEquals(respCtx.getSubject(), "subject");

    }

}