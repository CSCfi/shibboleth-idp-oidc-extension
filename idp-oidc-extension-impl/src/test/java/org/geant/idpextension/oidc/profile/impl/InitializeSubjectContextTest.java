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

import net.shibboleth.idp.authn.context.SubjectContext;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Date;
import org.geant.idpextension.oidc.token.support.AuthorizeCodeClaimsSet;
import org.geant.idpextension.oidc.token.support.TokenClaimsSet;
import org.opensaml.profile.action.EventIds;
import org.springframework.webflow.execution.Event;
import org.testng.annotations.Test;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;

import junit.framework.Assert;

/** {@link InitializeSubjectContext} unit test. */
public class InitializeSubjectContextTest extends BaseOIDCResponseActionTest {

    private InitializeSubjectContext action;

    private void init() throws ComponentInitializationException {
        action = new InitializeSubjectContext();
        action.initialize();
    }

    /**
     * Test that action copes with no token claims set.
     */
    @Test
    public void testNoClaimsSet() throws ComponentInitializationException {
        init();
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_MESSAGE);

    }

    /**
     * Test success case.
     */
    @Test
    public void testSuccess() throws ComponentInitializationException, URISyntaxException {
        init();
        TokenClaimsSet claims = new AuthorizeCodeClaimsSet.Builder(idGenerator, new ClientID(), "issuer", "userPrin",
                "subject", new Date(), new Date(), new Date(), new URI("http://example.com"), new Scope()).build();
        respCtx.setTokenClaimsSet(claims);
        final Event event = action.execute(requestCtx);
        SubjectContext ctx = profileRequestCtx.getSubcontext(SubjectContext.class);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertEquals(ctx.getPrincipalName(), "userPrin");

    }
}