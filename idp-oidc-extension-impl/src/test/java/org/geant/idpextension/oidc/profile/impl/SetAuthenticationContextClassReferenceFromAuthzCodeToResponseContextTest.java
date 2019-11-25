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
import net.shibboleth.utilities.java.support.security.DataSealerException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Date;
import org.geant.idpextension.oidc.token.support.AuthorizeCodeClaimsSet;
import org.geant.idpextension.oidc.token.support.TokenClaimsSet;
import org.opensaml.profile.action.EventIds;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.Test;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.claims.ACR;

/** {@link SetAuthenticationContextClassReferenceFromAuthzCodeToResponseContext} unit test. */
public class SetAuthenticationContextClassReferenceFromAuthzCodeToResponseContextTest
        extends BaseOIDCResponseActionTest {

    private SetAuthenticationContextClassReferenceFromAuthzCodeToResponseContext action;

    private void init() throws ComponentInitializationException, NoSuchAlgorithmException, URISyntaxException {
        TokenClaimsSet claims = new AuthorizeCodeClaimsSet.Builder(idGenerator, new ClientID(), "issuer", "userPrin",
                "subject", new Date(), new Date(), new Date(), new URI("http://example.com"),
                new Scope()).setACR(new ACR("0")).build();
        respCtx.setTokenClaimsSet(claims);
        action = new SetAuthenticationContextClassReferenceFromAuthzCodeToResponseContext();
        action.initialize();
    }

    /**
     * Basic success case.
     */
    @Test
    public void testSuccess() throws ComponentInitializationException, NoSuchAlgorithmException, URISyntaxException,
            ParseException, DataSealerException {
        init();
        respCtx.setAcr(null);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertEquals(respCtx.getAcr(), new ACR("0"));
    }

    /**
     * Fails due to missing input.
     */
    @Test
    public void testFailsNoToken() throws ComponentInitializationException, NoSuchAlgorithmException,
            URISyntaxException, ParseException, DataSealerException {
        init();
        respCtx.setTokenClaimsSet(null);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_PROFILE_CTX);
    }

}