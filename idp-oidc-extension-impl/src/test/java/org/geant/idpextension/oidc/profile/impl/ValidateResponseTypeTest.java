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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.Set;

import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.geant.idpextension.oidc.profile.OidcEventIds;
import org.springframework.webflow.execution.Event;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

/** {@link ValidateResponseType} unit test. */
public class ValidateResponseTypeTest extends BaseOIDCResponseActionTest {

    private ValidateResponseType action;

    private OIDCClientMetadata metaData;

    @BeforeMethod
    private void init() throws ComponentInitializationException, URISyntaxException, ParseException {
        action = new ValidateResponseType();
        action.initialize();
        OIDCMetadataContext oidcCtx =
                profileRequestCtx.getInboundMessageContext().getSubcontext(OIDCMetadataContext.class, true);
        metaData = new OIDCClientMetadata();
        Set<ResponseType> responseTypes = new HashSet<ResponseType>();
        responseTypes.add(ResponseType.parse("code"));
        responseTypes.add(ResponseType.parse("id_token token"));
        metaData.setResponseTypes(responseTypes);
        metaData.setRedirectionURI(new URI("https://notmatching.org"));
        OIDCClientInformation information =
                new OIDCClientInformation(new ClientID("test"), null, metaData, null, null, null);
        oidcCtx.setClientInformation(information);
    }

    /**
     * Test that action accepts the "id_token token" response type.
     */
    @Test
    public void testSuccess() throws ComponentInitializationException {
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
    }

    /**
     * Test that action rejects the "id_token token" response type.
     */
    @Test
    public void testFailure() throws ComponentInitializationException, ParseException {
        Set<ResponseType> responseTypes = new HashSet<ResponseType>();
        responseTypes.add(ResponseType.parse("code"));
        metaData.setResponseTypes(responseTypes);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, OidcEventIds.INVALID_RESPONSE_TYPE);
    }

}