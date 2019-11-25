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

import net.shibboleth.idp.attribute.resolver.context.AttributeResolutionContext;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;

import org.geant.idpextension.oidc.profile.OidcEventIds;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.openid.connect.sdk.SubjectType;

/** {@link SetSectorIdentifierForAttributeResolution} unit test. */
public class SetSectorIdentifierForAttributeResolutionTest extends BaseOIDCResponseActionTest {

    private SetSectorIdentifierForAttributeResolution action;

    @BeforeMethod
    private void init() throws ComponentInitializationException, URISyntaxException {
        action = new SetSectorIdentifierForAttributeResolution();
        action.initialize();
        metadataCtx.getClientInformation().getOIDCMetadata().setSubjectType(SubjectType.PUBLIC);
        metadataCtx.getClientInformation().getOIDCMetadata().setRedirectionURI(new URI("http://example.com"));
    }

    /**
     * Test that action sets the attribute recipient group as public.
     */
    @Test
    public void testSuccessPublic() throws ComponentInitializationException {
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        AttributeResolutionContext attribCtx = profileRequestCtx.getSubcontext(AttributeResolutionContext.class, true);
        Assert.assertEquals(attribCtx.getAttributeRecipientGroupID(), "public");
    }

    /**
     * Test that action sets the attribute recipient group as host part of redirect uri (in this case).
     */
    @Test
    public void testSuccessPairwise() throws ComponentInitializationException {
        metadataCtx.getClientInformation().getOIDCMetadata().setSubjectType(SubjectType.PAIRWISE);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        AttributeResolutionContext attribCtx = profileRequestCtx.getSubcontext(AttributeResolutionContext.class, true);
        Assert.assertEquals(attribCtx.getAttributeRecipientGroupID(), "example.com");
    }

    /**
     * Test that action sets the attribute recipient group as host part of redirect uri (in this case).
     */
    @Test
    public void testFailPairwiseNoSectorIdentifier() throws ComponentInitializationException {
        metadataCtx.getClientInformation().getOIDCMetadata().setSubjectType(SubjectType.PAIRWISE);
        metadataCtx.getClientInformation().getOIDCMetadata().setRedirectionURI(null);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, OidcEventIds.MISSING_REDIRECT_URIS);
    }

    /**
     * Test setting null strategy for sector identifier.
     */
    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testNullStrategySectorIdentifier() {
        action = new SetSectorIdentifierForAttributeResolution();
        action.setSectorIdentifierLookupStrategy(null);
    }

    /**
     * Test setting null strategy for subject type.
     */
    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testNullStrategySubjectType() {
        action = new SetSectorIdentifierForAttributeResolution();
        action.setSubjectTypeLookupStrategy(null);
    }

}