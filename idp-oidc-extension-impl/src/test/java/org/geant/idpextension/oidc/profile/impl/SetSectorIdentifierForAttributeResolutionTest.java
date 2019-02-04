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