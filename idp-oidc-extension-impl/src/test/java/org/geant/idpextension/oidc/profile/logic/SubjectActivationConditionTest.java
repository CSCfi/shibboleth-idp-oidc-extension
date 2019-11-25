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

package org.geant.idpextension.oidc.profile.logic;

import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import com.nimbusds.oauth2.sdk.TokenResponse;

/** {@link SubjectActivationCondition} unit test. */
public class SubjectActivationConditionTest {

    private SubjectActivationCondition lookup;

    @SuppressWarnings("rawtypes")
    protected ProfileRequestContext prc;
    
    protected OIDCAuthenticationResponseContext respCtx;

    @SuppressWarnings("unchecked")
    @BeforeMethod
    public void setup() throws ComponentInitializationException  {
        lookup = new SubjectActivationCondition();
        prc = new WebflowRequestContextProfileRequestContextLookup().apply(new RequestContextBuilder().buildRequestContext());
        prc.setOutboundMessageContext(new MessageContext<TokenResponse>());
        respCtx = new OIDCAuthenticationResponseContext();
        respCtx.setSubject("joe");
        prc.getOutboundMessageContext().addSubcontext(respCtx);
    }

    /**
     * Test that activation condition returns false if subject exists in response context.
     */
    @Test
    public void testSubjectExists()  {
        Assert.assertFalse(lookup.apply(prc));
    }
    
    /**
     * Test that activation condition returns true if subject does not exists in response context.
     */
    @Test
    public void testNoSubject()  {
        respCtx.setSubject(null);
        Assert.assertTrue(lookup.apply(prc));
    }
    
    /**
     * Test that activation condition returns true if there is no oidc response context.
     */
    @Test
    public void testNoOIDCResponseCtx()  {
        prc.getOutboundMessageContext().removeSubcontext(OIDCAuthenticationResponseContext.class);
        Assert.assertTrue(lookup.apply(prc));
    }
    
    /**
     * Test that activation condition returns true if there is no outbound msg ctx.
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testNoOutboundCtx()  {
        prc.setOutboundMessageContext(null);
        Assert.assertTrue(lookup.apply(prc));
    }


}