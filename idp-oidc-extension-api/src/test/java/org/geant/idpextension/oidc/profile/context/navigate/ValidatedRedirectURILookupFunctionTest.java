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

package org.geant.idpextension.oidc.profile.context.navigate;

import java.net.URI;
import java.net.URISyntaxException;

import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/** Tests for {@link ValidatedRedirectURILookupFunction}. */
public class ValidatedRedirectURILookupFunctionTest extends BaseDefaultRequestLookupFunctionTest {

    private ValidatedRedirectURILookupFunction lookup;

    @BeforeMethod
    protected void setUp() throws Exception {
        lookup = new ValidatedRedirectURILookupFunction();
        oidcCtx.setRedirectURI(new URI("http://example.com"));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testNoInput() {
        // No profile context
        Assert.assertNull(lookup.apply(null));
        // No uri
        oidcCtx.setRedirectURI(null);
        Assert.assertNull(lookup.apply(prc));
        // No oidc context
        prc.getOutboundMessageContext().removeSubcontext(OIDCAuthenticationResponseContext.class);
        Assert.assertNull(lookup.apply(prc));
        // No outbound message context
        prc.setOutboundMessageContext(null);
        Assert.assertNull(lookup.apply(prc));
    }

    @Test
    public void testSuccess() throws URISyntaxException {
        Assert.assertEquals(new URI("http://example.com"), lookup.apply(prc));
    }

}