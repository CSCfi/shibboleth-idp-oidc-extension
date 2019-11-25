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
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;

import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

public class SectorIdentifierLookupFunctionTest {

    private SectorIdentifierLookupFunction lookup;
    @SuppressWarnings("rawtypes")
    private ProfileRequestContext prc;
    private MessageContext<AuthenticationRequest> msgCtx; 
    private OIDCMetadataContext ctx;
    private URI sector;

    @SuppressWarnings("unchecked")
    @BeforeMethod
    protected void setUp() throws Exception {
        sector = new URI("https://example.org/uri");
        lookup = new SectorIdentifierLookupFunction();
        final RequestContext requestCtx = new RequestContextBuilder().buildRequestContext();
        prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        msgCtx = new MessageContext<AuthenticationRequest>();
        prc.setInboundMessageContext(msgCtx);
        ctx = new OIDCMetadataContext();
        OIDCClientMetadata metadata= new OIDCClientMetadata();
        OIDCClientInformation information = new OIDCClientInformation(new ClientID(), new Date(), metadata, new Secret() );
        ctx.setClientInformation(information);
        msgCtx.addSubcontext(ctx);
    }

    
    @Test
    public void testSuccessSectorID() {
        ctx.getClientInformation().getOIDCMetadata().setSectorIDURI(sector);
        String locatedSector = lookup.apply(prc);
        Assert.assertEquals(locatedSector, sector.getHost());
    }
    
    @Test
    public void testSuccessRedirectURI() {
        ctx.getClientInformation().getOIDCMetadata().setRedirectionURI(sector);
        String locatedSector = lookup.apply(prc);
        Assert.assertEquals(locatedSector, sector.getHost());
    }
    
    @Test
    public void testSuccessRedirectURIs() {
        Set<URI> redirectURIs = new HashSet<URI>();
        redirectURIs.add(sector);
        ctx.getClientInformation().getOIDCMetadata().setRedirectionURIs(redirectURIs );
        String locatedSector = lookup.apply(prc);
        Assert.assertEquals(locatedSector, sector.getHost());
    }
    
    @Test
    public void testFailRedirectURIs() throws URISyntaxException {
        Set<URI> redirectURIs = new HashSet<URI>();
        redirectURIs.add(sector);
        redirectURIs.add(new URI("https://example2.org"));
        ctx.getClientInformation().getOIDCMetadata().setRedirectionURIs(redirectURIs);
        String locatedSector = lookup.apply(prc);
        Assert.assertNull(locatedSector);
    }
    
    @Test
    public void testFailNoURIs() throws URISyntaxException {
        String locatedSector = lookup.apply(prc);
        Assert.assertNull(locatedSector);
    }
    
    @Test
    public void testFailNoCtx() throws URISyntaxException {
        msgCtx.removeSubcontext(OIDCMetadataContext.class);
        String locatedSector = lookup.apply(prc);
        Assert.assertNull(locatedSector);
    }
    
    @Test
    public void testFailNoClientInformation() throws URISyntaxException {
        ctx.setClientInformation(null);
        String locatedSector = lookup.apply(prc);
        Assert.assertNull(locatedSector);
    }
}