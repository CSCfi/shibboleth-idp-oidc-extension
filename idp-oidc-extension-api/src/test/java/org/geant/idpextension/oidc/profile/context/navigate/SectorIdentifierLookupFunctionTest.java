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

package org.geant.idpextension.oidc.profile.context.navigate;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;

import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.junit.Assert;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.RequestContext;
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