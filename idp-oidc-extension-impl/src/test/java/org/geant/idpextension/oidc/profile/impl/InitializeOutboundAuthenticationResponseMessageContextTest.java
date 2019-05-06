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

import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Date;

import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.common.messaging.context.SAMLMetadataContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.ext.saml2mdui.UIInfo;
import org.opensaml.saml.saml2.metadata.Extensions;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

/** {@link InitializeOutboundAuthenticationResponseMessageContext} unit test. */
public class InitializeOutboundAuthenticationResponseMessageContextTest {

    private InitializeOutboundAuthenticationResponseMessageContext action;

    private RequestContext requestCtx;

    protected OIDCMetadataContext metadataCtx;

    @SuppressWarnings("rawtypes")
    private ProfileRequestContext prc;

    @BeforeMethod
    public void init() throws ComponentInitializationException, ParseException {
        AuthenticationRequest request = AuthenticationRequest.parse(
                "response_type=id_token+token&client_id=s6BhdRkqt3&login_hint=foo&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid%20email%20profile%20offline_access&state=af0ifjsldkj&nonce=n-0S6_WzA2Mj");
        action = new InitializeOutboundAuthenticationResponseMessageContext();
        action.initialize();
        requestCtx = new RequestContextBuilder().setInboundMessage(request).buildRequestContext();
        prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        metadataCtx = (OIDCMetadataContext) prc.getInboundMessageContext().addSubcontext(new OIDCMetadataContext());
        OIDCClientInformation information =
                new OIDCClientInformation(new ClientID("clientId"), new Date(), new OIDCClientMetadata(), new Secret());
        metadataCtx.setClientInformation(information);
    }

    /** Test that outbound message context exists. */
    @Test
    public void testSuccess() {
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNotNull(prc.getOutboundMessageContext());
    }

    /** Test that action copes with non existent logo. */
    @Test
    public void nonExistentLogo() throws URISyntaxException {
        metadataCtx.getClientInformation().getOIDCMetadata().setLogoURI(new URI("file:/nonexistent.png"));
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNotNull(prc.getOutboundMessageContext());
    }

    /** Test that action copes with invalid logo. */
    @Test
    public void emptyLogo() throws URISyntaxException {
        metadataCtx.getClientInformation().getOIDCMetadata()
                .setLogoURI(new URI(getClass().getResource("/misc/invalidlogo.png").toString()));
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNotNull(prc.getOutboundMessageContext());
    }

    /** Test that action sets valid logo. */
    @Test
    public void successLogo() throws URISyntaxException {
        metadataCtx.getClientInformation().getOIDCMetadata()
                .setLogoURI(new URI(getClass().getResource("/misc/logo.png").toString()));
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNotNull(prc.getOutboundMessageContext());
        SAMLMetadataContext ctx = prc.getOutboundMessageContext().getSubcontext(SAMLPeerEntityContext.class)
                .getSubcontext(SAMLMetadataContext.class);
        final Extensions exts = ctx.getRoleDescriptor().getExtensions();
        if (exts != null) {
            for (final XMLObject object : exts.getOrderedChildren()) {
                if (object instanceof UIInfo) {
                    Assert.assertTrue(((UIInfo) object).getLogos().size() == 1);
                    return;
                }
            }
        }
        Assert.assertFalse(false, "There is no logo for rp");
    }

    /** Test that action populates policy uri to privacy statement element . */
    @Test
    public void successPolicy() throws URISyntaxException {
        metadataCtx.getClientInformation().getOIDCMetadata().setPolicyURI(new URI("http://policy.example.com"));
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNotNull(prc.getOutboundMessageContext());
        SAMLMetadataContext ctx = prc.getOutboundMessageContext().getSubcontext(SAMLPeerEntityContext.class)
                .getSubcontext(SAMLMetadataContext.class);
        final Extensions exts = ctx.getRoleDescriptor().getExtensions();
        if (exts != null) {
            for (final XMLObject object : exts.getOrderedChildren()) {
                if (object instanceof UIInfo) {
                    Assert.assertTrue(((UIInfo) object).getPrivacyStatementURLs().size() == 1);
                    Assert.assertEquals("http://policy.example.com",
                            ((UIInfo) object).getPrivacyStatementURLs().get(0).getValue());
                    return;
                }
            }
        }
        Assert.assertFalse(false, "There is no privacy statement for rp");
    }

    /** Test that action populates tos to information element . */
    @Test
    public void successTos() throws URISyntaxException {
        metadataCtx.getClientInformation().getOIDCMetadata().setTermsOfServiceURI(new URI("http://tos.example.com"));
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNotNull(prc.getOutboundMessageContext());
        SAMLMetadataContext ctx = prc.getOutboundMessageContext().getSubcontext(SAMLPeerEntityContext.class)
                .getSubcontext(SAMLMetadataContext.class);
        final Extensions exts = ctx.getRoleDescriptor().getExtensions();
        if (exts != null) {
            for (final XMLObject object : exts.getOrderedChildren()) {
                if (object instanceof UIInfo) {
                    Assert.assertTrue(((UIInfo) object).getInformationURLs().size() == 1);
                    Assert.assertEquals("http://tos.example.com",
                            ((UIInfo) object).getInformationURLs().get(0).getValue());
                    return;
                }
            }
        }
        Assert.assertFalse(false, "There is no information url for rp");
    }

    /** Test that action populates contacts element . */
    @Test
    public void successContacts() throws URISyntaxException {
        metadataCtx.getClientInformation().getOIDCMetadata()
                .setEmailContacts(Arrays.asList("contact1@example.com", "contact2@example.com"));
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNotNull(prc.getOutboundMessageContext());
        SAMLMetadataContext ctx = prc.getOutboundMessageContext().getSubcontext(SAMLPeerEntityContext.class)
                .getSubcontext(SAMLMetadataContext.class);
        Assert.assertEquals(2, ctx.getEntityDescriptor().getContactPersons().size());
        Assert.assertEquals("mailto:contact1@example.com",
                ctx.getEntityDescriptor().getContactPersons().get(0).getEmailAddresses().get(0).getAddress());
        Assert.assertEquals("mailto:contact2@example.com",
                ctx.getEntityDescriptor().getContactPersons().get(1).getEmailAddresses().get(0).getAddress());
    }

    /** Test that action populates service information element . */
    @Test
    public void successService() throws URISyntaxException {
        metadataCtx.getClientInformation().getOIDCMetadata().setName("test rp");
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNotNull(prc.getOutboundMessageContext());
        SAMLMetadataContext ctx = prc.getOutboundMessageContext().getSubcontext(SAMLPeerEntityContext.class)
                .getSubcontext(SAMLMetadataContext.class);
        final Extensions exts = ctx.getRoleDescriptor().getExtensions();
        if (exts != null) {
            for (final XMLObject object : exts.getOrderedChildren()) {
                if (object instanceof UIInfo) {
                    Assert.assertTrue(((UIInfo) object).getDisplayNames().size() == 1);
                    Assert.assertEquals("test rp", ((UIInfo) object).getDisplayNames().get(0).getValue());
                    return;
                }
            }
        }
        Assert.assertFalse(false, "There is no service name for rp");
    }

}