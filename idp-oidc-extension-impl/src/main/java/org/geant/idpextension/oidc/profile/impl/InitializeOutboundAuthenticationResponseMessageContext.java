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

import net.shibboleth.idp.profile.IdPEventIds;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.net.URI;
import java.util.List;

import javax.annotation.Nonnull;
import javax.imageio.ImageIO;

import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.profile.context.navigate.InboundMessageContextLookup;
import org.opensaml.profile.context.navigate.OutboundMessageContextLookup;
import org.opensaml.saml.common.messaging.context.SAMLMetadataContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.ext.saml2mdui.DisplayName;
import org.opensaml.saml.ext.saml2mdui.InformationURL;
import org.opensaml.saml.ext.saml2mdui.Logo;
import org.opensaml.saml.ext.saml2mdui.PrivacyStatementURL;
import org.opensaml.saml.ext.saml2mdui.UIInfo;
import org.opensaml.saml.ext.saml2mdui.impl.DisplayNameBuilder;
import org.opensaml.saml.ext.saml2mdui.impl.InformationURLBuilder;
import org.opensaml.saml.ext.saml2mdui.impl.LogoBuilder;
import org.opensaml.saml.ext.saml2mdui.impl.PrivacyStatementURLBuilder;
import org.opensaml.saml.ext.saml2mdui.impl.UIInfoBuilder;
import org.opensaml.saml.saml2.metadata.ContactPerson;
import org.opensaml.saml.saml2.metadata.ContactPersonTypeEnumeration;
import org.opensaml.saml.saml2.metadata.EmailAddress;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Extensions;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.impl.ContactPersonBuilder;
import org.opensaml.saml.saml2.metadata.impl.EmailAddressBuilder;
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.ExtensionsBuilder;
import org.opensaml.saml.saml2.metadata.impl.SPSSODescriptorBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.google.common.base.Functions;
import com.nimbusds.langtag.LangTag;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

/**
 * Action that adds an outbound {@link MessageContext} and related OIDC contexts to the {@link ProfileRequestContext}
 * based on the identity of a relying party accessed via a lookup strategy, by default an immediate child of the profile
 * request context.
 * 
 * This action also initializes the {@link SAMLMetadataContext} and populates it with service and {@link UIInfo}
 * -related data.
 * 
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 * @event {@link IdPEventIds#INVALID_RELYING_PARTY_CTX}
 * @event {@link EventIds#INVALID_MSG_CTX}
 */
public class InitializeOutboundAuthenticationResponseMessageContext
        extends AbstractInitializeOutboundResponseMessageContextForRP<AuthenticationResponse> {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(InitializeOutboundAuthenticationResponseMessageContext.class);

    /** Strategy function to create the {@link SAMLMetadataContext}. */
    @Nonnull
    private Function<ProfileRequestContext, SAMLMetadataContext> samlMetadataCtxCreateStrategy;

    /** Strategy function to lookup the {@link OIDCMetadataContext}. */
    @Nonnull
    private Function<ProfileRequestContext, OIDCMetadataContext> oidcMetadataCtxLookupStrategy;

    /** The OIDC metadata context used as a source for the SAML metadata context. */
    private OIDCMetadataContext oidcMetadataCtx;

    /** The default language when it has not been defined in the metadata. */
    private String defaultLanguage;

    /**
     * Constructor.
     */
    public InitializeOutboundAuthenticationResponseMessageContext() {
        super();
        samlMetadataCtxCreateStrategy = Functions.compose(new ChildContextLookup<>(SAMLMetadataContext.class, true),
                Functions.compose(new ChildContextLookup<>(SAMLPeerEntityContext.class, true),
                        new OutboundMessageContextLookup()));
        oidcMetadataCtxLookupStrategy = Functions.compose(new ChildContextLookup<>(OIDCMetadataContext.class, false),
                new InboundMessageContextLookup());
        defaultLanguage = "en";
    }

    /**
     * Get the mechanism to create the {@link SAMLMetadataContext} to the {@link ProfileRequestContext}.
     * 
     * @return The mechanism to create the {@link SAMLMetadataContext} to the {@link ProfileRequestContext}.
     */
    @Nonnull
    public Function<ProfileRequestContext, SAMLMetadataContext> getSAMLMetadataContextCreateStrategy() {
        return samlMetadataCtxCreateStrategy;
    }

    /**
     * Set the mechanism to create the {@link OIDCMetadataContext} to the {@link ProfileRequestContext}.
     * 
     * @param strgy What to set.
     */
    public void setSAMLMetadataContextCreateStrategy(
            @Nonnull final Function<ProfileRequestContext, SAMLMetadataContext> strgy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        samlMetadataCtxCreateStrategy = Constraint.isNotNull(strgy, "Injected Metadata Strategy cannot be null");
    }

    /**
     * Get the mechanism to lookup the {@link OIDCMetadataContext} from the {@link ProfileRequestContext}.
     * 
     * @return The mechanism to lookup the {@link OIDCMetadataContext} from the {@link ProfileRequestContext}.
     */
    @Nonnull
    public Function<ProfileRequestContext, OIDCMetadataContext> getOIDCMetadataContextLookupStrategy() {
        return oidcMetadataCtxLookupStrategy;
    }

    /**
     * Set the mechanism to lookup the {@link OIDCMetadataContext} from the {@link ProfileRequestContext}.
     * 
     * @param strgy What to set.
     */
    public void setOIDCMetadataContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, OIDCMetadataContext> strgy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        oidcMetadataCtxLookupStrategy = Constraint.isNotNull(strgy, "Injected Metadata Strategy cannot be null");
    }

    /**
     * Set the default language when it has not been defined in the metadata.
     * 
     * @param language What to set.
     */
    public void setDefaultLanguage(@Nonnull final String language) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        defaultLanguage = Constraint.isNotEmpty(language, "The default language cannot be empty");
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        oidcMetadataCtx = oidcMetadataCtxLookupStrategy.apply(profileRequestContext);
        if (oidcMetadataCtx == null) {
            log.error("{} No OIDC metadata context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;
        }
        return super.doPreExecute(profileRequestContext);
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        super.doExecute(profileRequestContext);
        final SAMLMetadataContext samlContext = samlMetadataCtxCreateStrategy.apply(profileRequestContext);
        final EntityDescriptor entityDescriptor = new EntityDescriptorBuilder().buildObject();
        entityDescriptor.setEntityID(oidcMetadataCtx.getClientInformation().getID().getValue());
        final OIDCClientMetadata oidcMetadata = oidcMetadataCtx.getClientInformation().getOIDCMetadata();
        final SPSSODescriptor spDescriptor = new SPSSODescriptorBuilder().buildObject();
        final UIInfo uiInfo = new UIInfoBuilder().buildObject();
        for (final LangTag tag : oidcMetadata.getLogoURIEntries().keySet()) {
            final Logo logo = new LogoBuilder().buildObject();
            logo.setXMLLang(tag == null ? defaultLanguage : tag.getLanguage());
            final URI logoUri = oidcMetadata.getLogoURI(tag);
            try {
                final BufferedImage image = ImageIO.read(oidcMetadata.getLogoURI(tag).toURL());
                if (image != null) {
                    logo.setURL(logoUri.toString());
                    logo.setWidth(image.getWidth());
                    logo.setHeight(image.getHeight());
                    uiInfo.getLogos().add(logo);
                }
            } catch (IOException e) {
                log.warn("{} Could not load the image from the URI {}", getLogPrefix(), logoUri);
            }
        }
        for (final LangTag tag : oidcMetadata.getPolicyURIEntries().keySet()) {
            final PrivacyStatementURL url = new PrivacyStatementURLBuilder().buildObject();
            url.setXMLLang(tag == null ? defaultLanguage : tag.getLanguage());
            url.setValue(oidcMetadata.getPolicyURI(tag).toString());
            uiInfo.getPrivacyStatementURLs().add(url);
        }
        for (final LangTag tag : oidcMetadata.getTermsOfServiceURIEntries().keySet()) {
            final InformationURL url = new InformationURLBuilder().buildObject();
            url.setXMLLang(tag == null ? defaultLanguage : tag.getLanguage());
            url.setValue(oidcMetadata.getTermsOfServiceURI(tag).toString());
            uiInfo.getInformationURLs().add(url);
        }
        final List<String> emails = oidcMetadata.getEmailContacts();
        if (emails != null) {
            for (final String email : emails) {
                final ContactPerson contactPerson = new ContactPersonBuilder().buildObject();
                // TODO: should it be configurable?
                contactPerson.setType(ContactPersonTypeEnumeration.SUPPORT);
                final EmailAddress address = new EmailAddressBuilder().buildObject();
                address.setAddress(email.startsWith("mailto:") ? email : "mailto:" + email);
                contactPerson.getEmailAddresses().add(address);
                entityDescriptor.getContactPersons().add(contactPerson);
            }
        }
        for (final LangTag tag : oidcMetadata.getNameEntries().keySet()) {
            final DisplayName displayName = new DisplayNameBuilder().buildObject();
            displayName.setXMLLang(tag == null ? defaultLanguage : tag.getLanguage());
            displayName.setValue(oidcMetadata.getNameEntries().get(tag));
            uiInfo.getDisplayNames().add(displayName);
        }
        final Extensions extensions = new ExtensionsBuilder().buildObject();
        extensions.getUnknownXMLObjects().add(uiInfo);
        spDescriptor.setExtensions(extensions);
        samlContext.setEntityDescriptor(entityDescriptor);
        samlContext.setRoleDescriptor(spDescriptor);
    }
}