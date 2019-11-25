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

package org.geant.idpextension.oidc.metadata.impl;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Timer;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.geant.idpextension.oidc.metadata.resolver.ProviderMetadataResolver;
import org.geant.idpextension.oidc.metadata.resolver.RefreshableProviderMetadataResolver;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;

import com.google.common.base.Function;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * Based on {@link org.opensaml.saml.metadata.resolver.impl.FilesystemMetadataResolver}.
 */
public class FilesystemProviderMetadataResolver extends AbstractFileOIDCEntityResolver<Issuer, OIDCProviderMetadata>
        implements ProviderMetadataResolver, RefreshableProviderMetadataResolver {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(FilesystemProviderMetadataResolver.class);

    /**
     * Strategy used to locate the {@link RelyingPartyContext} associated with a given {@link ProfileRequestContext}.
     */
    @Nonnull
    private Function<ProfileRequestContext, RelyingPartyContext> relyingPartyContextLookupStrategy;

    /**
     * Constructor.
     * 
     * @param metadata the metadata file
     * 
     * @throws IOException If the metedata cannot be loaded.
     */
    public FilesystemProviderMetadataResolver(@Nonnull final Resource metadata) throws IOException {
        super(metadata);
        relyingPartyContextLookupStrategy = new ChildContextLookup<>(RelyingPartyContext.class);
    }

    /**
     * Constructor.
     * 
     * @param metadata the metadata file
     * @param backgroundTaskTimer timer used to refresh metadata in the background
     * 
     * @throws IOException If the metedata cannot be loaded.
     */
    public FilesystemProviderMetadataResolver(@Nullable final Timer backgroundTaskTimer,
            @Nonnull final Resource metadata) throws IOException {
        super(backgroundTaskTimer, metadata);
        relyingPartyContextLookupStrategy = new ChildContextLookup<>(RelyingPartyContext.class);
    }

    /**
     * Set the strategy used to locate the {@link RelyingPartyContext} associated with a given
     * {@link ProfileRequestContext}.
     * 
     * @param strategy strategy used to locate the {@link RelyingPartyContext} associated with a given
     *            {@link ProfileRequestContext}
     */
    public void setRelyingPartyContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, RelyingPartyContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        relyingPartyContextLookupStrategy =
                Constraint.isNotNull(strategy, "RelyingPartyContext lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    public Iterable<OIDCProviderMetadata> resolve(ProfileRequestContext profileRequestContext)
            throws ResolverException {
        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);

        final RelyingPartyContext rpCtx = relyingPartyContextLookupStrategy.apply(profileRequestContext);
        final List<OIDCProviderMetadata> entities = getBackingStore().getOrderedInformation();
        final List<OIDCProviderMetadata> result = new ArrayList<>();
        if (rpCtx == null || rpCtx.getConfiguration() == null || rpCtx.getConfiguration().getResponderId() == null) {
            log.warn("Could not find relying party ID from context, returning all");
            return entities;
        }
        for (OIDCProviderMetadata entity : entities) {
            if (entity.getIssuer().getValue().equals(rpCtx.getConfiguration().getResponderId())) {
                rpCtx.getConfiguration().getResponderId();
                result.add(entity);
            }
        }
        return result;
    }

    /** {@inheritDoc} */
    @Override
    public OIDCProviderMetadata resolveSingle(ProfileRequestContext profileRequestContext) throws ResolverException {
        final Iterable<OIDCProviderMetadata> iterable = resolve(profileRequestContext);
        if (iterable != null) {
            final Iterator<OIDCProviderMetadata> iterator = iterable.iterator();
            if (iterator != null && iterator.hasNext()) {
                return iterator.next();
            }
        }
        log.warn("Could not find any clients with the given criteria");
        return null;
    }

    /** {@inheritDoc} */
    @Override
    protected List<OIDCProviderMetadata> parse(byte[] bytes) throws ParseException {
        return Arrays.asList(OIDCProviderMetadata.parse(JSONObjectUtils.parse(new String(bytes))));
    }

    /** {@inheritDoc} */
    @Override
    protected Issuer getKey(OIDCProviderMetadata value) {
        return value.getIssuer();
    }
}
