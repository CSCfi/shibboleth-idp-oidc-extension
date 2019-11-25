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
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Timer;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.geant.idpextension.oidc.metadata.resolver.MetadataValueResolver;
import org.geant.idpextension.oidc.metadata.resolver.RefreshableMetadataValueResolver;
import org.joda.time.DateTime;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import net.minidev.json.JSONObject;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * An extension to {@link FilesystemProviderMetadataResolver} that enables some of the claims to be dynamically updated
 * outside the file.
 */
public class DynamicFilesystemProviderMetadataResolver extends FilesystemProviderMetadataResolver {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(DynamicFilesystemProviderMetadataResolver.class);

    /** The map of dynamic metadata value resolvers, key corresponding to the name of the metadata field. */
    private Map<String, ? extends MetadataValueResolver> dynamicResolvers = new HashMap<>();

    /**
     * Constructor.
     * 
     * @param metadata the metadata file
     * 
     * @throws IOException If the metedata cannot be loaded.
     */
    public DynamicFilesystemProviderMetadataResolver(@Nonnull final Resource metadata) throws IOException {
        super(metadata);
    }

    /**
     * Constructor.
     * 
     * @param backgroundTaskTimer timer used to refresh metadata in the background
     * @param metadata the metadata file
     * 
     * @throws IOException If the metedata cannot be loaded.
     */
    public DynamicFilesystemProviderMetadataResolver(@Nullable final Timer backgroundTaskTimer,
            @Nonnull final Resource metadata) throws IOException {
        super(backgroundTaskTimer, metadata);
    }

    /**
     * Set dynamic metadata value resolvers.
     * 
     * @param map What to set.
     */
    public void setDynamicValueResolvers(final Map<String, ? extends MetadataValueResolver> map) {
        dynamicResolvers = Constraint.isNotNull(map, "The map of dynamic metadata resolvers cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    public Iterable<OIDCProviderMetadata> resolve(ProfileRequestContext profileRequestContext)
            throws ResolverException {
        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);

        final List<OIDCProviderMetadata> result = new ArrayList<OIDCProviderMetadata>();
        final Iterator<OIDCProviderMetadata> entities = super.resolve(profileRequestContext).iterator();
        while (entities.hasNext()) {
            final OIDCProviderMetadata entity = entities.next();
            final JSONObject entityJson = entity.toJSONObject();
            for (final String key : dynamicResolvers.keySet()) {
                log.debug("Starting to resolve value for {}", key);
                final MetadataValueResolver resolver = dynamicResolvers.get(key);
                try {
                    if (resolver instanceof RefreshableMetadataValueResolver) {
                        ((RefreshableMetadataValueResolver) resolver).refresh();
                    }
                    final Object value = resolver.resolveSingle(profileRequestContext);
                    if (value != null) {
                        entityJson.put(key, value);
                        log.debug("The field {} updated to the result", key);
                    }
                } catch (ResolverException e) {
                    log.warn("Could not resolve a value for {̛}, ignoring it.", key, e);
                }
            }
            try {
                result.add(OIDCProviderMetadata.parse(entityJson));
            } catch (ParseException e) {
                log.warn("The resulting provider metadata is not valid, ignoring it", e);
            }
        }
        return result;
    }

    /** {@inheritDoc} */
    @Override
    protected DateTime getMetadataUpdateTime() {
        DateTime updateTime = super.getMetadataUpdateTime();
        for (final String id : dynamicResolvers.keySet()) {
            final MetadataValueResolver resolver = dynamicResolvers.get(id);
            if (resolver instanceof RefreshableMetadataValueResolver) {
                if (((RefreshableMetadataValueResolver) resolver).getLastUpdate() == null) {
                    return DateTime.now();
                }
                if (((RefreshableMetadataValueResolver) resolver).getLastUpdate().isAfter(updateTime)) {
                    return ((RefreshableMetadataValueResolver) resolver).getLastUpdate();
                }
            }
        }
        return updateTime;
    }
}
