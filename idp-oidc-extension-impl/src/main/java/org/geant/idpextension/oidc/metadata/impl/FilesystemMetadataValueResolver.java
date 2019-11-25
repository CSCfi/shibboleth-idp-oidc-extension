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
import java.util.Arrays;
import java.util.List;
import java.util.Timer;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.geant.idpextension.oidc.metadata.resolver.RefreshableMetadataValueResolver;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Identifier;

import net.minidev.json.JSONValue;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * An implementation to {@link RefreshableMetadataValueResolver} that fetches the information from a file.
 */
public class FilesystemMetadataValueResolver extends AbstractFileOIDCEntityResolver<Identifier, Object> 
    implements RefreshableMetadataValueResolver {
    
    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(FilesystemMetadataValueResolver.class);

    /**
     * Constructor.
     * 
     * @param metadata the metadata file
     * 
     * @throws IOException If the metedata cannot be loaded.
     */
    public FilesystemMetadataValueResolver(@Nonnull final Resource metadata) throws IOException {
        super(metadata);
    }
    
    /**
     * Constructor.
     * 
     * @param metadata the metadata file
     * @param backgroundTaskTimer timer used to refresh metadata in the background
     * 
     * @throws IOException If the metedata cannot be loaded.
     */
    public FilesystemMetadataValueResolver(@Nullable final Timer backgroundTaskTimer, 
            @Nonnull final Resource metadata) throws IOException {
        super(backgroundTaskTimer, metadata);
    }

    /**
     * Returns all the resolved objects.
     * 
     * @param criteria the criteria to evaluate or process, currently ignored. May be null.
     * 
     * @return all the resolved objects.
     * 
     * @throws ResolverException thrown if there is an error during resolution.
     */
    @Override
    public Iterable<Object> resolve(ProfileRequestContext profileRequestContext) throws ResolverException {
        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);

        return getBackingStore().getOrderedInformation();
    }

    /**
     * Returns a single resolved object. If many were resolved, a single one is selected randomly from the set.
     * 
     * @param criteria the criteria to evaluate or process, currently ignored. May be null.
     * 
     * @return a single resolved object.
     * 
     * @throws ResolverException thrown if there is an error during resolution.
     */
    @Override
    public Object resolveSingle(ProfileRequestContext profileRequestContext) throws ResolverException {
        return resolve(profileRequestContext).iterator().next();
    }

    /** {@inheritDoc} */
    @Override
    protected List<Object> parse(byte[] bytes) throws ParseException {
        return Arrays.asList(JSONValue.parse(bytes));
    }

    /** {@inheritDoc} */
    @Override
    protected Identifier getKey(Object value) {
        return new Identifier("dynamic metadata value");
    }

}
