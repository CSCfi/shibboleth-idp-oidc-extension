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
