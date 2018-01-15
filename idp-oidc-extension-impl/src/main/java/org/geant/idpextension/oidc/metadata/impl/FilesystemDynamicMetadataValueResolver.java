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

import java.io.File;
import java.util.Timer;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.geant.idpextension.oidc.metadata.resolver.DynamicMetadataValueResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Identifier;

import net.minidev.json.JSONValue;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * An implementation to {@link DynamicMetadataValueResolver} that fetches the information from a file.
 */
public class FilesystemDynamicMetadataValueResolver extends AbstractFileOIDCEntityResolver<Identifier, Object> 
    implements DynamicMetadataValueResolver {
    
    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(FilesystemDynamicMetadataValueResolver.class);

    /**
     * Constructor.
     * 
     * @param metadata the metadata file
     * 
     * @throws ResolverException this exception is no longer thrown
     */
    public FilesystemDynamicMetadataValueResolver(@Nonnull final File metadata) throws ResolverException {
        super(metadata);
    }
    
    /**
     * Constructor.
     * 
     * @param metadata the metadata file
     * @param backgroundTaskTimer timer used to refresh metadata in the background
     * 
     * @throws ResolverException this exception is no longer thrown
     */
    public FilesystemDynamicMetadataValueResolver(@Nullable final Timer backgroundTaskTimer, 
            @Nonnull final File metadata) throws ResolverException {
        super(backgroundTaskTimer, metadata);
    }

    /** {@inheritDoc} */
    @Override
    public Iterable<Object> resolve(CriteriaSet criteria) throws ResolverException {
        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);

        if (criteria != null) {
            log.warn("All criteria for this resolver are currently ignored");
        }
        return getBackingStore().getOrderedInformation();
    }

    /** {@inheritDoc} */
    @Override
    public Object resolveSingle(CriteriaSet criteria) throws ResolverException {
        return resolve(criteria).iterator().next();
    }

    /** {@inheritDoc} */
    @Override
    protected Object parse(byte[] bytes) throws ParseException {
        return JSONValue.parse(bytes);
    }

    /** {@inheritDoc} */
    @Override
    protected Identifier getKey(Object value) {
        return new Identifier("dynamic metadata value");
    }

}
