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
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Timer;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.joda.time.DateTime;
import org.joda.time.chrono.ISOChronology;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;

import com.nimbusds.oauth2.sdk.id.Identifier;

import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * Based on {@link org.opensaml.saml.metadata.resolver.impl.FilesystemMetadataResolver}.
 */
public abstract class AbstractFileOIDCEntityResolver<Key extends Identifier, Value> 
    extends AbstractReloadingOIDCEntityResolver<Key, Value> {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(AbstractFileOIDCEntityResolver.class);

    /** The metadata file. */
    @Nonnull private File metadataFile;

    /**
     * Constructor.
     * 
     * @param metadata the metadata file
     * 
     * @throws IOException If the metedata cannot be loaded.
     */
    public AbstractFileOIDCEntityResolver(@Nonnull final Resource metadata) throws IOException {
        super();
        setMetadataFile(metadata.getFile());
    }

    /**
     * Constructor.
     * 
     * @param metadata the metadata file
     * @param backgroundTaskTimer timer used to refresh metadata in the background
     * 
     * @throws IOException If the metedata cannot be loaded.
     */
    public AbstractFileOIDCEntityResolver(@Nullable final Timer backgroundTaskTimer, @Nonnull final Resource metadata)
            throws IOException {
        super(backgroundTaskTimer);
        setMetadataFile(metadata.getFile());
    }

    /**
     * Sets the file from which metadata is read.
     * 
     * @param file path to the metadata file
     */
    protected void setMetadataFile(@Nonnull final File file) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);

        metadataFile = Constraint.isNotNull(file, "Metadata file cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected void doDestroy() {
        metadataFile = null;
          
        super.doDestroy();
    }
    
    /** {@inheritDoc} */
    @Override
    protected String getMetadataIdentifier() {
        return metadataFile.getAbsolutePath();
    }
    
    /**
     * Get the time for the last update/modification of the metadata file.
     * @return The last update time.
     */
    protected DateTime getMetadataUpdateTime() {
        return new DateTime(metadataFile.lastModified(), ISOChronology.getInstanceUTC());
    }

    /** {@inheritDoc} */
    @Override
    protected byte[] fetchMetadata() throws ResolverException {
        try {
            ResolverHelper.validateMetadataFile(metadataFile);
            DateTime metadataUpdateTime = getMetadataUpdateTime();
            if (getLastRefresh() == null || getLastUpdate() == null || metadataUpdateTime.isAfter(getLastRefresh())) {
                log.debug("Returning the contents of {} as byte array", metadataFile.toPath());
                return ResolverHelper.inputstreamToByteArray(new FileInputStream(metadataFile));
            }
            return null;
        } catch (IOException e) {
            String errMsg = "Unable to read metadata file " + metadataFile.getAbsolutePath();
            log.error(errMsg, e);
            throw new ResolverException(errMsg, e);
        }
    }
}
