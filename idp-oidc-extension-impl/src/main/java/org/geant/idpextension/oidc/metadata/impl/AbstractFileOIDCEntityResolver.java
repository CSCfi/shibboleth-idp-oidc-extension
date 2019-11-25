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
