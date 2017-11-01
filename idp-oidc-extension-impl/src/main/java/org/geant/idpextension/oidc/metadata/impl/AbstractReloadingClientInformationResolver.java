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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

import javax.annotation.Nullable;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.chrono.ISOChronology;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;

import net.shibboleth.utilities.java.support.annotation.Duration;
import net.shibboleth.utilities.java.support.annotation.constraint.Positive;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * Based on {@link org.opensaml.saml.metadata.resolver.impl.AbstractReloadingMetadataResolver}.
 */
public abstract class AbstractReloadingClientInformationResolver extends AbstractClientInformationResolver {
    
    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(AbstractReloadingClientInformationResolver.class);
    
    /** Timer used to schedule background metadata update tasks. */
    private Timer taskTimer;
    
    /** Whether we created our own task timer during object construction. */
    private boolean createdOwnTaskTimer;
        
    /** Current task to refresh metadata. */
    private RefreshMetadataTask refreshMetadataTask;
    
    /** Factor used to compute when the next refresh interval will occur. Default value: 0.75 */
    private float refreshDelayFactor = 0.75f;
    
    /**
     * Refresh interval used when metadata does not contain any validUntil or cacheDuration information. Default value:
     * 14400000ms
     */
    @Duration @Positive private long maxRefreshDelay = 14400000;

    /** Floor, in milliseconds, for the refresh interval. Default value: 300000ms */
    @Duration @Positive private long minRefreshDelay = 300000;

    /** Time when the currently cached metadata file expires. */
    private DateTime expirationTime;

    /** Last time the metadata was updated. */
    private DateTime lastUpdate;

    /** Last time a refresh cycle occurred. */
    private DateTime lastRefresh;

    /** Next time a refresh cycle will occur. */
    private DateTime nextRefresh;

    /** Constructor. */
    protected AbstractReloadingClientInformationResolver() {
        this(null);
    }

    /**
     * Constructor.
     * 
     * @param backgroundTaskTimer time used to schedule background refresh tasks
     */
    protected AbstractReloadingClientInformationResolver(@Nullable final Timer backgroundTaskTimer) {
        super();
        
        if (backgroundTaskTimer == null) {
            taskTimer = new Timer(true);
            createdOwnTaskTimer = true;
        } else {
            taskTimer = backgroundTaskTimer;
        }
    }

    protected void initClientInformationResolver() throws ComponentInitializationException {
        super.initClientInformationResolver();
        try {
            refresh();
        } catch (ResolverException e) {
            log.error("Could not refresh the client information", e);
            throw new ComponentInitializationException("Could not refresh the client information", e);
        }
    }

    /** {@inheritDoc} */
    @Nullable public DateTime getLastUpdate() {
        return lastUpdate;
    }

    /** {@inheritDoc} */
    @Nullable public DateTime getLastRefresh() {
        return lastRefresh;
    }
    
    /**
     * Refreshes the metadata from its source.
     * 
     * @throws ResolverException thrown is there is a problem retrieving and processing the metadata
     */
    public synchronized void refresh() throws ResolverException {
        DateTime now = new DateTime(ISOChronology.getInstanceUTC());
        String mdId = getMetadataIdentifier();

        log.debug("Beginning refresh of metadata from '{}'", mdId);
        try {
            byte[] mdBytes = fetchMetadata();
            if (mdBytes == null) {
                log.debug("Metadata from '{}' has not changed since last refresh", mdId);
            } else {
                log.debug("Processing new metadata from '{}'", mdId);
                final Gson gson = new Gson();
                final OIDCClientInformation clientInformation = gson.fromJson(new String(mdBytes), 
                        OIDCClientInformation.class);
                final ClientID clientId = clientInformation.getID();
                log.info("Parsed client information for client ID {}", clientId);
                final ClientBackingStore newBackingStore = new ClientBackingStore();
                List<OIDCClientInformation> allInformation = new ArrayList<>();
                allInformation.add(clientInformation);
                newBackingStore.getIndexedInformation().put(clientId, allInformation);
                newBackingStore.getOrderedInformation().add(clientInformation);
                setBackingStore(newBackingStore);
                lastUpdate = now;
            }
        } catch (Throwable t) {
            log.error("Error occurred while attempting to refresh metadata from '" + mdId + "'", t);
            nextRefresh = new DateTime(ISOChronology.getInstanceUTC()).plus(minRefreshDelay);
            if (t instanceof Exception) {
                throw new ResolverException((Exception) t);
            } else {
                throw new ResolverException(String.format("Saw an error of type '%s' with message '%s'", 
                        t.getClass().getName(), t.getMessage()));
            }
        } finally {
            refreshMetadataTask = new RefreshMetadataTask();
            long nextRefreshDelay = minRefreshDelay;
            //TODO: refresh-delays should be defined better
            nextRefresh = new DateTime(ISOChronology.getInstanceUTC()).plus(minRefreshDelay);
            
            taskTimer.schedule(refreshMetadataTask, nextRefreshDelay);
            log.info("Next refresh cycle for metadata provider '{}' will occur on '{}' ('{}' local time)",
                    new Object[] {mdId, nextRefresh, nextRefresh.toDateTime(DateTimeZone.getDefault()),});
            lastRefresh = now;
        }
    }
    
    /**
     * Gets an identifier which may be used to distinguish this metadata in logging statements.
     * 
     * @return identifier which may be used to distinguish this metadata in logging statements
     */
    protected abstract String getMetadataIdentifier();

    /**
     * Fetches metadata from a source.
     * 
     * @return the fetched metadata, or null if the metadata is known not to have changed since the last retrieval
     * 
     * @throws ResolverException thrown if there is a problem fetching the metadata
     */
    protected abstract byte[] fetchMetadata() throws ResolverException;
    
    /**
     * Converts an InputStream into a byte array.
     * 
     * @param ins input stream to convert
     * 
     * @return resultant byte array
     * 
     * @throws ResolverException thrown if there is a problem reading the resultant byte array
     */
    protected byte[] inputstreamToByteArray(InputStream ins) throws ResolverException {
        try {
            // 1 MB read buffer
            byte[] buffer = new byte[1024 * 1024];
            ByteArrayOutputStream output = new ByteArrayOutputStream();

            int n = 0;
            while (-1 != (n = ins.read(buffer))) {
                output.write(buffer, 0, n);
            }

            ins.close();
            return output.toByteArray();
        } catch (IOException e) {
            throw new ResolverException(e);
        }
    }
    
    /** Background task that refreshes metadata. */
    private class RefreshMetadataTask extends TimerTask {

        /** {@inheritDoc} */
        @Override
        public void run() {
            try {
                if (!isInitialized()) {
                    // just in case the metadata provider was destroyed before this task runs
                    return;
                }
                
                refresh();
            } catch (ResolverException e) {
                // nothing to do, error message already logged by refreshMetadata()
                return;
            }
        }
    }
}
