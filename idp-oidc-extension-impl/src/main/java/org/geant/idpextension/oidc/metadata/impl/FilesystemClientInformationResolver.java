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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Timer;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.geant.idpextension.oidc.criterion.ClientIDCriterion;
import org.geant.idpextension.oidc.metadata.resolver.ClientInformationResolver;
import org.geant.idpextension.oidc.metadata.resolver.RefreshableClientInformationResolver;
import org.geant.idpextension.oidc.metadata.resolver.RemoteJwkSetCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.util.JSONArrayUtils;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.shibboleth.utilities.java.support.annotation.Duration;
import net.shibboleth.utilities.java.support.annotation.constraint.Positive;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * Based on {@link org.opensaml.saml.metadata.resolver.impl.FilesystemMetadataResolver}.
 */
public class FilesystemClientInformationResolver extends AbstractFileOIDCEntityResolver<ClientID, OIDCClientInformation>
        implements ClientInformationResolver, RefreshableClientInformationResolver {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(FilesystemClientInformationResolver.class);

    /** The cache for remote JWK key sets. */
    private RemoteJwkSetCache remoteJwkSetCache;

    /** The remote key refresh interval in milliseconds. Default value: 1800000ms */
    @Duration
    @Positive
    private long keyFetchInterval = 1800000;

    /**
     * Constructor.
     * 
     * @param metadata the metadata file
     * 
     * @throws ResolverException this exception is no longer thrown
     */
    public FilesystemClientInformationResolver(@Nonnull final File metadata) throws ResolverException {
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
    public FilesystemClientInformationResolver(@Nullable final Timer backgroundTaskTimer, @Nonnull final File metadata)
            throws ResolverException {
        super(backgroundTaskTimer, metadata);
    }
    
    /** {@inheritDoc} */
    @Override protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        if (remoteJwkSetCache == null) {
            log.warn("The RemoteJwkSetCache is not defined, the remote keys are not fetched automatically");
        }
    }

    /**
     * Set the cache for remote JWK key sets.
     * 
     * @param jwkSetCache What to set.
     */
    public void setRemoteJwkSetCache(final RemoteJwkSetCache jwkSetCache) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);
        remoteJwkSetCache = Constraint.isNotNull(jwkSetCache, "The remote JWK set cache cannot be null");
    }

    /**
     * Set the remote key refresh interval (in milliseconds).
     * 
     * @param interval What to set.
     */
    public void setKeyFetchInterval(@Duration @Positive long interval) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);

        if (interval < 0) {
            throw new IllegalArgumentException("Remote key refresh must be greater than 0");
        }
        keyFetchInterval = interval;
    }

    /** {@inheritDoc} */
    @Override
    public Iterable<OIDCClientInformation> resolve(CriteriaSet criteria) throws ResolverException {
        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);

        final ClientIDCriterion clientIdCriterion = criteria.get(ClientIDCriterion.class);
        if (clientIdCriterion == null || clientIdCriterion.getClientID() == null) {
            log.trace("No client ID criteria found, returning all");
            return updateKeys(getBackingStore().getOrderedInformation());
        }
        // TODO: support other criterion
        return updateKeys(lookupIdentifier(clientIdCriterion.getClientID()));
    }

    /**
     * Updates the key set in the given list of OIDC client informations. The configured remote JWK set cache is
     * exploited.
     * 
     * @param clientInformations The OIDC client informations whose keys are going to be updated.
     * 
     * @return The OIDC client informations, containing contents of getJWKSetURI() in getJWKSet().
     */
    protected List<OIDCClientInformation> updateKeys(final List<OIDCClientInformation> clientInformations) {
        final List<OIDCClientInformation> result = new ArrayList<>();
        for (final OIDCClientInformation clientInformation : getBackingStore().getOrderedInformation()) {
            if (clientInformation.getOIDCMetadata().getJWKSetURI() != null && remoteJwkSetCache != null) {
                clientInformation.getOIDCMetadata().setJWKSet(
                        remoteJwkSetCache.fetch(clientInformation.getOIDCMetadata().getJWKSetURI(), keyFetchInterval));
            }
            result.add(clientInformation);
        }
        return result;
    }

    /** {@inheritDoc} */
    @Override
    public OIDCClientInformation resolveSingle(CriteriaSet criteria) throws ResolverException {
        final Iterable<OIDCClientInformation> iterable = resolve(criteria);
        if (iterable != null) {
            final Iterator<OIDCClientInformation> iterator = iterable.iterator();
            if (iterator != null && iterator.hasNext()) {
                return iterator.next();
            }
        }
        log.warn("Could not find any clients with the given criteria");
        return null;
    }

    /** {@inheritDoc} */
    @Override
    protected List<OIDCClientInformation> parse(byte[] bytes) throws ParseException {
        final String rawString = new String(bytes);
        try {
            final OIDCClientInformation single = OIDCClientInformation.parse(JSONObjectUtils.parse(rawString));
            log.debug("Found single client information from the file");
            return Arrays.asList(single);
        } catch (ParseException e) {
            log.debug("Could not parse single client information from the file, checking for array");
        }
        try {
            final JSONArray parsedArray = JSONArrayUtils.parse(rawString);
            final List<OIDCClientInformation> result = new ArrayList<OIDCClientInformation>();
            for (final Object object : parsedArray) {
                final OIDCClientInformation client = OIDCClientInformation.parse((JSONObject) object);
                result.add(client);
            }
            return result;
        } catch (ParseException e) {
            throw new ParseException("Could not parse a single or an array of OIDC client information object(s).");
        }
    }

    /** {@inheritDoc} */
    @Override
    protected ClientID getKey(OIDCClientInformation value) {
        return value.getID();
    }
}
