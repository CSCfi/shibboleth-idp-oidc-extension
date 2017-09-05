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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.geant.idpextension.oidc.metadata.resolver.ClientInformationResolver;
import org.geant.idpextension.oidc.metadata.resolver.RefreshableClientInformationResolver;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Predicates;
import com.google.common.collect.Collections2;
import com.google.common.collect.ImmutableList;
import com.nimbusds.oauth2.sdk.client.ClientInformation;

import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.annotation.constraint.NotLive;
import net.shibboleth.utilities.java.support.annotation.constraint.Unmodifiable;
import net.shibboleth.utilities.java.support.component.AbstractIdentifiableInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * A client information provider that uses registered resolvers, in turn, to answer queries.
 * 
 * The Iterable of client informations returned is the first non-null and non-empty Iterable found while iterating over
 * the registered resolvers in resolver list order.
 */
public class ChainingClientInformationResolver extends AbstractIdentifiableInitializableComponent implements 
    ClientInformationResolver, RefreshableClientInformationResolver {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ChainingClientInformationResolver.class);
    
    /** Registered resolvers. */
    @Nonnull @NonnullElements private List<ClientInformationResolver> resolvers;

    /** Constructor. */
    public ChainingClientInformationResolver() {
        resolvers = Collections.emptyList();
    }
    
    /**
     * Get an immutable the list of currently registered resolvers.
     * 
     * @return list of currently registered resolvers
     */
    @Nonnull @NonnullElements @Unmodifiable @NotLive public List<ClientInformationResolver> getResolvers() {
        return ImmutableList.copyOf(resolvers);
    }

    /**
     * Set the registered client information resolvers.
     * 
     * @param newResolvers the client information resolvers to use
     * 
     * @throws ResolverException thrown if there is a problem adding the client information resolvers
     */
    public void setResolvers(@Nonnull @NonnullElements final List<? extends ClientInformationResolver> newResolvers)
            throws ResolverException {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);

        if (newResolvers == null || newResolvers.isEmpty()) {
            resolvers = Collections.emptyList();
            return;
        }

        resolvers = new ArrayList<>(Collections2.filter(newResolvers, Predicates.notNull()));
    }

    /** {@inheritDoc} */
    @Override
    @Nullable public ClientInformation resolveSingle(@Nullable final CriteriaSet criteria) throws ResolverException {
        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);

        final Iterable<ClientInformation> iterable = resolve(criteria);
        if (iterable != null) {
            final Iterator<ClientInformation> iterator = iterable.iterator();
            if (iterator != null && iterator.hasNext()) {
                return iterator.next();
            }
        }
        return null;
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull public Iterable<ClientInformation> resolve(@Nullable final CriteriaSet criteria) throws ResolverException {
        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);

        for (final ClientInformationResolver resolver : resolvers) {
            try {
                final Iterable<ClientInformation> clientInformations = resolver.resolve(criteria);
                if (clientInformations != null && clientInformations.iterator().hasNext()) {
                    return clientInformations;
                }
            } catch (final ResolverException e) {
                log.warn("Error retrieving client information from resolver of type {}, proceeding to next resolver",
                        resolver.getClass().getName(), e);
                continue;
            }
        }

        return Collections.emptyList();
    }

    /** {@inheritDoc} */
    @Override public void refresh() throws ResolverException {
        for (final ClientInformationResolver resolver : resolvers) {
            if (resolver instanceof RefreshableClientInformationResolver) {
                ((RefreshableClientInformationResolver) resolver).refresh();
            }
        }
    }

    /** {@inheritDoc} */
    @Override
    @Nullable public DateTime getLastUpdate() {
        DateTime ret = null;
        for (final ClientInformationResolver resolver : resolvers) {
            if (resolver instanceof RefreshableClientInformationResolver) {
                final DateTime lastUpdate = ((RefreshableClientInformationResolver) resolver).getLastUpdate();
                if (ret == null || ret.isBefore(lastUpdate)) {
                    ret = lastUpdate;
                }
            }
        }
        
        return ret;
    }

    /** {@inheritDoc} */
    @Override
    @Nullable public DateTime getLastRefresh() {
        DateTime ret = null;
        for (final ClientInformationResolver resolver : resolvers) {
            if (resolver instanceof RefreshableClientInformationResolver) {
                final DateTime lastRefresh = ((RefreshableClientInformationResolver) resolver).getLastRefresh();
                if (ret == null || ret.isBefore(lastRefresh)) {
                    ret = lastRefresh;
                }
            }
        }
        
        return ret;
    }
    
    /** {@inheritDoc} */
    @Override protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        if (resolvers == null) {
            log.warn("ChainingClientInformationResolver was not configured with any member " + 
                    "ClientInformationResolvers");
            resolvers = Collections.emptyList();
        }
    }

    /** {@inheritDoc} */
    @Override protected void doDestroy() {
        super.doDestroy();
        resolvers = Collections.emptyList();
    }

}