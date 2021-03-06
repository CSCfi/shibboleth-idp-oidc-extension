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
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;

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
    @Nullable public OIDCClientInformation resolveSingle(@Nullable final CriteriaSet criteria) 
            throws ResolverException {
        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);

        final Iterable<OIDCClientInformation> iterable = resolve(criteria);
        if (iterable != null) {
            final Iterator<OIDCClientInformation> iterator = iterable.iterator();
            if (iterator != null && iterator.hasNext()) {
                return iterator.next();
            }
        }
        return null;
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull public Iterable<OIDCClientInformation> resolve(@Nullable final CriteriaSet criteria) 
            throws ResolverException {
        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);

        for (final ClientInformationResolver resolver : resolvers) {
            try {
                final Iterable<OIDCClientInformation> clientInformations = resolver.resolve(criteria);
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
        } else {
            final List<String> resolverDetails = new ArrayList<>();
            for (final ClientInformationResolver resolver : resolvers) {
                resolverDetails.add(resolver.getId() + ": " + countClients(resolver) + " clients");
            }
            log.info("ChainingClientInformationResolver was configured with the following resolvers: {}",
                    resolverDetails);
        }
    }

    /** {@inheritDoc} */
    @Override protected void doDestroy() {
        super.doDestroy();
        resolvers = Collections.emptyList();
    }
    
    /**
     * Counts the clients found from the given resolver.
     * 
     * @param resolver The resolver whose clients are counted.
     * @return The amount of resolvable clients.
     */
    protected int countClients(final ClientInformationResolver resolver) {
        int count = 0;
        Iterable<OIDCClientInformation> iterable;
        try {
            iterable = resolver.resolve(new CriteriaSet());
        } catch (ResolverException e) {
            log.warn("ChainingClientInformationResolver could not count clients for {}", resolver.getId());
            return 0;
        }
        if (iterable != null) {
            final Iterator<OIDCClientInformation> iterator = iterable.iterator();
            while (iterator.hasNext()) {
                iterator.next();
                count++;
            }
        }
        return count;
    }

}