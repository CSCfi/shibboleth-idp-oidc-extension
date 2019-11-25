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

package org.geant.idpextension.oidc.metadata.resolver;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Objects;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;

import net.shibboleth.ext.spring.service.AbstractServiceableComponent;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * This class exists primarily to allow the parsing of relying-party.xml to create a serviceable implementation of
 * {@link ClientInformationResolver}. Based on net.shibboleth.idp.saml.metadata.RelyingPartyMetadataProvider.
 */

public class RelyingPartyClientInformationProvider extends AbstractServiceableComponent<ClientInformationResolver>
        implements RefreshableClientInformationResolver, Comparable<RelyingPartyClientInformationProvider> {

    /** If we autogenerate a sort key it comes from this count. */
    private static int sortKeyValue;

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(RelyingPartyClientInformationProvider.class);

    /** The embedded resolver. */
    @NonnullAfterInit
    private ClientInformationResolver resolver;

    /** The key by which we sort the provider. */
    @NonnullAfterInit
    private Integer sortKey;

    /** Constructor. */
    public RelyingPartyClientInformationProvider() {
    }

    /**
     * Set the sort key.
     * 
     * @param key what to set
     */
    public void setSortKey(final int key) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        sortKey = new Integer(key);
    }

    /**
     * Set the {@link ClientInformationResolver} to embed.
     * 
     * @param theResolver The {@link ClientInformationResolver} to embed.
     */
    @Nonnull
    public void setEmbeddedResolver(@Nonnull final ClientInformationResolver theResolver) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        resolver = Constraint.isNotNull(theResolver, "ClientInformationResolver cannot be null");
    }

    /**
     * Return what we are build around. Used for testing.
     * 
     * @return the parameter we got as a constructor
     */
    @Nonnull
    public ClientInformationResolver getEmbeddedResolver() {
        return resolver;
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull
    public Iterable<OIDCClientInformation> resolve(@Nullable final CriteriaSet criteria) throws ResolverException {

        return resolver.resolve(criteria);
    }

    /** {@inheritDoc} */
    @Override
    @Nullable
    public OIDCClientInformation resolveSingle(@Nullable final CriteriaSet criteria) throws ResolverException {

        return resolver.resolveSingle(criteria);
    }

    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        setId(resolver.getId());
        super.doInitialize();
        if (null == resolver) {
            throw new ComponentInitializationException("ClientInformationResolver cannot be null");
        }

        if (null == sortKey) {
            synchronized (this) {
                sortKeyValue++;
                sortKey = new Integer(sortKeyValue);
            }
            log.info("Top level ClientInformation Provider '{}' did not have a sort key; giving it value '{}'", getId(),
                    sortKey);
        }
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull
    public ClientInformationResolver getComponent() {
        return this;
    }

    /** {@inheritDoc} */
    @Override
    public void refresh() throws ResolverException {
        if (resolver instanceof RefreshableClientInformationResolver) {
            ((RefreshableClientInformationResolver) resolver).refresh();
        }
    }

    /** {@inheritDoc} */
    @Override
    public DateTime getLastRefresh() {
        if (resolver instanceof RefreshableClientInformationResolver) {
            return ((RefreshableClientInformationResolver) resolver).getLastRefresh();
        } else {
            return null;
        }
    }

    /** {@inheritDoc} */
    @Override
    public DateTime getLastUpdate() {
        if (resolver instanceof RefreshableClientInformationResolver) {
            return ((RefreshableClientInformationResolver) resolver).getLastUpdate();
        } else {
            return null;
        }
    }

    /** {@inheritDoc} */
    @Override
    public int compareTo(final RelyingPartyClientInformationProvider other) {
        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);
        final int result = sortKey.compareTo(other.sortKey);
        if (result != 0) {
            return result;
        }
        if (equals(other)) {
            return 0;
        }
        return getId().compareTo(other.getId());
    }

    /**
     * {@inheritDoc}. We are within a spring context and so equality can be determined by ID, however we also test by
     * sortKey just in case.
     */
    @Override
    public boolean equals(final Object other) {
        if (null == other) {
            return false;
        }
        if (!(other instanceof RelyingPartyClientInformationProvider)) {
            return false;
        }
        final RelyingPartyClientInformationProvider otherRp = (RelyingPartyClientInformationProvider) other;

        return Objects.equal(otherRp.sortKey, sortKey) && Objects.equal(getId(), otherRp.getId());
    }

    /** {@inheritDoc} */
    @Override
    public int hashCode() {
        return Objects.hashCode(sortKey, getId());
    }

}