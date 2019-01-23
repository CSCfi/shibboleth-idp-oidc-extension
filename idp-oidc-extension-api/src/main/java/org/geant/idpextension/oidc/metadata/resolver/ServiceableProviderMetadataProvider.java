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

package org.geant.idpextension.oidc.metadata.resolver;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.joda.time.DateTime;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Objects;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import net.shibboleth.ext.spring.service.AbstractServiceableComponent;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * A serviceable implementation of {@link ProviderMetadataResolver}.
 * 
 * Based on net.shibboleth.idp.saml.metadata.RelyingPartyMetadataProvider.
 */
public class ServiceableProviderMetadataProvider extends AbstractServiceableComponent<ProviderMetadataResolver>
        implements RefreshableProviderMetadataResolver, Comparable<ServiceableProviderMetadataProvider> {

    /** If we autogenerate a sort key it comes from this count. */
    private static int sortKeyValue;

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(ServiceableProviderMetadataProvider.class);

    /** The embedded resolver. */
    @NonnullAfterInit
    private ProviderMetadataResolver resolver;

    /** The key by which we sort the provider. */
    @NonnullAfterInit
    private Integer sortKey;

    /** Constructor. */
    public ServiceableProviderMetadataProvider() {
    }

    /**
     * Set the sort key.
     * 
     * @param key what to set
     */
    public void setSortKey(final int key) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        sortKey = Integer.valueOf(key);
    }

    /**
     * Set the {@link ProviderMetadataResolver} to embed.
     * 
     * @param theResolver The {@link ProviderMetadataResolver} to embed.
     */
    @Nonnull
    public void setEmbeddedResolver(@Nonnull final ProviderMetadataResolver theResolver) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        resolver = Constraint.isNotNull(theResolver, "ProviderMetadataResolver cannot be null");
    }

    /**
     * Return what we are build around. Used for testing.
     * 
     * @return the parameter we got as a constructor
     */
    @Nonnull
    public ProviderMetadataResolver getEmbeddedResolver() {
        return resolver;
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull
    public Iterable<OIDCProviderMetadata> resolve(final ProfileRequestContext profileRequestContext)
            throws ResolverException {

        return resolver.resolve(profileRequestContext);
    }

    /** {@inheritDoc} */
    @Override
    @Nullable
    public OIDCProviderMetadata resolveSingle(@Nullable final ProfileRequestContext profileRequestContext)
            throws ResolverException {

        return resolver.resolveSingle(profileRequestContext);
    }

    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        if (null == resolver) {
            throw new ComponentInitializationException("ProviderMetadataResolver cannot be null");
        }

        if (null == sortKey) {
            synchronized (this) {
                sortKeyValue++;
                setSortKey(sortKeyValue);
            }
            log.info("Top level ProviderMetadata Provider '{}' did not have a sort key; giving it value '{}'", getId(),
                    sortKey);
        }
    }
    
    /**
     * Sets the ID of this component. The component must not yet be initialized.
     * 
     * @param componentId ID of the component
     */
    @Override
    public void setId(@Nonnull @NotEmpty final String componentId) {
        super.setId(componentId);
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull
    public ProviderMetadataResolver getComponent() {
        return this;
    }

    /** {@inheritDoc} */
    @Override
    public void refresh() throws ResolverException {
        if (resolver instanceof RefreshableProviderMetadataResolver) {
            ((RefreshableProviderMetadataResolver) resolver).refresh();
        }
    }

    /** {@inheritDoc} */
    @Override
    public DateTime getLastRefresh() {
        if (resolver instanceof RefreshableProviderMetadataResolver) {
            return ((RefreshableProviderMetadataResolver) resolver).getLastRefresh();
        } else {
            return null;
        }
    }

    /** {@inheritDoc} */
    @Override
    public DateTime getLastUpdate() {
        if (resolver instanceof RefreshableProviderMetadataResolver) {
            return ((RefreshableProviderMetadataResolver) resolver).getLastUpdate();
        } else {
            return null;
        }
    }

    /** {@inheritDoc} */
    @Override
    public int compareTo(final ServiceableProviderMetadataProvider other) {
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
        if (!(other instanceof ServiceableProviderMetadataProvider)) {
            return false;
        }
        final ServiceableProviderMetadataProvider otherRp = (ServiceableProviderMetadataProvider) other;

        return Objects.equal(otherRp.sortKey, sortKey) && Objects.equal(getId(), otherRp.getId());
    }

    /** {@inheritDoc} */
    @Override
    public int hashCode() {
        return Objects.hashCode(sortKey, getId());
    }
}