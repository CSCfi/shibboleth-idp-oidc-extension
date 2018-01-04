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
import java.util.Iterator;
import java.util.Timer;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.geant.idpextension.oidc.criterion.IssuerCriterion;
import org.geant.idpextension.oidc.metadata.resolver.ProviderMetadataResolver;
import org.geant.idpextension.oidc.metadata.resolver.RefreshableProviderMetadataResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * Based on {@link org.opensaml.saml.metadata.resolver.impl.FilesystemMetadataResolver}.
 */
public class FilesystemProviderMetadataResolver extends AbstractFileOIDCEntityResolver<Issuer, OIDCProviderMetadata>
        implements ProviderMetadataResolver, RefreshableProviderMetadataResolver {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(FilesystemProviderMetadataResolver.class);

    /**
     * Constructor.
     * 
     * @param metadata the metadata file
     * 
     * @throws ResolverException this exception is no longer thrown
     */
    public FilesystemProviderMetadataResolver(@Nonnull final File metadata) throws ResolverException {
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
    public FilesystemProviderMetadataResolver(@Nullable final Timer backgroundTaskTimer, @Nonnull final File metadata)
            throws ResolverException {
        super(backgroundTaskTimer, metadata);
    }

    /** {@inheritDoc} */
    @Override
    public Iterable<OIDCProviderMetadata> resolve(CriteriaSet criteria) throws ResolverException {
        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);

        final IssuerCriterion issuerCriterion = criteria.get(IssuerCriterion.class);
        if (issuerCriterion == null || issuerCriterion.getIssuer() == null) {
            log.trace("No issuer criteria found, returning all");
            return getBackingStore().getOrderedInformation();
        }
        // TODO: support other criterion
        return lookupIdentifier(issuerCriterion.getIssuer());
    }

    /** {@inheritDoc} */
    @Override
    public OIDCProviderMetadata resolveSingle(CriteriaSet criteria) throws ResolverException {
        final Iterable<OIDCProviderMetadata> iterable = resolve(criteria);
        if (iterable != null) {
            final Iterator<OIDCProviderMetadata> iterator = iterable.iterator();
            if (iterator != null && iterator.hasNext()) {
                return iterator.next();
            }
        }
        log.warn("Could not find any clients with the given criteria");
        return null;
    }

    /** {@inheritDoc} */
    @Override
    protected OIDCProviderMetadata parse(byte[] bytes) throws ParseException {
        return OIDCProviderMetadata.parse(JSONObjectUtils.parse(new String(bytes)));
    }

    /** {@inheritDoc} */
    @Override
    protected Issuer getKey(OIDCProviderMetadata value) {
        return value.getIssuer();
    }
}
