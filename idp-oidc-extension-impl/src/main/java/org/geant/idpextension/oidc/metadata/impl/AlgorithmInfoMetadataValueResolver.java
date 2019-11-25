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
import java.util.Iterator;
import java.util.List;

import javax.annotation.Nonnull;

import org.geant.idpextension.oidc.metadata.resolver.MetadataValueResolver;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.SignatureSigningConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;

import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.utilities.java.support.component.AbstractIdentifiableInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

public class AlgorithmInfoMetadataValueResolver extends AbstractIdentifiableInitializableComponent
        implements MetadataValueResolver {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(AlgorithmInfoMetadataValueResolver.class);

    /**
     * Strategy used to locate the {@link RelyingPartyContext} associated with a given {@link ProfileRequestContext}.
     */
    @Nonnull
    private Function<ProfileRequestContext, RelyingPartyContext> relyingPartyContextLookupStrategy;

    /**
     * Whether to resolve data and key transport encryption algorithms. Defaults to false, when signature algorithms
     * are resolved.
     */
    private boolean resolveEncryptionAlgs = false;
    
    /**
     * Whether to resolve key transport encryption algorithms. Defaults to false, when data encryption algorithms are 
     * resolved. This flag is only used when resolveEncryptionAlgs is enabled.
     */
    private boolean resolveKeyTransportEncAlgs = false;

    public AlgorithmInfoMetadataValueResolver() {
        relyingPartyContextLookupStrategy = new ChildContextLookup<>(RelyingPartyContext.class);
    }

    /**
     * Set the strategy used to locate the {@link RelyingPartyContext} associated with a given
     * {@link ProfileRequestContext}.
     * 
     * @param strategy strategy used to locate the {@link RelyingPartyContext} associated with a given
     *            {@link ProfileRequestContext}
     */
    public void setRelyingPartyContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, RelyingPartyContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        relyingPartyContextLookupStrategy =
                Constraint.isNotNull(strategy, "RelyingPartyContext lookup strategy cannot be null");
    }

    /**
     * Set whether to resolve data encryption algorithms. When set to false, signature algorithms are resolved.
     * 
     * @param flag What to set.
     */
    public void setResolveEncryptionAlgs(final boolean flag) {
        resolveEncryptionAlgs = flag;
    }
    
    /**
     * Set whether to resolve key transport algorithms. Defaults to false, when data encryption algorithms are
     * resolved. In any case, resolveEncryptionAlgs must be enabled.
     * 
     * @param flag What to set.
     */
    public void setResolveKeyTransportEncAlgs(final boolean flag) {
        resolveKeyTransportEncAlgs = flag;
    }

    /** {@inheritDoc} */
    @Override
    public Iterable<Object> resolve(ProfileRequestContext profileRequestContext) throws ResolverException {
        final List<Object> result = new ArrayList<>();

        final RelyingPartyContext rpCtx = relyingPartyContextLookupStrategy.apply(profileRequestContext);
        if (rpCtx == null || rpCtx.getProfileConfig() == null
                || rpCtx.getProfileConfig().getSecurityConfiguration() == null) {
            log.warn("Could not find security configuration, nothing to do");
            return result;
        }
        final List<String> algorithms;
        if (resolveEncryptionAlgs) {
            final EncryptionConfiguration encryptionConfig =
                    rpCtx.getProfileConfig().getSecurityConfiguration().getEncryptionConfiguration();
            if (encryptionConfig != null) {
                if (resolveKeyTransportEncAlgs) {
                    algorithms = encryptionConfig.getKeyTransportEncryptionAlgorithms();
                } else {
                    algorithms = encryptionConfig.getDataEncryptionAlgorithms();
                }
            } else {
                algorithms = new ArrayList<String>();
            }
        } else {
            final SignatureSigningConfiguration signingConfig =
                    rpCtx.getProfileConfig().getSecurityConfiguration().getSignatureSigningConfiguration();
            if (signingConfig != null) {
                algorithms = signingConfig.getSignatureAlgorithms();
            } else {
                algorithms = new ArrayList<String>();
            }
        }
        result.add(algorithms);
        return result;
    }

    /** {@inheritDoc} */
    @Override
    public Object resolveSingle(ProfileRequestContext profileRequestContext) throws ResolverException {
        Iterator<Object> iterator = resolve(profileRequestContext).iterator();
        if (iterator.hasNext()) {
            return iterator.next();
        } else {
            return null;
        }
    }
}
