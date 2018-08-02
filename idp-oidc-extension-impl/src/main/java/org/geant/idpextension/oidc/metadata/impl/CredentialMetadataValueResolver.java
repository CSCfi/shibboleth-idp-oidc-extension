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

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.annotation.Nonnull;

import org.geant.idpextension.oidc.metadata.resolver.MetadataValueResolver;
import org.geant.security.jwk.JWKCredential;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.SignatureSigningConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

import net.minidev.json.JSONArray;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.utilities.java.support.component.AbstractIdentifiableInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * An implementation to {@link DynamicMetadataValueResolver} that converts public parts of the attached
 * {@link Credential} to the value.
 */
public class CredentialMetadataValueResolver extends AbstractIdentifiableInitializableComponent
        implements MetadataValueResolver {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(CredentialMetadataValueResolver.class);

    /**
     * Strategy used to locate the {@link RelyingPartyContext} associated with a given {@link ProfileRequestContext}.
     */
    @Nonnull
    private Function<ProfileRequestContext, RelyingPartyContext> relyingPartyContextLookupStrategy;

    public CredentialMetadataValueResolver() {
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
     * Set the credential to be resolved as JSON.
     * 
     * @param credential What to set.
     */
    public JWK parseJwkCredential(final Credential credential) {
        Constraint.isNotNull(credential, "Credential cannot be null!");
        final PublicKey publicKey = credential.getPublicKey();
        String kid = credential instanceof JWKCredential ? ((JWKCredential) credential).getKid() : null;
        final KeyUse use;
        switch (credential.getUsageType()) {
            case SIGNING:
                use = KeyUse.SIGNATURE;
                break;
            case ENCRYPTION:
                use = KeyUse.ENCRYPTION;
                break;
            default:
                use = null;
        }
        final JWK jwk;
        if (publicKey instanceof RSAPublicKey) {
            final RSAKey.Builder builder = new RSAKey.Builder((RSAPublicKey) publicKey).keyID(kid).keyUse(use);
            if (credential instanceof JWKCredential) {
                builder.algorithm(((JWKCredential) credential).getAlgorithm());
            }
            jwk = builder.build();
        } else if (publicKey instanceof ECPublicKey) {
            final Curve curve = Curve.forECParameterSpec(((ECPublicKey) publicKey).getParams());
            final ECKey.Builder builder = new ECKey.Builder(curve, (ECPublicKey) publicKey);
            if (credential instanceof JWKCredential) {
                builder.algorithm(((JWKCredential) credential).getAlgorithm());
            }
            jwk = builder.build();
        } else {
            // TODO: support other algorithms
            log.warn("Unsupported public key {}", publicKey.getAlgorithm());
            throw new ConstraintViolationException("Unsupported public key algorithm");
        }
        return jwk;
    }

    /** {@inheritDoc} */
    @Override
    public Iterable<Object> resolve(ProfileRequestContext profileRequestContext) throws ResolverException {
        final List<Object> result = new ArrayList<>();

        RelyingPartyContext rpCtx = relyingPartyContextLookupStrategy.apply(profileRequestContext);
        if (rpCtx == null || rpCtx.getProfileConfig() == null
                || rpCtx.getProfileConfig().getSecurityConfiguration() == null) {
            log.warn("Could not find security configuration, nothing to do");
            return result;
        }

        // currently only signing keys are included
        SignatureSigningConfiguration signingConfig =
                rpCtx.getProfileConfig().getSecurityConfiguration().getSignatureSigningConfiguration();
        List<Credential> credentials = signingConfig.getSigningCredentials();
        JSONArray jwkCredentials = new JSONArray();
        for (Credential credential : credentials) {
            try {
                jwkCredentials.add(parseJwkCredential(credential).toJSONObject());
            } catch (ConstraintViolationException e) {
                log.warn("Ignoring key from the resulting list", e);
            }
        }
        result.add(jwkCredentials);
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
