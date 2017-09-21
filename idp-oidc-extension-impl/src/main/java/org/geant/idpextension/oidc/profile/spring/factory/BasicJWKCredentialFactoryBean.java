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

package org.geant.idpextension.oidc.profile.spring.factory;

import java.io.IOException;
import java.io.InputStream;
import javax.annotation.Nonnull;
import org.opensaml.security.credential.UsageType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.FatalBeanException;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.core.io.Resource;
import java.security.PrivateKey;
import java.text.ParseException;
import java.util.List;
import net.shibboleth.idp.profile.spring.factory.AbstractCredentialFactoryBean;
import org.geant.security.jwk.BasicJWKCredential;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.google.common.io.ByteStreams;

/** factory bean for Basic JSON Web Keys (JWK). */
public class BasicJWKCredentialFactoryBean extends AbstractCredentialFactoryBean<BasicJWKCredential> {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(BasicJWKCredentialFactoryBean.class);

    /** Where the private key is to be found. */
    private Resource jwkResource;

    /**
     * Set the resource containing the private key.
     * 
     * @param res
     *            private key resource, never <code>null</code>
     */
    public void setJWKResource(@Nonnull final Resource res) {
        jwkResource = res;
    }

    /**
     * Get RSA/EC privatekey of JWK.
     * 
     * @param jwk
     *            containing private key
     * @return jwk private key
     * @throws JOSEException
     *             if private key parsing fails
     */
    private PrivateKey getPrivateKey(JWK jwk) throws JOSEException {
        if (jwk instanceof RSAKey) {
            return ((RSAKey) jwk).toPrivateKey();
        }
        if (jwk instanceof ECKey) {
            return ((ECKey) jwk).toPrivateKey();
        }
        log.error("{}: Unsupported KeyFile at {}", getConfigDescription(), jwkResource.getDescription());
        throw new FatalBeanException("Unsupported KeyFile at " + jwkResource.getDescription());
    }

    /**
     * Convert jwk key usage type to shibboleth usage type.
     * 
     * @param jwk
     *            containing usage type.
     * @return usage type.
     */
    private UsageType getUsageType(JWK jwk) {
        switch (jwk.getKeyUse()) {
        case ENCRYPTION:
            return UsageType.ENCRYPTION;
        case SIGNATURE:
            return UsageType.SIGNING;
        default:
            return UsageType.UNSPECIFIED;
        }
    }

    /** {@inheritDoc} */
    @Override
    protected BasicJWKCredential doCreateInstance() throws Exception {

        if (jwkResource == null) {
            log.error("{}: No JWK credential provided", getConfigDescription());
            throw new BeanCreationException("No JWK credential provided");
        }
        JWK jwk = null;
        BasicJWKCredential jwkCredential = null;
        try (InputStream is = jwkResource.getInputStream()) {
            jwk = JWK.parse(new String(ByteStreams.toByteArray(is)));
            jwkCredential = new BasicJWKCredential();
            jwkCredential.setPrivateKey(getPrivateKey(jwk));
        } catch (IOException | ParseException | JOSEException e) {
            log.error("{}: Could not decode KeyFile at {}: {}", getConfigDescription(), jwkResource.getDescription(), e);
            throw new FatalBeanException("Could not decode provided KeyFile " + jwkResource.getDescription(), e);
        }
        jwkCredential.setUsageType(getUsageType(jwk));
        jwkCredential.setEntityId(getEntityID());
        jwkCredential.setAlgorithm(jwk.getAlgorithm());
        jwkCredential.setKid(jwk.getKeyID());
        final List<String> keyNames = getKeyNames();
        if (keyNames != null) {
            jwkCredential.getKeyNames().addAll(keyNames);
        }
        return jwkCredential;
    }

    /** {@inheritDoc} */
    @Override
    public Class<?> getObjectType() {
        return BasicJWKCredential.class;
    }

}
