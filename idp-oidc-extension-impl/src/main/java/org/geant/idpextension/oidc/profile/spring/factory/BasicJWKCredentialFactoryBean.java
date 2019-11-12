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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.FatalBeanException;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.core.io.Resource;
import java.text.ParseException;
import java.util.List;
import net.shibboleth.idp.profile.spring.factory.AbstractCredentialFactoryBean;

import org.geant.idpextension.oidc.security.impl.CredentialConversionUtil;
import org.geant.security.jwk.BasicJWKCredential;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.KeyType;
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
     * @param res private key resource, never <code>null</code>
     */
    public void setJWKResource(@Nonnull final Resource res) {
        jwkResource = res;
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
            if (jwk.getKeyType() == KeyType.EC || jwk.getKeyType() == KeyType.RSA) {
                if (jwk.isPrivate()) {
                    jwkCredential.setPrivateKey(((AsymmetricJWK) jwk).toPrivateKey());
                }
                jwkCredential.setPublicKey(((AsymmetricJWK) jwk).toPublicKey());
            } else if (jwk.getKeyType() == KeyType.OCT) {
                jwkCredential.setSecretKey(((OctetSequenceKey) jwk).toSecretKey());
            } else {
                throw new FatalBeanException("Unsupported KeyFile at " + jwkResource.getDescription());
            }
        } catch (IOException | ParseException e) {
            log.error("{}: Could not decode KeyFile at {}: {}", getConfigDescription(), jwkResource.getDescription(),
                    e);
            throw new FatalBeanException("Could not decode provided KeyFile " + jwkResource.getDescription(), e);
        }
        jwkCredential.setUsageType(CredentialConversionUtil.getUsageType(jwk));
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
