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
