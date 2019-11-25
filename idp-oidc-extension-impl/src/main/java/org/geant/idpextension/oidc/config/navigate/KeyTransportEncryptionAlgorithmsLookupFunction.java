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

package org.geant.idpextension.oidc.config.navigate;

import java.util.Collections;
import java.util.List;

import javax.annotation.Nullable;

import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.xmlsec.EncryptionConfiguration;

import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.idp.profile.context.navigate.AbstractRelyingPartyLookupFunction;

/**
 * A function that returns {@link EncryptionConfiguration#getKeyTransportEncryptionAlgorithms()} if it is available in
 * the security configuration of the profile configuration. The profile configuration is fetched from the
 * {@link RelyingPartyContext} obtained via a lookup function, by default a child of the {@link ProfileRequestContext}.
 * 
 * <p>
 * If a specific setting is unavailable, an empty list is returned.
 * </p>
 */
public class KeyTransportEncryptionAlgorithmsLookupFunction extends AbstractRelyingPartyLookupFunction<List<String>> {

    /** {@inheritDoc} */
    @Override
    @Nullable
    public List<String> apply(@Nullable final ProfileRequestContext input) {
        final RelyingPartyContext rpc = getRelyingPartyContextLookupStrategy().apply(input);
        if (rpc != null && rpc.getProfileConfig() != null
                && rpc.getProfileConfig().getSecurityConfiguration() != null) {
            final EncryptionConfiguration encryptionConfig =
                    rpc.getProfileConfig().getSecurityConfiguration().getEncryptionConfiguration();
            if (encryptionConfig != null && encryptionConfig.getKeyTransportEncryptionAlgorithms() != null) {
                return encryptionConfig.getKeyTransportEncryptionAlgorithms();
            }
        }
        return Collections.emptyList();
    }
}