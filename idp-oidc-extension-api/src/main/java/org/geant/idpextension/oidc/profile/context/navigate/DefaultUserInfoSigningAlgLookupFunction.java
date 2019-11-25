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

package org.geant.idpextension.oidc.profile.context.navigate;

import javax.annotation.Nullable;
import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.opensaml.messaging.context.navigate.ContextDataLookupFunction;
import org.opensaml.profile.context.ProfileRequestContext;

import com.nimbusds.jose.JWSAlgorithm;

/** A function that returns registered userinfo signing algorithm from metadata. */
@SuppressWarnings("rawtypes")
public class DefaultUserInfoSigningAlgLookupFunction
        implements ContextDataLookupFunction<ProfileRequestContext, JWSAlgorithm> {

    /** {@inheritDoc} */
    @Override
    @Nullable
    public JWSAlgorithm apply(@Nullable final ProfileRequestContext input) {
        if (input == null || input.getInboundMessageContext() == null) {
            return null;
        }
        OIDCMetadataContext ctx = input.getInboundMessageContext().getSubcontext(OIDCMetadataContext.class, false);
        if (ctx == null || ctx.getClientInformation() == null || ctx.getClientInformation().getOIDCMetadata() == null) {
            return null;
        }
        return ctx.getClientInformation().getOIDCMetadata().getUserInfoJWSAlg();
    }

}