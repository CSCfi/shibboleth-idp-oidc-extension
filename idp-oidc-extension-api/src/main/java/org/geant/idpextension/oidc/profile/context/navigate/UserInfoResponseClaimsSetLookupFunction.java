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
import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseContext;
import org.opensaml.messaging.context.navigate.ContextDataLookupFunction;
import org.opensaml.profile.context.ProfileRequestContext;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;

/** A function that returns user info claims set from response context. Null if not able to locate it. */
@SuppressWarnings("rawtypes")
public class UserInfoResponseClaimsSetLookupFunction
        implements ContextDataLookupFunction<ProfileRequestContext, ClaimsSet> {

    /** {@inheritDoc} */
    @Override
    @Nullable
    public ClaimsSet apply(@Nullable final ProfileRequestContext input) {
        if (input == null || input.getOutboundMessageContext() == null) {
            return null;
        }
        OIDCAuthenticationResponseContext ctx =
                input.getOutboundMessageContext().getSubcontext(OIDCAuthenticationResponseContext.class, false);
        if (ctx == null) {
            return null;
        }
        return ctx.getUserInfo();
    }

}