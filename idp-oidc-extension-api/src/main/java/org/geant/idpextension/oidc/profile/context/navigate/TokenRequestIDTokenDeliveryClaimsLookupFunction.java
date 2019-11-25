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

import javax.annotation.Nonnull;
import org.geant.idpextension.oidc.token.support.TokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;

/**
 * For Token end point.
 * 
 * A function that returns copy of token delivery claims meant only for id token via a lookup function. This lookup
 * locates delivery claims from token (Authorization Code / Access Token) for token request handling. If token delivery
 * claims are not available, null is returned.
 */
public class TokenRequestIDTokenDeliveryClaimsLookupFunction extends AbstractTokenClaimsLookupFunction<ClaimsSet> {

    /** {@inheritDoc} */
    @Override
    ClaimsSet doLookup(@Nonnull TokenClaimsSet tokenClaims) {
        return tokenClaims.getIDTokenDeliveryClaims();
    }

}