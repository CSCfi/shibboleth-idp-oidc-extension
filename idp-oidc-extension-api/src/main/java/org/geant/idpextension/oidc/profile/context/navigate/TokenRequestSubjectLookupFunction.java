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

/**
 * For Token and UserInfo end points.
 * 
 * A function that returns subject claims via a lookup function. This lookup locates subject from token (Authorization
 * Code / Access Token) for token request handling. If subject is not available, null is returned.
 */
public class TokenRequestSubjectLookupFunction extends AbstractTokenClaimsLookupFunction<String> {

    /** {@inheritDoc} */
    @Override
    String doLookup(@Nonnull TokenClaimsSet tokenClaims) {
        return tokenClaims.getClaimsSet().getSubject();
    }

}