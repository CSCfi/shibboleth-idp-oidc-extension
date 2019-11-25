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

package org.geant.idpextension.oidc.profile.impl;

import javax.annotation.Nonnull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;

/**
 * Abstract class for actions performing actions on {@link UserInfoRequest} found via
 * {@link ProfileRequestContext#getInboundMessageContext()#getMessage()}.
 */
public abstract class AbstractOIDCUserInfoRequestAction extends AbstractOIDCRequestAction<UserInfoRequest> {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(AbstractOIDCUserInfoRequestAction.class);

    /**
     * Returns OIDC user info request.
     * 
     * @return request
     */
    public UserInfoRequest getUserInfoRequest() {
        return getRequest();
    }

}