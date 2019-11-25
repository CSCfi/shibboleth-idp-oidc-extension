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

package org.geant.idpextension.oidc.metadata.resolver;

import javax.annotation.Nullable;

import org.joda.time.DateTime;

import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * Specialization of {@link ClientInformationResolver} that supports on-demand refresh.
 */
public interface RefreshableClientInformationResolver extends ClientInformationResolver {

    /**
     * Refresh the data exposed by the resolver.
     * 
     * <p>
     * An implementation of this method should typically be either <code>synchronized</code>
     * or make use other locking mechanisms to protect against concurrent access.
     * </p>
     * 
     * @throws ResolverException if the refresh operation was unsuccessful
     */
    void refresh() throws ResolverException;

    /**
     * Gets the time the last refresh cycle occurred.
     * 
     * @return time the last refresh cycle occurred
     */
    @Nullable DateTime getLastRefresh();

    /**
     * Get the time that the currently available client information was last updated. Note, this may be different than
     * the time retrieved by {@link #getLastRefresh()} is the client information was known not to have changed during
     * the last refresh cycle.
     * 
     * @return time when the currently client information was last updated, null if it has never successfully been read
     * in
     */
    @Nullable DateTime getLastUpdate();

}