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