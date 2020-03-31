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

package org.geant.idpextension.oidc.metadata.impl;

import org.geant.idpextension.oidc.metadata.resolver.RemoteJwkSetCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.FileSystemResource;

import java.io.File;
import java.nio.file.Path;
import java.util.Map;
import java.util.Timer;

/**
 * {@inheritDoc}.
 */
public class DirectoryWatcherPathEventHandler implements DirectoryWatcherEventHandler {

	/**
	 * Class logger.
	 */
	private final Logger log = LoggerFactory.getLogger(DirectoryWatcherPathEventHandler.class);

	/**
	 * Shared map to update on file changes.
	 */
	private final Map<String, FilesystemClientInformationResolver> map;

	/**
	 * RemoteJwkSetCache for new {@link FilesystemClientInformationResolver}s.
	 */
	private final RemoteJwkSetCache remoteJwkSetCache;

	/**
	 * Timer for new {@link FilesystemClientInformationResolver}s.
	 */
	private final Timer backgroundTaskTimer;

	/**
	 * keyFetchInterval for new {@link FilesystemClientInformationResolver}s.
	 */
	private final long keyFetchInterval;

	/**
	 * Default constructor.
	 *
	 * @param map                 shared map to update according to metadata file changes.
	 * @param remoteJwkSetCache   the {@link RemoteJwkSetCache} for new {@link FilesystemClientInformationResolver}.
	 * @param backgroundTaskTimer the {@link Timer} for new {@link FilesystemClientInformationResolver}.
	 * @param keyFetchInterval    the keyFetchInterval for new {@link FilesystemClientInformationResolver}.
	 */
	public DirectoryWatcherPathEventHandler(final Map<String, FilesystemClientInformationResolver> map,
	                                        final RemoteJwkSetCache remoteJwkSetCache,
	                                        final Timer backgroundTaskTimer,
	                                        final long keyFetchInterval) {
		this.map = map;
		this.remoteJwkSetCache = remoteJwkSetCache;
		this.backgroundTaskTimer = backgroundTaskTimer;
		this.keyFetchInterval = keyFetchInterval;
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * Initializes a new {@link FilesystemClientInformationResolver} for the newly created metadata file
	 * and adds them to the shared {@link DirectoryWatcherPathEventHandler#map}.
	 *
	 * @param path the absolute Path of the created metadata file.
	 */
	@Override
	public void onCreate(final Path path) {
		try {
			final String id = path.toString();
			final FilesystemClientInformationResolver resolver = new FilesystemClientInformationResolver(backgroundTaskTimer, new FileSystemResource(new File(id)));
			resolver.setRemoteJwkSetCache(remoteJwkSetCache);
			resolver.setKeyFetchInterval(keyFetchInterval);
			resolver.setId(id);
			resolver.initialize();
			map.put(id, resolver);
			log.debug("Added ned FilesystemClientInformationResolver for metadata file '" + path + "'");
		} catch (final Exception e) {
			log.error("Initializing a new FilesystemClientInformationResolver for metadata file '" + path + "' threw an Exception: " + e.getMessage());
		}
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * Simply calls {@link #onDelete(Path)} followed by {@link #onCreate(Path)} to re-initialize the modified metadata file.
	 *
	 * @param path the absolute Path of the modified metadata file.
	 */
	@Override
	public void onModify(final Path path) {
		onDelete(path);
		onCreate(path);
		log.debug("Updated FilesystemClientInformationResolver for metadata file '" + path + "'");
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * Destroys the existing {@link FilesystemClientInformationResolver} of the deleted metadata file
	 * and removes them from the shared {@link DirectoryWatcherPathEventHandler#map}.
	 *
	 * @param path the absolute Path of the deleted metadata file.
	 */
	@Override
	public void onDelete(final Path path) {
		try {
			final String id = path.toString();
			final FilesystemClientInformationResolver resolver = map.remove(id);
			resolver.destroy();
			log.debug("Removed FilesystemClientInformationResolver for metadata file '" + path + "'");
		} catch (final Exception e) {
			log.error("Destroying the FilesystemClientInformationResolver for metadata file '" + path + "' threw an Exception: " + e.getMessage());
		}
	}
}
