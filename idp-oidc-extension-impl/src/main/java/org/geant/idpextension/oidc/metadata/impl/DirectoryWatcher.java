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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static java.nio.file.StandardWatchEventKinds.*;

public class DirectoryWatcher implements Runnable {

	private final ExecutorService executorService = Executors.newSingleThreadExecutor();
	private Future<?> directoryWatcherFuture;

	/**
	 * Class logger.
	 */
	private final Logger log = LoggerFactory.getLogger(DirectoryWatcher.class);

	private final Path dir;
	private final WatchService watcher;
	private final WatchKey key;
	private final DirectoryWatcherEventListener<Path> eventListener;

	/**
	 * Creates a WatchService and registers the given directory
	 */
	public DirectoryWatcher(final Path dir, final DirectoryWatcherEventListener<Path> eventListener)
			throws IOException {
		this.dir = dir;
		this.watcher = FileSystems.getDefault().newWatchService();
		this.key = dir.register(watcher, ENTRY_CREATE, ENTRY_MODIFY, ENTRY_DELETE);
		this.eventListener = eventListener;
	}

	@Override
	public void run() {
		try {
			WatchKey key;
			while ((key = watcher.take()) != null) {
				if (this.key != key) {
					log.error("Unrecognized WatchKey for directory '" + dir.toAbsolutePath().toString() + "': " + key);
					continue;
				}

				for (final WatchEvent<?> _event : key.pollEvents()) {
					@SuppressWarnings("unchecked")
					WatchEvent<Path> event = (WatchEvent<Path>) _event;

					log.debug("Event occurred: Event{context=" + event.context() + ", kind=" + event.kind().name() + "}");

					final WatchEvent.Kind<?> kind = event.kind();
					final Path path = dir.resolve(event.context());

					if (path.toString().toLowerCase().endsWith(".json")) {
						if (kind == OVERFLOW) {
							continue;
						} else if (kind == ENTRY_CREATE) {
							eventListener.onCreate(path);
						} else if (kind == ENTRY_MODIFY) {
							eventListener.onModify(path);
						} else if (kind == ENTRY_DELETE) {
							eventListener.onDelete(path);
						} else {
							log.warn("Unrecognized event kind occurred: " + event.kind().name());
						}
					} else {
						log.debug("Skipping file: '" + path + "' (not a .json metadata file)");
					}
				}

				if (!key.reset()) {
					log.error("WatchKey is no longer valid, DirectoryWatcher for directory '" + dir.toAbsolutePath().toString() + "' will stop");
					break;
				}
			}
		} catch (final InterruptedException e) {
			log.warn("DirectoryWatcher for directory '" + dir.toAbsolutePath().toString() + "' threw an InterruptedException and will stop: " + e.getMessage());
		}
	}

	public void start() {
		log.debug("Starting DirectoryWatcher for directory '" + dir.toAbsolutePath().toString() + "'");
		this.directoryWatcherFuture = executorService.submit(this);
		executorService.shutdown();
		log.debug("Started DirectoryWatcher for directory '" + dir.toAbsolutePath().toString() + "'");
	}

	public void stop() {
		log.debug("Stopping DirectoryWatcher for directory '" + dir.toAbsolutePath().toString() + "'");
		if (this.key != null) {
			key.cancel();
		}
		try {
			watcher.close();
		} catch (final IOException e) {
			log.warn("DirectoryWatcher for directory '" + dir.toAbsolutePath().toString() + "' threw an IOException while stopping: " + e.getMessage());
		}

		if (directoryWatcherFuture != null) {
			try {
				executorService.awaitTermination(100, TimeUnit.MILLISECONDS);
			} catch (InterruptedException e) {
			}
			directoryWatcherFuture.cancel(true);
			executorService.shutdownNow();
		}
		log.debug("Stopped DirectoryWatcher for directory '" + dir.toAbsolutePath().toString() + "'");
	}
}
