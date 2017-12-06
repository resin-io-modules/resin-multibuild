import * as Promise from 'bluebird';
import * as Dockerode from 'dockerode';
import * as _ from 'lodash';
import { Builder, BuildHooks } from 'resin-docker-build';
import * as Stream from 'stream';

import { BuildTask, Dict } from './build-task';
import { BuildProcessError } from './errors';
import { pullExternal } from './external';
import { LocalImage } from './local-image';

function taskHooks(
	task: BuildTask,
	docker: Dockerode,
	resolve: (image: LocalImage) => void,
): BuildHooks {
	return {
		buildSuccess: (imageId: string, layers: string[]) => {
			Promise.try(() => {
				if (task.tag != null) {
					return Promise.resolve(docker.getImage(imageId).tag({ repo: task.tag, force: true }))
						.return(task.tag);
				} else {
					return imageId;
				}
			})
			.then((tag) => {
				const image = new LocalImage(docker, tag, task.serviceName, false, true);
				image.layers = layers;

				resolve(image);
			});
		},
		buildFailure: (error: Error, layers: string[]) => {
			const image = new LocalImage(
				docker,
				layers[layers.length  - 1],
				task.serviceName,
				false,
				false,
			);
			image.layers = layers;
			image.error = error;

			resolve(image);
		},
		buildStream: (stream: Stream.Duplex) => {
			if (_.isFunction(task.streamHook)) {
				task.streamHook(stream);
			}

			task.buildStream!.pipe(stream);
		},
	};
}

const generateBuildArgs = (task: BuildTask): { buildargs?: Dict<string> } => {
	return {
		buildargs: task.args,
	};
}

const generateLabels = (task: BuildTask): { labels?: Dict<string> } => {
	return {
		labels: task.labels,
	};
}

/**
 * Given a build task which is primed with the necessary input, perform either
 * a build or a docker pull, and return this as a LocalImage.
 *
 * @param task The build task to perform
 * @param docker The handle to the docker daemon
 * @return a promise which resolves to a LocalImage which points to the produced image
 */
export function runBuildTask(task: BuildTask, docker: Dockerode): Promise<LocalImage> {

	if (task.external) {
		// Handle this separately
		return pullExternal(task, docker);
	}

	return new Promise((resolve, reject) => {
		if (task.buildStream == null) {
			reject(new BuildProcessError('Null build stream on non-external image'));
			return;
		}

		let dockerOpts = task.dockerOpts || { };
		dockerOpts = _.merge(dockerOpts, generateBuildArgs(task), generateLabels(task));

		const builder = new Builder(docker);
		const hooks = taskHooks(task, docker, resolve);

		builder.createBuildStream(dockerOpts, hooks, reject);
	});

}