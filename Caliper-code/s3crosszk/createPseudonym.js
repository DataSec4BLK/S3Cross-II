/*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

'use strict';

const { WorkloadModuleBase } = require('@hyperledger/caliper-core');

/**
 * Caliper workload module for calling CreatePseudonym function.
 */
class CreatePseudonymWorkload extends WorkloadModuleBase {

    constructor() {
        super();
        this.proofStrGroup = [
            '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'
        ];
        this.witnessStrGroup = [
            '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'
        ];
    }

    async initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext) {
        await super.initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext);
    }

    async submitTransaction() {
        const index = Math.floor(Math.random() * this.proofStrGroup.length);
        const request = {
            contractId: 's3crosszk',
            contractFunction: 'CreatePseudonym',
            invokerIdentity: 'User1',
            contractArguments: [
                this.proofStrGroup[index],
                this.witnessStrGroup[index]
            ],
            readOnly: false
        };

        await this.sutAdapter.sendRequests(request);
    }
}

function createWorkloadModule() {
    return new CreatePseudonymWorkload();
}

module.exports.createWorkloadModule = createWorkloadModule;
