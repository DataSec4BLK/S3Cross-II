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

class InitLedgerWorkload extends WorkloadModuleBase {
    constructor() {
        super();
    }

    async initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext) {
        await super.initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext);

        // 从 roundArguments 读取静态输入参数
        this.ppStr = roundArguments.ppStr;
        this.gpStr = roundArguments.gpStr;
    }

    async submitTransaction() {
        const args = [this.ppStr, this.gpStr];

        const request = {
            contractId: 's3crossgs',
            contractFunction: 'InitLedger',
            invokerIdentity: 'User1',
            contractArguments: args,
            readOnly: false,
            channel: 'mychannel',
        };

        await this.sutAdapter.sendRequests(request);
    }
}

function createWorkloadModule() {
    return new InitLedgerWorkload();
}

module.exports.createWorkloadModule = createWorkloadModule;
