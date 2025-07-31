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
 * Caliper workload module for calling QueryPseudonymByPBK function.
 */
class QueryPseudonymByPBKWorkload extends WorkloadModuleBase {

    constructor() {
        super();
        this.pbkStrGroup = [
            'LydWx4R4SR7Hf5yMostiAhg9KCj0HAUiTJAfLWu06II=',
            '2dsU69aPLwBneEhPD2Qh9pTGOiVGfdkz/eDgA2fG+RQ=',
            '48WjILV3yjw+KqC0S0oaezzPJ4AoLuFwLkP3zHaX45I=',
            '0eqt33pKZTCDB0OATDWnPTA4nO0iXSKUO2eNd3WmSxw=',
            'APU25DMDySEmtSrRXBg4qQGK12Dld5dYrw/T3C9uRAk=',
            '0IxPWa/OsG8UJ9Ci4T95mERTzXzOn9lqxLKWqcE1dAI=',
            'Bb74JzzXxzUs5NhVYUuJMvmSQziANp96MXCltM4tJJA=',
            '5RYBF3Bjuy3N0HhwCl3GvXNL99tV9S0sZXouLGVQJh4=',
            'xAngjTUBSzlIDJbtSLryP1E+p3XRMQR7M+l06VDLrJ4=',
            'NToKrDc8XQJbh0BVZe0IXp0O4ylQnNYEmyhJGDc6byM='
        ];
    }

    async initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext) {
        await super.initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext);
    }

    async submitTransaction() {
        const pbk = this.pbkStrGroup[Math.floor(Math.random() * this.pbkStrGroup.length)];
        const request = {
            contractId: 's3crosszk',
            contractFunction: 'QueryPseudonymByPBK',
            invokerIdentity: 'User1',
            contractArguments: [pbk],
            readOnly: true
        };

        await this.sutAdapter.sendRequests(request);
    }
}

function createWorkloadModule() {
    return new QueryPseudonymByPBKWorkload();
}

module.exports.createWorkloadModule = createWorkloadModule;
