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
        this.ppkStrGroup = [
            'qWPZzpgj2P6Ks8UnKKshq8WJt5uwbhNbzAViv3xlYB4=',
            '1Ftq1+GWxrnWrYC6DxwfVnuIP9i08aHg/6gdeGn/6mA=',
            '6JCpp1jeBQmODNVAP94ZLAZMTXhkbY2WSB67NaMnNM8=',
            '3lcvxD6T4EyeeUzv3DOkF7F/tGGZIYu4bKqvUamB9bM=',
            'liLzsyJOOTNv8Xkl8oSqLUrmbYDL+TKNmRPL2E3qTBU=',
            'jC7D1KppmML5KdOPVe8CXc+468uZU4LnK3MKtOMaHmk=',
            'xbeZrIRrQii9PGd5HXbgUc9yVDeRLGO7KQOEh3D6Hp0=',
            'xUgDMD7VWp4/l+Ez5Lb854v4pWKGIuBB6Mk+sNiyvgY=',
            'xFUOczDv0RWAJ+XaDBL7XIax147piez17VFTRzvusdI=',
            '1qE/hu7hIwYGBTi1j547gDqmKZvFESuADXikLxdQvRY='
        ];
    }

    async initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext) {
        await super.initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext);
    }

    async submitTransaction() {
        const pbk = this.ppkStrGroup[Math.floor(Math.random() * this.ppkStrGroup.length)];
        const request = {
            contractId: 's3crossgs',
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
