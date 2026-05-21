// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract MNT4ProofSystemVerifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 5937362036783366961007189198028486669444578682504883114886767017400506491192;
    uint256 constant alphay  = 187781092113971561328670302067082867731225732202731841256961220300542335449;
    uint256 constant betax1  = 13229130920691482252775943752417219300067207193401210501540076277302133065439;
    uint256 constant betax2  = 17336912670099921946553147370146789579708293405480800665198126784535300942992;
    uint256 constant betay1  = 2550812987222943589242660811521296619945723755355372329404920951143509525218;
    uint256 constant betay2  = 121001444847551879434989098743288793914612733595045056212435686782005903321;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 12823787697315151723261453150138527028704972626319224426461821877343800789665;
    uint256 constant deltax2 = 13078257739299560956807066356976971054297136998832732014524012378037073603072;
    uint256 constant deltay1 = 3411723121489478593612020130869154379239043649551870075820476321288924613006;
    uint256 constant deltay2 = 11876200825983272997180239752724768675565503741429317873129741399457599324351;

    
    uint256 constant IC0x = 4617237843185317848588548521529102679105871521979661765641658047476295133007;
    uint256 constant IC0y = 12631262997990182302816119224114630926533449256183426928885978881636347730529;
    
    uint256 constant IC1x = 13562219862338701952067920876450815471829737093607379898650911404168707402877;
    uint256 constant IC1y = 1788623504461001897440885315113590061177785218770919768904004673144689422856;
    
    uint256 constant IC2x = 7433868019727273482303631202927505157900122990672016562384180884035553672311;
    uint256 constant IC2y = 5403297075833003652594016515242036154936652637845729331848260987819879977389;
    
    uint256 constant IC3x = 19683381477815932690914826981203003555026749213578575697460836168168336242476;
    uint256 constant IC3y = 2586677726623974811838398419026248069352236325242664487207877398341140414535;
    
    uint256 constant IC4x = 7691769789578667960858021226049232663667961492792042478550576677487226188158;
    uint256 constant IC4y = 9981978801123734109290554570253116817395310019543028979232482562686989802235;
    
    uint256 constant IC5x = 5221050508824028024214241277370599572894117568825488424644092032667514008350;
    uint256 constant IC5y = 18209027321699234970650917931700293714395024046199403792191317229125908403906;
    
    uint256 constant IC6x = 20608531413331269543049165607436420013267683657062703766435525889857223602917;
    uint256 constant IC6y = 2313748648758403026692395322502360915554771233282275955344612530982079173316;
    
    uint256 constant IC7x = 1085360367160480321826405258379234621640302288187908703356519319724318541367;
    uint256 constant IC7y = 2954273149832238796481191951816573541154685879819283144745184318427933955511;
    
    uint256 constant IC8x = 11230594738989591527488965326082051676617949425837671099629929743579430992890;
    uint256 constant IC8y = 3291312053602015706510029115009618468954661826369477675294347253908910571053;
    
    uint256 constant IC9x = 3326332866227998432073383193859418472294774037004778709456600005905433530995;
    uint256 constant IC9y = 10507494438809641535811683556881922485092005621071234253094932049416009162747;
    
    uint256 constant IC10x = 17619688387266992020354918625323704509490096923667932265064250129595390929812;
    uint256 constant IC10y = 18717605969555951143940920777419681027012470259309684215167818932928820815598;
    
    uint256 constant IC11x = 6778861452936656718333678354234471357388217446921422018640903425592418607594;
    uint256 constant IC11y = 13512224465918813578113210278567454155786089116617205041018002896972880601717;
    
    uint256 constant IC12x = 20440191879982578620197772247580799172220226277068866991170166064679274993062;
    uint256 constant IC12y = 7147994420666771514182793297656534603108080545326417255716697429675783220600;
    
    uint256 constant IC13x = 13936953535596312444214339348561921159685974724700377180461545011737371151640;
    uint256 constant IC13y = 6939438510454903162292627190708536646099570180695608269057881657468163249938;
    
    uint256 constant IC14x = 15095560659047452699362378685553500807118290912499537143800546698865921475183;
    uint256 constant IC14y = 8368396936406798585602272178659093026864807312252307009928373473631056237263;
    
    uint256 constant IC15x = 7354968134004788889817525403103134115785804502793517616263064744528902354707;
    uint256 constant IC15y = 13087880753180731434675299681993437522357098154411700318061765128977232158662;
    
    uint256 constant IC16x = 455152355004053863672901845921774118479135592698484846315744264448043087270;
    uint256 constant IC16y = 2469711481660813067418445928774755066559739224590544252663795767774033863201;
    
    uint256 constant IC17x = 5110748242208005123288545286810879063371488484449981948718823369732057478558;
    uint256 constant IC17y = 16740422751552876201840957969957273496288957546705624989672735356591062479257;
    
    uint256 constant IC18x = 12941303447592668053395574306023984333161721729885481482916202251330410106391;
    uint256 constant IC18y = 3476751280945004086850806302481230795034717202286024355594359610037600552870;
    
    uint256 constant IC19x = 3100709087202538510190240183923709802603325744159000670954705511197843497379;
    uint256 constant IC19y = 1731641053926674044901654912180083935261795055674442000960054513434305157207;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[19] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                
                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                
                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                
                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))
                
                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))
                
                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))
                
                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            
            checkField(calldataload(add(_pubSignals, 416)))
            
            checkField(calldataload(add(_pubSignals, 448)))
            
            checkField(calldataload(add(_pubSignals, 480)))
            
            checkField(calldataload(add(_pubSignals, 512)))
            
            checkField(calldataload(add(_pubSignals, 544)))
            
            checkField(calldataload(add(_pubSignals, 576)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
