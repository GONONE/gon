// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "txmempool.h"
#include <stdio.h>
#include "consensus/consensus.h"
#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "validation.h"
#include "policy/policy.h"
#include "policy/fees.h"
#include "reverse_iterator.h"
#include "streams.h"
#include "timedata.h"
#include "util.h"
#include "utilmoneystr.h"
#include "utiltime.h"
#include "utilstrencodings.h"
#include "net.h"
#include "univalue.h"

//Portgas
#include "netmessagemaker.h"
#include "poker/poker.h"
#include <map>

#define LOG_PRINT(msg) printf("log msg is : [ %s ] file is : %s  function is %s line is : %d\n",(msg),__FILE__,__FUNCTION__,__LINE__);

CTxMemPoolEntry::CTxMemPoolEntry(const CTransactionRef& _tx, const CAmount& _nFee,
                                 int64_t _nTime, unsigned int _entryHeight,
                                 bool _spendsCoinbase, int64_t _sigOpsCost, LockPoints lp):
    tx(_tx), nFee(_nFee), nTime(_nTime), entryHeight(_entryHeight),
    spendsCoinbase(_spendsCoinbase), sigOpCost(_sigOpsCost), lockPoints(lp)
{
    nTxWeight = GetTransactionWeight(*tx);
    nUsageSize = RecursiveDynamicUsage(tx);

    nCountWithDescendants = 1;
    nSizeWithDescendants = GetTxSize();
    nModFeesWithDescendants = nFee;

    feeDelta = 0;

    nCountWithAncestors = 1;
    nSizeWithAncestors = GetTxSize();
    nModFeesWithAncestors = nFee;
    nSigOpCostWithAncestors = sigOpCost;
}

CTxMemPoolEntry::CTxMemPoolEntry(const CTxMemPoolEntry& other)
{
    *this = other;
}

void CTxMemPoolEntry::UpdateFeeDelta(int64_t newFeeDelta)
{
    nModFeesWithDescendants += newFeeDelta - feeDelta;
    nModFeesWithAncestors += newFeeDelta - feeDelta;
    feeDelta = newFeeDelta;
}

void CTxMemPoolEntry::UpdateLockPoints(const LockPoints& lp)
{
    lockPoints = lp;
}

size_t CTxMemPoolEntry::GetTxSize() const
{
    return GetVirtualTransactionSize(nTxWeight, sigOpCost);
}

// Update the given tx for any in-mempool descendants.
// Assumes that setMemPoolChildren is correct for the given tx and all
// descendants.
void CTxMemPool::UpdateForDescendants(txiter updateIt, cacheMap &cachedDescendants, const std::set<uint256> &setExclude)
{
    setEntries stageEntries, setAllDescendants;
    stageEntries = GetMemPoolChildren(updateIt);

    while (!stageEntries.empty()) {
        const txiter cit = *stageEntries.begin();
        setAllDescendants.insert(cit);
        stageEntries.erase(cit);
        const setEntries &setChildren = GetMemPoolChildren(cit);
        for (const txiter childEntry : setChildren) {
            cacheMap::iterator cacheIt = cachedDescendants.find(childEntry);
            if (cacheIt != cachedDescendants.end()) {
                // We've already calculated this one, just add the entries for this set
                // but don't traverse again.
                for (const txiter cacheEntry : cacheIt->second) {
                    setAllDescendants.insert(cacheEntry);
                }
            } else if (!setAllDescendants.count(childEntry)) {
                // Schedule for later processing
                stageEntries.insert(childEntry);
            }
        }
    }
    // setAllDescendants now contains all in-mempool descendants of updateIt.
    // Update and add to cached descendant map
    int64_t modifySize = 0;
    CAmount modifyFee = 0;
    int64_t modifyCount = 0;
    for (txiter cit : setAllDescendants) {
        if (!setExclude.count(cit->GetTx().GetHash())) {
            modifySize += cit->GetTxSize();
            modifyFee += cit->GetModifiedFee();
            modifyCount++;
            cachedDescendants[updateIt].insert(cit);
            // Update ancestor state for each descendant
            mapTx.modify(cit, update_ancestor_state(updateIt->GetTxSize(), updateIt->GetModifiedFee(), 1, updateIt->GetSigOpCost()));
        }
    }
    mapTx.modify(updateIt, update_descendant_state(modifySize, modifyFee, modifyCount));
}

// vHashesToUpdate is the set of transaction hashes from a disconnected block
// which has been re-added to the mempool.
// for each entry, look for descendants that are outside vHashesToUpdate, and
// add fee/size information for such descendants to the parent.
// for each such descendant, also update the ancestor state to include the parent.
void CTxMemPool::UpdateTransactionsFromBlock(const std::vector<uint256> &vHashesToUpdate)
{
    LOCK(cs);
    // For each entry in vHashesToUpdate, store the set of in-mempool, but not
    // in-vHashesToUpdate transactions, so that we don't have to recalculate
    // descendants when we come across a previously seen entry.
    cacheMap mapMemPoolDescendantsToUpdate;

    // Use a set for lookups into vHashesToUpdate (these entries are already
    // accounted for in the state of their ancestors)
    std::set<uint256> setAlreadyIncluded(vHashesToUpdate.begin(), vHashesToUpdate.end());

    // Iterate in reverse, so that whenever we are looking at a transaction
    // we are sure that all in-mempool descendants have already been processed.
    // This maximizes the benefit of the descendant cache and guarantees that
    // setMemPoolChildren will be updated, an assumption made in
    // UpdateForDescendants.
    for (const uint256 &hash : reverse_iterate(vHashesToUpdate)) {
        // we cache the in-mempool children to avoid duplicate updates
        setEntries setChildren;
        // calculate children from mapNextTx
        txiter it = mapTx.find(hash);
        if (it == mapTx.end()) {
            continue;
        }
        auto iter = mapNextTx.lower_bound(COutPoint(hash, 0));
        // First calculate the children, and update setMemPoolChildren to
        // include them, and update their setMemPoolParents to include this tx.
        for (; iter != mapNextTx.end() && iter->first->hash == hash; ++iter) {
            const uint256 &childHash = iter->second->GetHash();
            txiter childIter = mapTx.find(childHash);
            assert(childIter != mapTx.end());
            // We can skip updating entries we've encountered before or that
            // are in the block (which are already accounted for).
            if (setChildren.insert(childIter).second && !setAlreadyIncluded.count(childHash)) {
                UpdateChild(it, childIter, true);
                UpdateParent(childIter, it, true);
            }
        }
        UpdateForDescendants(it, mapMemPoolDescendantsToUpdate, setAlreadyIncluded);
    }
}

bool CTxMemPool::CalculateMemPoolAncestors(const CTxMemPoolEntry &entry, setEntries &setAncestors, uint64_t limitAncestorCount, uint64_t limitAncestorSize, uint64_t limitDescendantCount, uint64_t limitDescendantSize, std::string &errString, bool fSearchForParents /* = true */) const
{
    LOCK(cs);

    setEntries parentHashes;
    const CTransaction &tx = entry.GetTx();

    if (fSearchForParents) {
        // Get parents of this transaction that are in the mempool
        // GetMemPoolParents() is only valid for entries in the mempool, so we
        // iterate mapTx to find parents.
        for (unsigned int i = 0; i < tx.vin.size(); i++) {
            txiter piter = mapTx.find(tx.vin[i].prevout.hash);
            if (piter != mapTx.end()) {
                parentHashes.insert(piter);
                if (parentHashes.size() + 1 > limitAncestorCount) {
                    errString = strprintf("too many unconfirmed parents [limit: %u]", limitAncestorCount);
                    return false;
                }
            }
        }
    } else {
        // If we're not searching for parents, we require this to be an
        // entry in the mempool already.
        txiter it = mapTx.iterator_to(entry);
        parentHashes = GetMemPoolParents(it);
    }

    size_t totalSizeWithAncestors = entry.GetTxSize();

    while (!parentHashes.empty()) {
        txiter stageit = *parentHashes.begin();

        setAncestors.insert(stageit);
        parentHashes.erase(stageit);
        totalSizeWithAncestors += stageit->GetTxSize();

        if (stageit->GetSizeWithDescendants() + entry.GetTxSize() > limitDescendantSize) {
            errString = strprintf("exceeds descendant size limit for tx %s [limit: %u]", stageit->GetTx().GetHash().ToString(), limitDescendantSize);
            return false;
        } else if (stageit->GetCountWithDescendants() + 1 > limitDescendantCount) {
            errString = strprintf("too many descendants for tx %s [limit: %u]", stageit->GetTx().GetHash().ToString(), limitDescendantCount);
            return false;
        } else if (totalSizeWithAncestors > limitAncestorSize) {
            errString = strprintf("exceeds ancestor size limit [limit: %u]", limitAncestorSize);
            return false;
        }

        const setEntries & setMemPoolParents = GetMemPoolParents(stageit);
        for (const txiter &phash : setMemPoolParents) {
            // If this is a new ancestor, add it.
            if (setAncestors.count(phash) == 0) {
                parentHashes.insert(phash);
            }
            if (parentHashes.size() + setAncestors.size() + 1 > limitAncestorCount) {
                errString = strprintf("too many unconfirmed ancestors [limit: %u]", limitAncestorCount);
                return false;
            }
        }
    }

    return true;
}

void CTxMemPool::UpdateAncestorsOf(bool add, txiter it, setEntries &setAncestors)
{
    setEntries parentIters = GetMemPoolParents(it);
    // add or remove this tx as a child of each parent
    for (txiter piter : parentIters) {
        UpdateChild(piter, it, add);
    }
    const int64_t updateCount = (add ? 1 : -1);
    const int64_t updateSize = updateCount * it->GetTxSize();
    const CAmount updateFee = updateCount * it->GetModifiedFee();
    for (txiter ancestorIt : setAncestors) {
        mapTx.modify(ancestorIt, update_descendant_state(updateSize, updateFee, updateCount));
    }
}

void CTxMemPool::UpdateEntryForAncestors(txiter it, const setEntries &setAncestors)
{
    int64_t updateCount = setAncestors.size();
    int64_t updateSize = 0;
    CAmount updateFee = 0;
    int64_t updateSigOpsCost = 0;
    for (txiter ancestorIt : setAncestors) {
        updateSize += ancestorIt->GetTxSize();
        updateFee += ancestorIt->GetModifiedFee();
        updateSigOpsCost += ancestorIt->GetSigOpCost();
    }
    mapTx.modify(it, update_ancestor_state(updateSize, updateFee, updateCount, updateSigOpsCost));
}

void CTxMemPool::UpdateChildrenForRemoval(txiter it)
{
    const setEntries &setMemPoolChildren = GetMemPoolChildren(it);
    for (txiter updateIt : setMemPoolChildren) {
        UpdateParent(updateIt, it, false);
    }
}

void CTxMemPool::UpdateForRemoveFromMempool(const setEntries &entriesToRemove, bool updateDescendants)
{
    // For each entry, walk back all ancestors and decrement size associated with this
    // transaction
    const uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
    if (updateDescendants) {
        // updateDescendants should be true whenever we're not recursively
        // removing a tx and all its descendants, eg when a transaction is
        // confirmed in a block.
        // Here we only update statistics and not data in mapLinks (which
        // we need to preserve until we're finished with all operations that
        // need to traverse the mempool).
        for (txiter removeIt : entriesToRemove) {
            setEntries setDescendants;
            CalculateDescendants(removeIt, setDescendants);
            setDescendants.erase(removeIt); // don't update state for self
            int64_t modifySize = -((int64_t)removeIt->GetTxSize());
            CAmount modifyFee = -removeIt->GetModifiedFee();
            int modifySigOps = -removeIt->GetSigOpCost();
            for (txiter dit : setDescendants) {
                mapTx.modify(dit, update_ancestor_state(modifySize, modifyFee, -1, modifySigOps));
            }
        }
    }
    for (txiter removeIt : entriesToRemove) {
        setEntries setAncestors;
        const CTxMemPoolEntry &entry = *removeIt;
        std::string dummy;
        // Since this is a tx that is already in the mempool, we can call CMPA
        // with fSearchForParents = false.  If the mempool is in a consistent
        // state, then using true or false should both be correct, though false
        // should be a bit faster.
        // However, if we happen to be in the middle of processing a reorg, then
        // the mempool can be in an inconsistent state.  In this case, the set
        // of ancestors reachable via mapLinks will be the same as the set of
        // ancestors whose packages include this transaction, because when we
        // add a new transaction to the mempool in addUnchecked(), we assume it
        // has no children, and in the case of a reorg where that assumption is
        // false, the in-mempool children aren't linked to the in-block tx's
        // until UpdateTransactionsFromBlock() is called.
        // So if we're being called during a reorg, ie before
        // UpdateTransactionsFromBlock() has been called, then mapLinks[] will
        // differ from the set of mempool parents we'd calculate by searching,
        // and it's important that we use the mapLinks[] notion of ancestor
        // transactions as the set of things to update for removal.
        CalculateMemPoolAncestors(entry, setAncestors, nNoLimit, nNoLimit, nNoLimit, nNoLimit, dummy, false);
        // Note that UpdateAncestorsOf severs the child links that point to
        // removeIt in the entries for the parents of removeIt.
        UpdateAncestorsOf(false, removeIt, setAncestors);
    }
    // After updating all the ancestor sizes, we can now sever the link between each
    // transaction being removed and any mempool children (ie, update setMemPoolParents
    // for each direct child of a transaction being removed).
    for (txiter removeIt : entriesToRemove) {
        UpdateChildrenForRemoval(removeIt);
    }
}

void CTxMemPoolEntry::UpdateDescendantState(int64_t modifySize, CAmount modifyFee, int64_t modifyCount)
{
    nSizeWithDescendants += modifySize;
    assert(int64_t(nSizeWithDescendants) > 0);
    nModFeesWithDescendants += modifyFee;
    nCountWithDescendants += modifyCount;
    assert(int64_t(nCountWithDescendants) > 0);
}

void CTxMemPoolEntry::UpdateAncestorState(int64_t modifySize, CAmount modifyFee, int64_t modifyCount, int modifySigOps)
{
    nSizeWithAncestors += modifySize;
    assert(int64_t(nSizeWithAncestors) > 0);
    nModFeesWithAncestors += modifyFee;
    nCountWithAncestors += modifyCount;
    assert(int64_t(nCountWithAncestors) > 0);
    nSigOpCostWithAncestors += modifySigOps;
    assert(int(nSigOpCostWithAncestors) >= 0);
}

CTxMemPool::CTxMemPool(CBlockPolicyEstimator* estimator) :
    nTransactionsUpdated(0), minerPolicyEstimator(estimator)
{
    _clear(); //lock free clear

    // Sanity checks off by default for performance, because otherwise
    // accepting transactions becomes O(N^2) where N is the number
    // of transactions in the pool
    nCheckFrequency = 0;
}

bool CTxMemPool::isSpent(const COutPoint& outpoint)
{
    LOCK(cs);
    return mapNextTx.count(outpoint);
}

unsigned int CTxMemPool::GetTransactionsUpdated() const
{
    LOCK(cs);
    return nTransactionsUpdated;
}

void CTxMemPool::AddTransactionsUpdated(unsigned int n)
{
    LOCK(cs);
    nTransactionsUpdated += n;
}

// 	add   to  tmcg
std::map<std::string, std::string> gMapAddress;
std::vector< CTransaction> vTxIpVerify; //40
std::vector< CTransaction> vTxNewAddressVerify; //41
std::vector< CTransaction> vTxPublicAddressVerify; //42
std::vector< CTransaction> vTxPokerBalanceVerify; //43
std::vector< CTransaction> vTxPokerHandleVerify; //44
std::vector< CTransaction> vTxPokerDlogVerify; //45 // not use
std::vector< CTransaction> vTxPokerPubkeyVerify; //46
std::vector< CTransaction> vTxPokerSshVerify; //47
std::vector< CTransaction> vTxPokerShuffleVerify; //49
std::vector< CTransaction> vTxPokerHandleCardVerify; //51
std::vector< CTransaction> vTxPokerFlopCardVerify; //53
std::vector< CTransaction> vTxPokerOpenHandVerify; //55
std::vector< CTransaction> vTxDepositVerify; //70
std::vector< CTransaction> vTxBetVerify; //80
std::vector< MsgTimeOut > vMsgTimeOut;
std::vector< CTransaction> vTxTimeOut; //

std::vector< CTransaction > vTxMatchPlayer;

std::multimap<std::string, CTransaction> vTxBetPlayer;
std::map<std::string, CTransaction> vTxDepositPlayer;


void saveTxBet(std::string &ip,const CTransaction &tx)
{
	// if(!vTxBetVerify.empty())
	// {
		// const std::string preHash = vTxBetVerify.at(vTxBetVerify.size() - 1).GetHash().ToString();
		// const MsgNode &node = g_tmcg->RecvMsg[preHash];

		// if(node.NextIndex != g_tmcg->nodeIndexMap[ip])
		// {
			// std::cout << "无效交易 游戏结束  " << ip << " index : " << node.NextIndex << " map index : " << g_tmcg->nodeIndexMap[ip] << std::endl;
			// return ;
		// }
		// // int tempIndex = -1;
		// // int tempAmount = -1;
		// // pokerhistory(tempIndex,tempAmount);
	// }
	vTxBetVerify.push_back(tx);
	vTxBetPlayer.insert(std::make_pair(ip,tx));
	return ;
}

void saveTxDeposit(std::string &ip,const CTransaction &tx)
{
	vTxDepositVerify.push_back(tx);
	vTxDepositPlayer.insert(std::make_pair(ip, tx));
	return ;
}


//{"nextMatchNode":"120.27.232.146",
//{"nextMatchNode":"","matchTables":[{"tableTx":["607270827503c9ba521d251f46f11e8d3a45b1fbc0305af8279c717a18653ff3","7ecd053c909f63e0a02f59a0ac86c8c4e1994b864a24d0a2dcec4f39bb5d8b48"],"address":["1FUWUMywzAwiAFijC3WCzvNAkDuA2rmyjQ","18Rsi3hfGzMbi3PCLV6jPtL9MtiA3SyQsw"],"tableID":"768a99196b54609aa46f3a580b5690a7c8660eb7fb9e7a8e93c301f3b0f62c20","pokeraddress":"38jjm5AMPLY1udixybJPQWy45ca2sREXmE"}]}
void parseMatchJson(std::string & getResponseStr)
{
    json jsonMsg = json::parse(getResponseStr);
    // match node get ip
    if(jsonMsg.find("nextMatchNode") == jsonMsg.end() || jsonMsg.find("matchTables") == jsonMsg.end())// simple check --> replace other check
    {
        //error log
        std::cout << "json find error" << std::endl;
        return ;
    }

    if(!jsonMsg.at("matchTables").is_array())
    {
        // error log
        std::cout << " match is array error " <<std::endl;
        return ;
    }
    std::string nextMatchIp = jsonMsg.at("nextMatchNode").get<std::string>();
    json jsTables = jsonMsg.at("matchTables");
    std::map< std::string,std::vector<std::string > > mTableTx;
    std::map< std::string,std::string > mTxTab;
    for(auto & itObj : jsTables)
    {
        std::vector<std::string> v;
        std::string tabid = itObj.at("tableID").get<std::string>();
        // for(auto & it : itObj.at("tableTx"))
        // {
            // v.push_back(it);
            // mTxTab[it] = tabid;	
        // }
		
        for(size_t i = 0; i < itObj.at("tableTx").size(); i++)
        {
			auto it = itObj.at("tableTx").at(i);
            v.push_back(it);
            mTxTab[it] = tabid;
			
			g_tmcg->mPlayerIndex[it] = i;
			g_tmcg->mPlayerTxid[i] = it;
			 
			if (it == g_tmcg->matchTxID) {  
	            g_tmcg->myindex = i;
			}
        }
		
        mTableTx[tabid] = v;

		g_tmcg->playersize = itObj.at("tableTx").size();
		g_tmcg->pokeraddress = itObj.at("pokeraddress").get<std::string>();
		g_tmcg->fPokerAddressVerify = true;
    }
	
	g_tmcg->matchTableID = mTxTab[g_tmcg->matchTxID];
	
	std::cout << "myTabid: " << g_tmcg->matchTableID << std::endl;
	std::cout << "mytxid : " << g_tmcg->matchTxID << std::endl;
	std::cout << "myindex: " << g_tmcg->myindex << std::endl;
	std::cout << "g_tmcg->playersize: " << g_tmcg->playersize << std::endl;
	std::cout << "g_tmcg->pokeraddress: " << g_tmcg->pokeraddress << std::endl;
	std::cout << "g_tmcg->mPlayerIndex.size: " << g_tmcg->mPlayerIndex.size() << std::endl;

    std::vector< CTransaction > vTran;
    for(auto &tx : vTxMatchPlayer)
    {
        std::string txid = tx.GetHash().ToString();
        if(mTxTab.count(txid) == 0)
        {
            vTran.push_back(tx);
        }
    }
    vTxMatchPlayer.swap(vTran);
}

void parseNewAddressJson(std::string & getResponseStr)
{
    json jsonMsg = json::parse(getResponseStr);
    if( jsonMsg.find("txID") == jsonMsg.end() || jsonMsg.find("newaddress") == jsonMsg.end())
    {
        // error log
        //std::cout << "parseNewAddressJson find error " << std::endl;
        LOG_PRINT("parseNewAddressJson find error ")
        return ;
    }

    std::string tableid = jsonMsg["tableID"].get<std::string>();
    std::string txid = jsonMsg["txID"].get<std::string>();
    std::string newaddress  = jsonMsg["newaddress"].get<std::string>();

    if(g_tmcg->mPlayerIndex.count(txid) == 0)
    {
        //error log
        //std::cout << "player index not found " << "  __FUNCTION__  : "  << __FUNCTION__ << "  __LINE__  : " << __LINE__ << std::endl;
        LOG_PRINT("player index not found")
        return ;
    }
    if(g_tmcg->mMatchAddress.count(txid))
    {
        //repeat address
        std::cout << "repeat address" << std::endl;
        return ;
    }
    std::cout << "parseNewAddressJson tbaleID       : " << tableid << std::endl;
    std::cout << "parseNewAddressJson txid          : " << txid << std::endl;
    std::cout << "parseNewAddressJson newaddress    : " << newaddress << std::endl;
    g_tmcg->mMatchAddress[txid] = newaddress;
    std::cout << "parseNewAddressJson g_tmcg->mMatchAddress.size    : " << g_tmcg->mMatchAddress.size() << std::endl;
}

//{"tableID":"07e8b69b915e351c1353ca84d946daa11d467eec75cb877517d39c79acf4c94d",
//"txID":"20f17867c070a79fbb44fe1e4d5c891697adf3ecc4634dc154493196e0943a09",
//"pokeraddress":"3KzTGcz2T6s5sBd6QKteWTc9Z8Xc7wZCXw"}
void parsePokerAddressJson(std::string & getResponseStr)
{
    json jsonMsg = json::parse(getResponseStr);
    if( jsonMsg.find("txID") == jsonMsg.end() || jsonMsg.find("pokeraddress") == jsonMsg.end())// simple check --> replace other check
    {
        // error log
        //std::cout << "parsePokerAddressJson find error " << std::endl;
        LOG_PRINT("parsePokerAddressJson find error")
        return ;
    }

    std::string tableid = jsonMsg["tableID"].get<std::string>();
    std::string txid = jsonMsg["txID"].get<std::string>();
    std::string pokeraddress  = jsonMsg["pokeraddress"].get<std::string>();
    std::cout << "parsePokerAddressJson tbaleID       : " << tableid << std::endl;
    std::cout << "parsePokerAddressJson txid          : " << txid << std::endl;
    std::cout << "parsePokerAddressJson newaddress    : " << pokeraddress << std::endl;
    if(g_tmcg->mPlayerIndex.count(txid) == 0)
    {
        LOG_PRINT("player index not found")
        return ;
    }

	if(g_tmcg->mPokerAddress.count(txid))
    {
        //repeat address
        std::cout << "repeat poker address" << std::endl;
        return ;
    }
	g_tmcg->mPokerAddress[txid] = pokeraddress;

	if(g_tmcg->mPokerAddress.size() != (size_t) g_tmcg->playersize)
	{
		LOG_PRINT("g_tmcg->mPokerAddress.size() != g_tmcg->playersize")
		return;
	}

	for(auto &it: g_tmcg->mPokerAddress)
	{
		if(it.second != g_tmcg->pokeraddress)
		{
			LOG_PRINT("pokeraddress != g_tmcg->pokeraddress")
			return;
		}
	}

	g_tmcg->fPokerAddressVerify = true;
    LOG_PRINT("poker address successful")
}

//{"tableID":"511bfafb3d19376c73e9f59de646165511849b942a1917a0f505d4840f5f04e7",
//"txID":"5b1c542dfb25a8bf63dfdea7fc3fbfe63ff6737ea4b5fa322e4d1c2395a5e94f",
//"balance":1}
void parseBalanceJson(std::string &getResponseStr, const CTransaction &ctx)
{
    json jsonMsg = json::parse(getResponseStr);
    if( jsonMsg.find("txID") == jsonMsg.end() || jsonMsg.find("balance") == jsonMsg.end())
    {
        // error log
        //std::cout << "parseBalanceJson find error " << std::endl;
        LOG_PRINT("parseBalanceJson find error")
        return ;
    }
    std::string txid = jsonMsg["txID"].get<std::string>();
    int balance = jsonMsg["balance"].get<int>();

    if(g_tmcg->mPlayerIndex.count(txid) == 0)
    {
        //error log
        //std::cout << "player index not found " << std::endl;
        LOG_PRINT("player index not found")
        return ;
    }

    if(g_tmcg->mPokerBalance.count(txid))
    {
        // repeat tx
        std::cout << "repeat balance tx error" << std::endl;
        return ;
    }
    g_tmcg->mPokerBalance[txid] = balance;
    std::cout << "parseBalanceJson balance is : " << balance << std::endl;
    std::cout << "g_tmcg->mPokerBalance.size is : " << g_tmcg->mPokerBalance.size() << std::endl;

	//init gBetIpfsMsg
	if(g_tmcg->mPokerBalance.size() == (size_t) g_tmcg->playersize)
	{
		g_tmcg->initBetIpfsMsg(g_tmcg->gBetIpfsMsg);
	}

	g_tmcg->mPokerBalanceTx.insert(make_pair(txid, ctx));
}
//{"tableID":"fbbd6d408ecd7b7435d2685b8a0b133af9b64a42b0a95279c51c304ff032c5a1",
//"txID":"567fdc1f8b4ee161e62144bc2e1667f6d37f8532c09ee8e4ed8b71ffa2fcc7f6",
//"tmcg_handle":"STVpzWPXrh8V3TptbygBp8PJBa5XGmnJRq4r0GsLTDaOmT6KPCvCs7TbmmrSmvefmjr6GjrIsbVDEJXzBCDALS
//FrYMxsYq1kHC0psOWH498EJKnYva0IHJY4jzDNUHAtBfALAyflrMqOPLXQ0ec0PQehPd07Lc61c7J52PotexrgRRXwmLIR4Y4cI1K3k2
//xQFBpoNDtMVlJHbaOvjtmNPtpnxQZqP78trGvbh6T6HppS9KfRT2bzueiNvoAPeoEJngqEoW3mEAgWwwCrc67POjhe2Ljudoy2nCOtcjeVRC\n"}

void parseHandleJson(std::string & getResponseStr)
{
    json jsonMsg = json::parse(getResponseStr);
    if( jsonMsg.find("txID") == jsonMsg.end() || jsonMsg.find("tmcg_handle") == jsonMsg.end())// simple check --> replace other check
    {
        // error log
        //std::cout << "parseHandleJson find error " << std::endl;
        LOG_PRINT("parseHandleJson find error")
        return ;
    }
    std::string txid = jsonMsg["txID"].get<std::string>();
    std::string tmcg_handle = jsonMsg["tmcg_handle"].get<std::string>();

    if(g_tmcg->mPlayerIndex.count(txid) == 0)
    {
        //error log
        //std::cout << "player index not found " << std::endl;
        LOG_PRINT("player index not found")
        return ;
    }

    std::cout << "parseHandleJson balance is : " << tmcg_handle << std::endl;


    if(g_tmcg->isOne) return ;
    if(g_tmcg->vtmfOne) return ;
    if(!g_tmcg->vtmf_str.str().empty())
    {
        //repeat tmcg_handle
        std::cout << "repeat tmcg_handle" << std::endl;
        return ;
    }
    g_tmcg->PublishGroup(tmcg_handle);
    if(!g_tmcg->VTMF_dlog())
    {
        LOG_PRINT("init handle error")
        //LOG_PRINT
    }
    else
    {
        //std::cout << "init handle successful " << std::endl;
        LOG_PRINT("init handle successful ")
    }
}

//{"tableID":"fd421c05a27c068952616bec93892c1da187075de97394114ca34aa4c91ad35a",
//"txID":"5f6315ba10ca9921c8762c1d708ca99f3d756c2b45bbd3ab1d35399c70bf29eb",
//"tmcg_pubkey":"1Aee9fGrl8xVVGobtpFfrEbdz31jhnlf0axu5yRahuMvpiy9nRNuUM4fN9gaDbeM4swiuaMPWBGdvy
//TLru5cJyI\n3E8l8UT1mCfiAZ0DQozKyqyO5aO5SYHfdNsPFiHYdoR\n"}
void parsePubkeyJson(std::string & getResponseStr)
{
    json jsonMsg = json::parse(getResponseStr);
    if(jsonMsg.find("txID") == jsonMsg.end() || jsonMsg.find("tmcg_pubkey") == jsonMsg.end())// simple check --> replace other check
    {
        // error log
        std::cout << "parsePubkeyJson find error " << std::endl;
        return ;
    }
    std::string txid = jsonMsg["txID"].get<std::string>();
    std::string tmcg_pubkey = jsonMsg["tmcg_pubkey"].get<std::string>();

    if(g_tmcg->mPlayerIndex.count(txid) == 0)
    {
        //error log
        LOG_PRINT("player index not found ")
        return ;
    }

    std::cout << "parsePubkeyJson tmcg_pubkey is : " << tmcg_pubkey << std::endl;

    if(g_tmcg->mPubkeyVerify.count(txid) != 0)
    {
        //repeat pubkey verify
        std::cout << " repeat pubkey " << std::endl;
        return ;
    }

    g_tmcg->mPubkeyVerify[txid] = tmcg_pubkey;

    if(g_tmcg->mPubkeyVerify.size() == (size_t)g_tmcg->playersize)
    {
        for(auto & pubIt : g_tmcg->mPubkeyVerify)
        {
            if(pubIt.first == g_tmcg->matchTxID)// self
            {
                LOG_PRINT("self tx return")
                continue ;
            }

            if (!g_tmcg->verifyPubKey(pubIt.second))
			{
                LOG_PRINT("verifyPubKey error")
                LOG_PRINT("pubIt.second")
                return ;
			}
            LOG_PRINT("verifyPubKey successful")
        }
        g_tmcg->fAllPubkeyVerify = true;
        LOG_PRINT("g_tmcg->fAllPubkeyVerify is true")
    }
}


//{"tableID":"0f5097a23f3e8eff29feaf4ff3b28462d941b185adac50243e3b3b2e24fc996b",
//"txID":"4d0bf2c241d1b89457e8842608ab961ecef5947e47d73088711d4bc5998bf9d4",
//"handCards":[{"htxid":"567fdc1f8b4ee161e62144bc2e1667f6d37f8532c09ee8e4ed8b71ffa2fcc7f6",
//"hcard":["I7GZLZbqSsi1LmWtXIJ0cfRu0JDB1EgYolQNyQlnY45GxYJOBylbhRIPqIx6ETtqUSh27mMGuvIWVSYKyZ8LEuUlNIlcIupyMxcGbsa3O91RWy1gYXpiATIkJDUsQYx
//oXdDfn6Dja5\nmbz8rC3IomLAboSMGu85KEXlEVMBFPUinAYYJ2yeLnB\nAnGMpQRez3SJ6qet3SigIiHMXSuP65Q4aUskoaRshVb\ndsKYVrk7mmaSrwVtbqu2RHjf3TxGEz2DpdYHmt6QqKu\n"]}]}

void  parseHandCardsJson(std::string & getResponseStr)
{
    json jsonMsg = json::parse(getResponseStr);
    if(jsonMsg.find("txID") == jsonMsg.end() || jsonMsg.find("handCards") == jsonMsg.end())// simple check --> replace other check
    {
        // error log
        LOG_PRINT("parseHandCardsJson not found ")
        return ;
    }
    std::string txid = jsonMsg["txID"].get<std::string>();
    if(g_tmcg->mPlayerIndex.count(txid) == 0)
    {
        //error log
        LOG_PRINT("player index not found ")
        return ;
    }

    if(g_tmcg->matchTxID == txid)
    {
        // error log
        LOG_PRINT("self hand msg")
        return ;
    }
    if(g_tmcg->mHandCardVerify.count(txid))
    {
        //repeat handcard
        std::cout << "repeat hand card verify " << std::endl;
        return ;
    }
    if(!jsonMsg["handCards"].is_array())
    {
        //error log
        LOG_PRINT("handCards is not array ")
        return ;
    }

    std::map<int,std::string> mHandCardMsg;

    auto handCards = jsonMsg["handCards"];
    for(auto &arrayIt : handCards)
    {
        std::string htxid = arrayIt["htxid"];
        if(htxid != g_tmcg->matchTxID)
        {
            // log
            continue;
        }

        if(!mHandCardMsg.empty())
        {
            //error log
            LOG_PRINT("mHandCardMsg is not empty")
            return ;
        }
        auto hcard = arrayIt["hcard"];
        if(hcard.size() != 2)
        {
            //error log
            LOG_PRINT("hcard.size() != 2")
            return ;
        }
        std::string cardOne = hcard[0].get<std::string>();
        std::string cardTwo = hcard[1].get<std::string>();
        mHandCardMsg[0] = cardOne;
        mHandCardMsg[1] = cardTwo;
        g_tmcg->mHandCardVerify[txid] = mHandCardMsg;
    }

    if(g_tmcg->mHandCardVerify.size() != (size_t)(g_tmcg->playersize-1))
    {
        LOG_PRINT("g_tmcg->mHandCardVerify.size() != (size_t)(g_tmcg->playersize-1")
        return ;
    }

    for(int verifyHandIndex = 0;verifyHandIndex < HANDCARDSIZE; ++verifyHandIndex)
    {
        g_tmcg->selfCardSecret(g_tmcg->myindex, verifyHandIndex);//

        for(auto & playerIt : g_tmcg->mHandCardVerify)
        {
            auto handcardMap =  playerIt.second;
            auto handCardMapIt = handcardMap.find(verifyHandIndex);
            if(handCardMapIt == handcardMap.end())
            {
                //not found index ---->verifyHandIndex
                std::cout << "hand card index : " << verifyHandIndex << " not found " <<std::endl;
                return ;
            }
            std::string handCardMsg = handCardMapIt->second;
            if(!g_tmcg->verifyCardSecret(g_tmcg->myindex, verifyHandIndex, handCardMsg))
            {
                // verify error

                std::cout << "verify hand card error . card index is  : " << verifyHandIndex << "  myindex is : " << g_tmcg->myindex <<std::endl;
                return ;
            }
        }
        g_tmcg->saveHandCard(g_tmcg->myindex, verifyHandIndex);
    }
    g_tmcg->showPlayerInfo();
    LOG_PRINT("verify hand card successful")
}


//{"tableID":"774a7982f4ecb239860ccbd02c89b0e380807788690153a4ae8bad3cf7f34d2b",
//"txID":"d325d4dd731f1e2bdada510157a9f202e0acf4cbb1ee7dea835934e92cbc80ff",
//"nextShuffleIndex":1,
///"tmcg_shuffle":"stk^52^crd|4JhrdeyrCcFwMDhzxYfd"}
void  parseShuffleJson(std::string & getResponseStr)
{
    json jsonMsg = json::parse(getResponseStr);
    if(jsonMsg.find("txID") == jsonMsg.end() || jsonMsg.find("nextShuffleIndex") == jsonMsg.end()||  jsonMsg.find("tmcg_shuffle") == jsonMsg.end())// simple check --> replace other check
    {
        // error log
        LOG_PRINT("parseShuffleJson not found ")
        return ;
    }
    std::string txid = jsonMsg["txID"].get<std::string>();
    std::string tmcg_shuffle = jsonMsg["tmcg_shuffle"].get<std::string>();
    int nextShuffleIndex = jsonMsg["nextShuffleIndex"].get<int>();

	g_tmcg->nextShuffleIndex = nextShuffleIndex;

    if(g_tmcg->mPlayerIndex.count(txid) == 0)
    {
        //error log
        LOG_PRINT("player index not found ")
        return ;
    }

    std::cout << "parseShuffleJson tmcg_shuffle size is : " << tmcg_shuffle.size() << std::endl;

    if(txid != g_tmcg->matchTxID)
    {

    	if(g_tmcg->s.empty())
    	{
    		g_tmcg->createCard();
			std::cout << "g_tmcg->createCard successful " <<std::endl;
    	}

    	if(!g_tmcg->verifyShuffleCard(tmcg_shuffle))
    	{
            //error log
            LOG_PRINT("parseShuffleJson error")
            return ;
    	}

        LOG_PRINT("parseShuffleJson successful")
    }

    if(nextShuffleIndex == g_tmcg->playersize)
    {
        g_tmcg->createHandCard();
        LOG_PRINT("createHandCard successful")

		// Egret
		if (!g_tmcg->vHandCardMsg.empty()) {
			LOG_PRINT("=================================================== verify eraly handcard msg. ")
			LOG_PRINT("=================================================== vHandCardMsg.size(): " + g_tmcg->vHandCardMsg.size())
			for(auto &it: g_tmcg->vHandCardMsg ){
				parseHandCardsJson(it);
			}
			g_tmcg->vHandCardMsg.clear();
		}
    }
}


void  parseSsheJson(std::string & getResponseStr)
{
    json jsonMsg = json::parse(getResponseStr);
    if(jsonMsg.find("txID") == jsonMsg.end() || jsonMsg.find("tmcg_ssh") == jsonMsg.end())// simple check --> replace other check
    {
        // error log
        std::cout << "parseSsheJson find error " << std::endl;
        return ;
    }
    std::string txid = jsonMsg["txID"].get<std::string>();
    std::string tmcg_ssh = jsonMsg["tmcg_ssh"].get<std::string>();

    if(g_tmcg->mPlayerIndex.count(txid) == 0)
    {
        //error log
        LOG_PRINT("player index not found ")
        return ;
    }

    std::cout << "parseSsheJson tmcg_ssh size is : " << tmcg_ssh.size() << std::endl;
    if(g_tmcg->vsshe)
    {
        //repeat  sshe
        std::cout << " repeat  sshe " << std::endl;
        return ;
    }
    g_tmcg->createSshe(tmcg_ssh);//产生sshe

    if(!g_tmcg->verifySsheKey())//验证产生的sshe
    {
        LOG_PRINT("verifySsheKey error")
        std::cout << "verifySsheKey error txid is : " << txid << std::endl;
        return ;
    }

	g_tmcg->fVerifySSHE = true;
    LOG_PRINT("verifySsheKey successful")

	// Egret
	if (!g_tmcg->vShuffleMsg.empty()) {
		LOG_PRINT("=================================================== verify eraly shuffle msg. ")
		LOG_PRINT("=================================================== vShuffleMsg.size(): " + g_tmcg->vShuffleMsg.size())
		for(auto &it: g_tmcg->vShuffleMsg ){
			parseShuffleJson(it);
		}
		g_tmcg->vShuffleMsg.clear();
	}
}


//{"tableID":"555c069622257dc754ca593f2e82dd8f78f43e4b19fcced5757be41f471e6536",
//"txID":"e9d159db17bc19537921e941b3335fe015695f742e522cf2ee41aba1893beeba",
//"flopCards":["7Y9LKVQWOGloNlAKpQkwYhHy1yP2o6TpHARYh0DNqDamFghCsnXNnMQiWWo7lEEz2Fi
//ZKiuqnRhD1AdWD4bQxEMyemPnoUFOzpEZUGGIVjC2CDkTACmRIWiVHgItREGqcjpY2M5aaLuUdw3GDQt
//cwOSTMW6I54fui1vHiDNBzkMk62KGvHzKUdWK7UCfeqyE3dfsVfv6370DAFyvz1P


void  parseFlopCardsJson(std::string & getResponseStr)
{
    json jsonMsg = json::parse(getResponseStr);
    if( jsonMsg.find("txID") == jsonMsg.end() ||  jsonMsg.find("flopCards") == jsonMsg.end())// simple check --> replace other check
    {
        // error log
        LOG_PRINT("parseFlopCardsJson not found ")
        return ;
    }

    std::string txid = jsonMsg["txID"].get<std::string>();

    if(g_tmcg->mPlayerIndex.count(txid) == 0)
    {
        //error log
        LOG_PRINT("player index not found ")
        return ;
    }

    if(g_tmcg->matchTxID == txid)
    {
        // error log
        LOG_PRINT("self flop msg")
        return ;
    }

    if(!jsonMsg["flopCards"].is_array())
    {
        //error log
        LOG_PRINT("handCards is not array ")
        return ;
    }
    std::vector<std::string> v;
    auto flopArray = jsonMsg["flopCards"];


    for(auto &vIt : flopArray)
    {
        v.push_back(vIt);
    }
    std::cout << "v.size() is : " <<v.size() << std::endl;
	if(g_tmcg->mFlopCardVerify.count(txid))
	{
        //repeat flop card verify
        std::cout << "repeat flop card verify" << std::endl;
        return ;
	}

    g_tmcg->mFlopCardVerify[txid] = v;

    if(g_tmcg->mFlopCardVerify.size() != (size_t)(g_tmcg->playersize-1))
    {
        LOG_PRINT("g_tmcg->mFlopCardVerify.size() != (size_t)(g_tmcg->playersize-1")

        return ;
    }
    // verify

    if(g_tmcg->flop.size() == 0)
	{
        //
        LOG_PRINT(" -------- create flop card -------- ")
		g_tmcg->createFlopCard();
	}

    std::cout << "g_tmcg->mFlopCardVerify size is : " << g_tmcg->mFlopCardVerify.size() << std::endl;

	if (isGameOver() == -1)
	{
		int fromIndex = 0;
		if (g_tmcg->gBetIpfsMsg.publicIndex)
		{
			fromIndex = g_tmcg->gBetIpfsMsg.publicIndex + 2;
		}
		else
		{
			fromIndex = 0;
		}

		for (int k = fromIndex; k < 5; k++)
		{
			g_tmcg->selfFlopSecret(k);

			for(auto &it : g_tmcg->mFlopCardVerify)
			{
				std::string flopMsg = it.second.at(k - fromIndex);
				std::cout << "it.size() is : " << it.second.size() << std::endl;
				if(!g_tmcg->verifyFlopSecret(k, flopMsg))
				{
					//error log
					LOG_PRINT("verify flop card error")
					return ;
				}
			}
			g_tmcg->saveFlopCard(k);
		}
	}
	else if (g_tmcg->gBetIpfsMsg.publicIndex == 1)
	{
		for(int verifyFlopIndex = 0;verifyFlopIndex < 3; ++verifyFlopIndex)
		{
			g_tmcg->selfFlopSecret(verifyFlopIndex);

			for(auto &it : g_tmcg->mFlopCardVerify)
			{
				std::string flopMsg = it.second.at(verifyFlopIndex);

				if(!g_tmcg->verifyFlopSecret(verifyFlopIndex, flopMsg))
				{
					//error log
					LOG_PRINT("verify flop card error")
					return ;
				}
			}
			g_tmcg->saveFlopCard(verifyFlopIndex);
		}
	}
	else if (g_tmcg->gBetIpfsMsg.publicIndex == 2 || g_tmcg->gBetIpfsMsg.publicIndex == 3)
	{
		g_tmcg->selfFlopSecret(g_tmcg->gBetIpfsMsg.publicIndex + 1);

		for(auto &it : g_tmcg->mFlopCardVerify)
		{
			std::string flopMsg = it.second.at(0);

			if(!g_tmcg->verifyFlopSecret(g_tmcg->gBetIpfsMsg.publicIndex + 1, flopMsg))
			{
				//error log
				LOG_PRINT("verify flop card error")
				return ;
			}
		}
		g_tmcg->saveFlopCard(g_tmcg->gBetIpfsMsg.publicIndex + 1);
	}

	std::cout << "g_tmcg->gBetIpfsMsg.publicIndex is : " << g_tmcg->gBetIpfsMsg.publicIndex << std::endl;


	g_tmcg->mFlopCardVerify.clear();

    LOG_PRINT("verify flop card successful")

	//clear one round data
	g_tmcg->gBetIpfsMsg.curBet = 0;
	g_tmcg->gBetIpfsMsg.maxBet = 0;

	g_tmcg->fVerifyFlopCard = true;
	// 验证公共牌通过并且自己也发送了公共牌交易
	if (!g_tmcg->fSendFlopCardTx) {
		g_tmcg->gBetIpfsMsg.fFlopCard = false;
	}

	for (auto &it: g_tmcg->gBetIpfsMsg.mHasBet) {
		it.second = 0;
	}

    g_tmcg->showPlayerInfo();
}
//{"tableID":"e0b8ebc943e08f2efcaedac783ca83f8a19428a287e773c45adde5ea3a0519a9",
//"txID":"367b2a452899731f0c7e36f31b471c99fe91a43d74acd5c3d040a9acfd02801f",
//"openhands":["OJVjkHceRojgjTS672XQxcY2PT3DCGnEZY0Oiylg06XDCnNG2MgrrEGzGb2NvOXVGxUpb8Tgp
//rRl65J8JsXxDWk0H6Awc2rGSUMn5vjTPTdF2bBBNrdpeTSMGSh2lK4UesNNiY2RqgpI4ArrIBiR7GYLT

void  parseOpenHandJson(std::string & getResponseStr)
{

    json jsonMsg = json::parse(getResponseStr);
    if( jsonMsg.find("txID") == jsonMsg.end() ||  jsonMsg.find("openhands") == jsonMsg.end())// simple check --> replace other check
    {
        // error log
        LOG_PRINT("parseOpenHandJson not found ")
        return ;
    }

    std::string txid = jsonMsg["txID"].get<std::string>();

    if(g_tmcg->mPlayerIndex.count(txid) == 0)
    {
        //error log
        LOG_PRINT("player index not found ")
        return ;
    }

    if(g_tmcg->matchTxID == txid)
    {
        // error log
        LOG_PRINT("self flop msg")
        return ;
    }
    if(!jsonMsg["openhands"].is_array())
    {
        //error log
        LOG_PRINT("openhands is not array ")
        return ;
    }
    if(g_tmcg->mOpenFlopVerify.count(txid))
    {
        //repeat open handle card
        std::cout << " repeat open handle card " <<std::endl;
        return ;
    }
    std::vector<std::string> v;
    auto openHandArray = jsonMsg["openhands"];
    if(openHandArray.size() != (size_t)(g_tmcg->playersize*HANDCARDSIZE))
    {
        // error log
        LOG_PRINT("openHandArray.size() != (size_t)(g_tmcg->playersize*HANDCARDSIZE)")
        return ;
    }
    for(auto &vIt : openHandArray)
    {
        v.push_back(vIt);
    }

    g_tmcg->mOpenFlopVerify[txid] = v;

    if(g_tmcg->mOpenFlopVerify.size() != (size_t)(g_tmcg->playersize-1))
    {
        LOG_PRINT("g_tmcg->mOpenFlopVerify.size() != (size_t)(g_tmcg->playersize-1")
        return ;
    }


    for(int i = 0;i < (g_tmcg->playersize*HANDCARDSIZE) ; ++i)
    {
        g_tmcg->selfHandFlopSecret(i);
        for(auto &it: g_tmcg->mOpenFlopVerify)
        {
            if(!g_tmcg->verifyHandFlopSecret(i, it.second.at(i)))
            {
                //error log
                LOG_PRINT("verify hand flop error ")
                return ;
            }
        }
        g_tmcg->saveHandFlopCard(i);
    }

    g_tmcg->showPlayerInfo();
    LOG_PRINT("verify open flop card successful")

	g_tmcg->IsOver = true;
}


//{"tableID":"b5fdf88e32d35413c2a7387b0cd6c6a8f62830a0293f3025605d38a580020bb1",
//"txID":"9e559d5827da8cecbc82b6e170dfc05cde41d3190b09e90a4b22f919f40f8d7d",
//"nextBetTxID":"9e559d5827da8cecbc82b6e170dfc05cde41d3190b09e90a4b22f919f40f8d7d",
//"curBet":10,"maxBet":10,"jackot":10,"publicIndex":0,"fGameOver":false,"fFlopCard":false,
//"mHasBet":[{"txID":"9e559d5827da8cecbc82b6e170dfc05cde41d3190b09e90a4b22f919f40f8d7d","hasBet":10},
//{"txID":"e9d159db17bc19537921e941b3335fe015695f742e522cf2ee41aba1893beeba","hasBet":0}],
//"mBalance":[{"txID":"9e559d5827da8cecbc82b6e170dfc05cde41d3190b09e90a4b22f919f40f8d7d","balance":35},
//{"txID":"e9d159db17bc19537921e941b3335fe015695f742e522cf2ee41aba1893beeba","balance":100}],
//"mPlayerStatus":[{"txIndex":0,"status":0},{"txIndex":1,"status":0}]}
void getBetData(const json &jsonMsg,BetIpfsMsg &curBetMsg)
{
    curBetMsg.nextBetTxID = jsonMsg["nextBetTxID"].get<std::string>();
    curBetMsg.curBetTxID = jsonMsg["curBetTxID"].get<std::string>();
    curBetMsg.curBet = jsonMsg["curBet"].get<int>();
    curBetMsg.maxBet = jsonMsg["maxBet"].get<int>();
    curBetMsg.jackpot = jsonMsg["jackpot"].get<int>();
    curBetMsg.publicIndex = jsonMsg["publicIndex"].get<int>();
    curBetMsg.fGameOver = jsonMsg["fGameOver"].get<bool>();
    curBetMsg.fFlopCard = jsonMsg["fFlopCard"].get<bool>();

    for(auto &hasbetIt : jsonMsg["mHasBet"])
    {
        std::string htxid = hasbetIt["txID"].get<std::string>();
        int hbet = hasbetIt["hasBet"].get<int>();
        curBetMsg.mHasBet.insert(std::make_pair(htxid,hbet));
    }

    for(auto &hasbetIt : jsonMsg["mBalance"])
    {
        std::string btxid = hasbetIt["txID"].get<std::string>();
        int balance = hasbetIt["balance"].get<int>();
        curBetMsg.mBalance.insert(std::make_pair(btxid,balance));
    }

    for(auto &hasbetIt : jsonMsg["mPlayerStatus"])
    {
        int index = hasbetIt["txIndex"].get<int>();
        int status = hasbetIt["status"].get<int>();
        curBetMsg.mPlayerStatus.insert(std::make_pair(index,status));
    }
}

bool checkPokerBetJson(const json &jsonMsg,std::string &error)
{
    error.clear();
    if(jsonMsg.find("tableID") == jsonMsg.end() || jsonMsg.find("txID") == jsonMsg.end())// simple check --> replace other check
    {
        // error log
        error = "checkPokerBetJson not found ";
        return false;
    }

    std::string txid = jsonMsg["txID"].get<std::string>();

    if(g_tmcg->mPlayerIndex.count(txid) == 0)
    {
        //error log
        error = "player index not found ";
        return false;
    }

    if(!jsonMsg["mHasBet"].is_array() || !jsonMsg["mBalance"].is_array() || !jsonMsg["mPlayerStatus"].is_array())
    {
        // error log
        error = "bet parse json error";
        return false;
    }

    error.clear();
    return true;
}

// pre --> g_tmcg->gBetIpfsMsg
// cur --> curBetMsg
// verify pre and cur
// -->  g_tmcg->gBetIpfsMsg = curBetMsg;

/*
std::string nextBetTxID;
std::string curBetTxID
int curBet;
int maxBet;
int jackot;
int publicIndex;
bool fGameOver;
bool fFlopCard;
std::map<std::string, int> mHasBet;
std::map<std::string, int> mBalance;
std::map<int, int> mPlayerStatus;

*/

bool verifyBetMsg(BetIpfsMsg& preBetMsg,  BetIpfsMsg& curBetMsg,std::string &error)
{
    error.clear();

	if(preBetMsg.nextBetTxID != curBetMsg.curBetTxID)
	{
        error = "verifyBetMsg NextIndex error. preBetMsg.nextBetTxID : " + preBetMsg.nextBetTxID + "  curBetMsg.curBetTxID : " + curBetMsg.curBetTxID;
		return false;
	}
std::cout << "--> verifyBetMsg nextBetTxID ok" << std::endl;
	for(auto & it : preBetMsg.mPlayerStatus)
	{
		int index = it.first;
        int fromIndex = g_tmcg->mPlayerIndex[curBetMsg.curBetTxID];

        std::string txid = g_tmcg->mPlayerTxid[index];

        (void)index;

		if(index == fromIndex)// 上个玩家有没有违反规则
		{

			if((preBetMsg.mBalance[txid] - curBetMsg.mBalance[txid]) == (curBetMsg.mHasBet[txid] - preBetMsg.mHasBet[txid]) && (
				  curBetMsg.mHasBet[txid] - preBetMsg.mHasBet[txid]) == curBetMsg.curBet){}//下注
			else
			{
				error =  "CurBet --> Someone is lying : GameOver " ;
				return false;
			}
std::cout << "--> verifyBetMsg index == fromIndex CurBet ok" << std::endl;
			if(curBetMsg.mHasBet[txid] >= preBetMsg.maxBet)//最大注
			{
				if(curBetMsg.maxBet != curBetMsg.mHasBet[txid])
				{
                    std::cout << "curBetMsg.maxBet is : " << curBetMsg.maxBet << std::endl;
                    std::cout << "curBetMsg.mHasBet[txid] is : " << curBetMsg.mHasBet[txid] << std::endl;
					error =  "MaxBet --> Someone is lying : GameOver ";
					return false;
				}
			}
std::cout << "--> verifyBetMsg index == fromIndex mHasBet ok" << std::endl;
			if(curBetMsg.mPlayerStatus[index] == PS_ALLIN)
			{
				if(preBetMsg.mBalance[txid] != curBetMsg.curBet)
				{
                    std::cout << "preBetMsg.mBalance[txid] is : " << preBetMsg.mBalance[txid] << std::endl;
                    std::cout << "curBetMsg.curBet is : " << curBetMsg.curBet << std::endl;
					error =  "PS_ALLIN --> Someone is lying : GameOver " ;
					return false;
				}
std::cout << "--> verifyBetMsg index == fromIndex PS_ALLIN ok" << std::endl;
			}

			else if(curBetMsg.mPlayerStatus[index] == PS_DISCARD)
			{
				if(preBetMsg.mBalance[txid] != curBetMsg.mBalance[txid])
				{
                    std::cout << "preBetMsg.mBalance[txid] is : " << preBetMsg.mBalance[txid] << std::endl;
                    std::cout << "curBetMsg.mBalance[txid] is : " << curBetMsg.mBalance[txid] << std::endl;
					error =  "PS_DISCARD --> Someone is lying : GameOver ";
					return false;
				}
std::cout << "--> verifyBetMsg index == fromIndex PS_DISCARD ok" << std::endl;
			}
		}
		else
		{
			if(curBetMsg.mPlayerStatus[index] != it.second)//验证状态
			{
                std::cout << "curBetMsg.mPlayerStatus[index] is : " << curBetMsg.mPlayerStatus[index] << std::endl;
                std::cout << "it.second is : " << it.second << std::endl;
				error = "PlayerStatus --> Someone is lying : GameOver ";
				return false;
			}
std::cout << "--> verifyBetMsg  mPlayerStatus ok" << std::endl;
			if(curBetMsg.mBalance[txid] != preBetMsg.mBalance[txid])//余额
			{
                std::cout << "curBetMsg.mBalance[txid]  is : " << curBetMsg.mBalance[txid]  << std::endl;
                std::cout << "preBetMsg.mBalance[txid]  is : " << preBetMsg.mBalance[txid] << std::endl;
				error = "Balance --> Someone is lying : GameOver ";
				return false;
			}
std::cout << "--> verifyBetMsg  mBalance ok" << std::endl;
		}

	}

	// if(g_tmcg->IsFlopOpen(curBetMsg) != curBetMsg.fFlopCard)
	// {
		// error = "IsFlopOpen --> Someone is lying : GameOver ";
	// }

	std::cout << "--> verifyBetMsg  ok" << std::endl;

    error.clear();
	return true;
}


void parsePokerBetJson(std::string & getResponseStr, const CTransaction &ctx)
{
    std::string error;
    json jsonMsg = json::parse(getResponseStr);
    bool ret;
    ret = checkPokerBetJson(jsonMsg,error);
    if(!ret)
    {
        LOG_PRINT(error.c_str())
        return ;
    }
    BetIpfsMsg curBetMsg;
    getBetData(jsonMsg,curBetMsg);

    ret = verifyBetMsg(g_tmcg->gBetIpfsMsg, curBetMsg, error);
    if(!ret)
    {
        LOG_PRINT(error.c_str())
        return ;
    }
    g_tmcg->gBetIpfsMsg = curBetMsg;
	g_tmcg->nextBetTxID = g_tmcg->gBetIpfsMsg.nextBetTxID;

	if (g_tmcg->gBetIpfsMsg.fFlopCard && !g_tmcg->fSendFlopCardTx) {
		g_tmcg->fSendFlopCardTx = true;
	}

	g_tmcg->showPlayerInfo();

	// 如果不是让牌, 保存交易 Egret
	if (g_tmcg->gBetIpfsMsg.maxBet == 0 && g_tmcg->gBetIpfsMsg.curBet == 0 && !g_tmcg->gBetIpfsMsg.fFlopCard) {
		LOG_PRINT(".........................让牌tx .. \n")
	} else {
		vTxBetPlayer.insert(make_pair(curBetMsg.curBetTxID, ctx));
	}
	vTxBetVerify.push_back(ctx);

	// Egret
    if(g_tmcg->gBetIpfsMsg.fFlopCard)
    {
        std::cout << "--- > > g_tmcg->vFlopCardMsg size is : " << g_tmcg->vFlopCardMsg.size() << std::endl;
        for(auto &msgIt : g_tmcg->vFlopCardMsg)
        {
            parseFlopCardsJson(msgIt);
        }
        g_tmcg->vFlopCardMsg.clear();
        std::cout << "--- > > g_tmcg->vFlopCardMsg size is : " << g_tmcg->vFlopCardMsg.size() << std::endl;
    }
}


void parseJsonData(const CScript &script, const CTransaction &ctx)
{
    std::string tableID(script.begin() + 4, script.begin() + 68);
    std::string msgHash(script.begin() + 68, script.end());
	std::string xxx(script.begin(), script.end());

	std::cout << "script[start, end]: " << xxx << std::endl;
	std::cout << "tableid: " << tableID << std::endl;
    std::cout << "ipfshash: " << msgHash << std::endl;

    if(tableID != g_tmcg->matchTableID)
    {
        std::cout << "tableID != g_tmcg->matchTableID" <<std::endl;
        return ;
    }

    std::string getResponseStr;

    ipfsCatFile(msgHash,getResponseStr);
    if(getResponseStr.empty())
    {
        std::cout <<"curl get msg is empty reutn " << std::endl;
        return ;
    }

    //std::cout << "getResponseStr size : " << getResponseStr.size() << std::endl;

    if(script[3] == PC_NEW_ADDRESS) // new address
    {
        // save data -> g_tmcg
        parseNewAddressJson(getResponseStr);
        return ;
    }
    else if(script[3] == PC_POKER_ADDRESS)// poker address
    {
        parsePokerAddressJson(getResponseStr);
        return ;
    }
    else if(script[3] == PC_POKER_BALANCE)// balance
    {
        parseBalanceJson(getResponseStr, ctx);
    }
    else if(script[3] == PC_POKER_HANDLE)
    {
        parseHandleJson(getResponseStr);
    }
    else if(script[3] == PC_POKER_PUBKEY)
    {
        parsePubkeyJson(getResponseStr);
    }
    else if(script[3] == PC_POKER_PUBKEY_VERIFY)
    {
        ++g_tmcg->countVerify;
        if(g_tmcg->countVerify == g_tmcg->playersize)
        {
            g_tmcg->updatePubkey(); //update pubkey
			g_tmcg->fMyPubkeyVerify = true;
            LOG_PRINT("updatePubkey")
        }
        else if(g_tmcg->countVerify > g_tmcg->playersize)
        {
            //repeat pubkey verify
            std::cout << "repeat pubkey verify  " << std::endl;
            return ;
        }
    }
    else if(script[3] == PC_POKER_SSH)
    {
        if(g_tmcg->isOne)
        {
            // log self
            LOG_PRINT("self tx : PC_POKER_SSH")
            return ;
        }
        parseSsheJson(getResponseStr);
    }
    else if(script[3] == PC_POKER_SHUFFLE)
    {
		// Egret 洗牌交易比SSHE交易先到达
		// if (g_tmcg->myindex != 0 && !g_tmcg->fVerifySSHE)
        // {
            // g_tmcg->vShuffleMsg.push_back(getResponseStr);
            // LOG_PRINT(".........shuffle msg arrived early  < < <--------------\n")
            // return ;
        // }
        parseShuffleJson(getResponseStr);
    }
    else if(script[3] == PC_POKER_HAND_CARD)
    {
		// Egret 手牌交易比Shuffle交易先到达
		// if (g_tmcg->nextShuffleIndex != g_tmcg->playersize)
        // {
            // g_tmcg->vHandCardMsg.push_back(getResponseStr);
            // LOG_PRINT(".........shuffle msg arrived early  < < <--------------\n")
            // return ;
        // }
        parseHandCardsJson(getResponseStr);
    }
    else if(script[3] == PC_POKER_FLOP_CARD)
    {
		// Egret 公共牌交易比下注交易先到达

        // if(!g_tmcg->gBetIpfsMsg.fFlopCard && !g_tmcg->gBetIpfsMsg.fGameOver)
        // {
            // g_tmcg->vFlopCardMsg.push_back(getResponseStr);
            // LOG_PRINT("......... public card msg arrived early  < < <--------------\n")
            // return ;
        // }
        parseFlopCardsJson(getResponseStr);
    }
    else if(script[3] == PC_POKER_OPEN_HAND)
    {
        parseOpenHandJson(getResponseStr);
    }
    else if(script[3] == PC_POKER_BET)
    {
        parsePokerBetJson(getResponseStr, ctx);
    }
}
void parseTxScript(const CScript &script, const CTransaction &ctx)
{

	if(script.size() > 3 && script[0] == OP_RETURN && script[2] == PC_POKER_MATCH_FINISH)	// match node tx
	{
		std::string hash(script.begin() + 3, script.end());
		if(!g_tmcg->matchTableID.empty())
		{
			std::cout << "  new match  hash is :  " << hash << std::endl;
			return ;
		}

        std::string getResponseStr;
        ipfsCatFile(hash, getResponseStr);// ipfs cat
        if(getResponseStr.empty())
        {
            std::cout <<"------------------ curl get msg is empty reutn " << std::endl;
            return ;
        }

        parseMatchJson(getResponseStr);    // json data
        return ;
	}
	else if(script.size() > 4 && script[0] == OP_RETURN )
    {
        parseJsonData(script, ctx);
	}
}

void parseMatchScript(const CScript &script,const CTransaction &tx)
{

    // if(script.size() > 3)
    // {
        // int ms = script[3];
        // std::string key(script.begin() + 4, script.end());
        // std::cout << "ms: " << ms << std::endl;
        // std::cout << "key: " << key << std::endl;
    // }
    if(g_tmcg->fMatchNode)
    {
        vTxMatchPlayer.push_back(tx);
        return;
    }
}

bool CTxMemPool::addDepositTx(const uint256& hash, const CTxMemPoolEntry &entry, setEntries &setAncestors,std::string ip)
{
	assert(g_tmcg);

	if(ip.empty())
	{
		ip = g_tmcg->selfip;
	}
    std::cout << "------------------   " << hash.ToString() << std::endl;
	auto txptr = entry.GetSharedTx();

	for(auto voutit : txptr->vout)
	{
		auto script = voutit.scriptPubKey;
        if(script[0] != OP_RETURN ) continue;

		if(script.size() > 2 && script[0] == OP_RETURN && script[2] == PC_POKER_MATCH)//player --> match tx
		{
            parseMatchScript(script,entry.GetTx());
		} else {

			bool boo = (script.size() > 2 && script[0] == OP_RETURN && script[1] == OP_POKER);
			if(boo)
			{
				std::cout << " OP_POKER " << std::endl;
			}
			else
			{
				parseTxScript(script, entry.GetTx());
			}
		}

	}
	addUnchecked(hash, entry, setAncestors, false);
	return true;
}


void CTxMemPool::txPokerAddress(const CScript &script,const uint256& hash)
{
	std::vector<unsigned char> vch(script.begin() + 3, script.begin() + 16);
	std::string ip(vch.begin(), vch.end());
	std::cout<<"##CTxMemPool ip: " << ip << std::endl;

	std::vector<unsigned char> add(script.begin() + 16, script.end());
	std::string address(add.begin(), add.end());
	std::cout<<"##CTxMemPool address: " << address << std::endl;

	if(gMapAddress.find(ip) == gMapAddress.end())
		gMapAddress.insert(std::pair<std::string, std::string>(ip, address));

	for(auto it = gMapAddress.begin(); it != gMapAddress.end(); it++){
        std::cout << it->first << " - " << it->second << std::endl;
    }
}


bool CTxMemPool::addUnchecked(const uint256& hash, const CTxMemPoolEntry &entry, setEntries &setAncestors, bool validFeeEstimate,bool deposit,std::string ip)
{
	auto txptr = entry.GetSharedTx();
	(void)txptr;
	if(deposit && addDepositTx(hash, entry,  setAncestors,ip))
	{
		return true;
	}
	addUnchecked(hash,entry,setAncestors,validFeeEstimate);
	return true;
}

bool CTxMemPool::addUnchecked(const uint256& hash, const CTxMemPoolEntry &entry, setEntries &setAncestors, bool validFeeEstimate)
{
//txLeavesMap mapLeaves;
//pairTxMap mapRoot;

    NotifyEntryAdded(entry.GetSharedTx());
    // Add to memory pool without checking anything.
    // Used by AcceptToMemoryPool(), which DOES do
    // all the appropriate checks.
    LOCK(cs);
    indexed_transaction_set::iterator newit = mapTx.insert(entry).first;
    mapLinks.insert(make_pair(newit, TxLinks()));

    // Update transaction for any feeDelta created by PrioritiseTransaction
    // TODO: refactor so that the fee delta is calculated before inserting
    // into mapTx.
    std::map<uint256, CAmount>::const_iterator pos = mapDeltas.find(hash);
    if (pos != mapDeltas.end()) {
        const CAmount &delta = pos->second;
        if (delta) {
            mapTx.modify(newit, update_fee_delta(delta));
        }
    }

    // Update cachedInnerUsage to include contained transaction's usage.
    // (When we update the entry for in-mempool parents, memory usage will be
    // further updated.)
    cachedInnerUsage += entry.DynamicMemoryUsage();

    const CTransaction& tx = newit->GetTx();
    std::set<uint256> setParentTransactions;
    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        mapNextTx.insert(std::make_pair(&tx.vin[i].prevout, &tx));
        setParentTransactions.insert(tx.vin[i].prevout.hash);
    }
    // Don't bother worrying about child transactions of this one.
    // Normal case of a new transaction arriving is that there can't be any
    // children, because such children would be orphans.
    // An exception to that is if a transaction enters that used to be in a block.
    // In that case, our disconnect block logic will call UpdateTransactionsFromBlock
    // to clean up the mess we're leaving here.

    // Update ancestors with information about this tx
    for (const uint256 &phash : setParentTransactions) {
        txiter pit = mapTx.find(phash);
        if (pit != mapTx.end()) {
            UpdateParent(newit, pit, true);
        }
    }
    UpdateAncestorsOf(true, newit, setAncestors);
    UpdateEntryForAncestors(newit, setAncestors);

    nTransactionsUpdated++;
    totalTxSize += entry.GetTxSize();
    if (minerPolicyEstimator) {minerPolicyEstimator->processTransaction(entry, validFeeEstimate);}

    vTxHashes.emplace_back(tx.GetWitnessHash(), newit);
    newit->vTxHashesIdx = vTxHashes.size() - 1;

    return true;
}

void CTxMemPool::removeUnchecked(txiter it, MemPoolRemovalReason reason)
{
    NotifyEntryRemoved(it->GetSharedTx(), reason);
    const uint256 hash = it->GetTx().GetHash();
    for (const CTxIn& txin : it->GetTx().vin)
        mapNextTx.erase(txin.prevout);

    if (vTxHashes.size() > 1) {
        vTxHashes[it->vTxHashesIdx] = std::move(vTxHashes.back());
        vTxHashes[it->vTxHashesIdx].second->vTxHashesIdx = it->vTxHashesIdx;
        vTxHashes.pop_back();
        if (vTxHashes.size() * 2 < vTxHashes.capacity())
            vTxHashes.shrink_to_fit();
    } else
        vTxHashes.clear();

    totalTxSize -= it->GetTxSize();
    cachedInnerUsage -= it->DynamicMemoryUsage();
    cachedInnerUsage -= memusage::DynamicUsage(mapLinks[it].parents) + memusage::DynamicUsage(mapLinks[it].children);
    mapLinks.erase(it);
    mapTx.erase(it);
    nTransactionsUpdated++;
    if (minerPolicyEstimator) {minerPolicyEstimator->removeTx(hash, false);}
}

// Calculates descendants of entry that are not already in setDescendants, and adds to
// setDescendants. Assumes entryit is already a tx in the mempool and setMemPoolChildren
// is correct for tx and all descendants.
// Also assumes that if an entry is in setDescendants already, then all
// in-mempool descendants of it are already in setDescendants as well, so that we
// can save time by not iterating over those entries.
void CTxMemPool::CalculateDescendants(txiter entryit, setEntries &setDescendants)
{
    setEntries stage;
    if (setDescendants.count(entryit) == 0) {
        stage.insert(entryit);
    }
    // Traverse down the children of entry, only adding children that are not
    // accounted for in setDescendants already (because those children have either
    // already been walked, or will be walked in this iteration).
    while (!stage.empty()) {
        txiter it = *stage.begin();
        setDescendants.insert(it);
        stage.erase(it);

        const setEntries &setChildren = GetMemPoolChildren(it);
        for (const txiter &childiter : setChildren) {
            if (!setDescendants.count(childiter)) {
                stage.insert(childiter);
            }
        }
    }
}

void CTxMemPool::removeRecursive(const CTransaction &origTx, MemPoolRemovalReason reason)
{
    // Remove transaction from memory pool
    {
        LOCK(cs);
        setEntries txToRemove;
        txiter origit = mapTx.find(origTx.GetHash());
        if (origit != mapTx.end()) {
            txToRemove.insert(origit);
        } else {
            // When recursively removing but origTx isn't in the mempool
            // be sure to remove any children that are in the pool. This can
            // happen during chain re-orgs if origTx isn't re-accepted into
            // the mempool for any reason.
            for (unsigned int i = 0; i < origTx.vout.size(); i++) {
                auto it = mapNextTx.find(COutPoint(origTx.GetHash(), i));
                if (it == mapNextTx.end())
                    continue;
                txiter nextit = mapTx.find(it->second->GetHash());
                assert(nextit != mapTx.end());
                txToRemove.insert(nextit);
            }
        }
        setEntries setAllRemoves;
        for (txiter it : txToRemove) {
            CalculateDescendants(it, setAllRemoves);
        }

        RemoveStaged(setAllRemoves, false, reason);
    }
}

void CTxMemPool::removeForReorg(const CCoinsViewCache *pcoins, unsigned int nMemPoolHeight, int flags)
{
    // Remove transactions spending a coinbase which are now immature and no-longer-final transactions
    LOCK(cs);
    setEntries txToRemove;
    for (indexed_transaction_set::const_iterator it = mapTx.begin(); it != mapTx.end(); it++) {
        const CTransaction& tx = it->GetTx();
        LockPoints lp = it->GetLockPoints();
        bool validLP =  TestLockPointValidity(&lp);
        if (!CheckFinalTx(tx, flags) || !CheckSequenceLocks(tx, flags, &lp, validLP)) {
            // Note if CheckSequenceLocks fails the LockPoints may still be invalid
            // So it's critical that we remove the tx and not depend on the LockPoints.
            txToRemove.insert(it);
        } else if (it->GetSpendsCoinbase()) {
            for (const CTxIn& txin : tx.vin) {
                indexed_transaction_set::const_iterator it2 = mapTx.find(txin.prevout.hash);
                if (it2 != mapTx.end())
                    continue;
                const Coin &coin = pcoins->AccessCoin(txin.prevout);
                if (nCheckFrequency != 0) assert(!coin.IsSpent());
                if (coin.IsSpent() || (coin.IsCoinBase() && ((signed long)nMemPoolHeight) - coin.nHeight < COINBASE_MATURITY)) {
                    txToRemove.insert(it);
                    break;
                }
            }
        }
        if (!validLP) {
            mapTx.modify(it, update_lock_points(lp));
        }
    }
    setEntries setAllRemoves;
    for (txiter it : txToRemove) {
        CalculateDescendants(it, setAllRemoves);
    }
    RemoveStaged(setAllRemoves, false, MemPoolRemovalReason::REORG);
}

void CTxMemPool::removeConflicts(const CTransaction &tx)
{
    // Remove transactions which depend on inputs of tx, recursively
    LOCK(cs);
    for (const CTxIn &txin : tx.vin) {
        auto it = mapNextTx.find(txin.prevout);
        if (it != mapNextTx.end()) {
            const CTransaction &txConflict = *it->second;
            if (txConflict != tx)
            {
                ClearPrioritisation(txConflict.GetHash());
                removeRecursive(txConflict, MemPoolRemovalReason::CONFLICT);
            }
        }
    }
}

/**
 * Called when a block is connected. Removes from mempool and updates the miner fee estimator.
 */
void CTxMemPool::removeForBlock(const std::vector<CTransactionRef>& vtx, unsigned int nBlockHeight)
{
    LOCK(cs);
    std::vector<const CTxMemPoolEntry*> entries;
    for (const auto& tx : vtx)
    {
        uint256 hash = tx->GetHash();

        indexed_transaction_set::iterator i = mapTx.find(hash);
        if (i != mapTx.end())
            entries.push_back(&*i);
    }
    // Before the txs in the new block have been removed from the mempool, update policy estimates
    if (minerPolicyEstimator) {minerPolicyEstimator->processBlock(nBlockHeight, entries);}
    for (const auto& tx : vtx)
    {
        txiter it = mapTx.find(tx->GetHash());
        if (it != mapTx.end()) {
            setEntries stage;
            stage.insert(it);
            RemoveStaged(stage, true, MemPoolRemovalReason::BLOCK);
        }
        removeConflicts(*tx);
        ClearPrioritisation(tx->GetHash());
    }
    lastRollingFeeUpdate = GetTime();
    blockSinceLastRollingFeeBump = true;
}

void CTxMemPool::_clear()
{
    mapLinks.clear();
    mapTx.clear();
    mapNextTx.clear();
    totalTxSize = 0;
    cachedInnerUsage = 0;
    lastRollingFeeUpdate = GetTime();
    blockSinceLastRollingFeeBump = false;
    rollingMinimumFeeRate = 0;
    ++nTransactionsUpdated;
}

void CTxMemPool::clear()
{
    LOCK(cs);
    _clear();
}

void CTxMemPool::check(const CCoinsViewCache *pcoins) const
{
    if (nCheckFrequency == 0)
        return;

    if (GetRand(std::numeric_limits<uint32_t>::max()) >= nCheckFrequency)
        return;

    LogPrint(BCLog::MEMPOOL, "Checking mempool with %u transactions and %u inputs\n", (unsigned int)mapTx.size(), (unsigned int)mapNextTx.size());

    uint64_t checkTotal = 0;
    uint64_t innerUsage = 0;

    CCoinsViewCache mempoolDuplicate(const_cast<CCoinsViewCache*>(pcoins));
    const int64_t nSpendHeight = GetSpendHeight(mempoolDuplicate);

    LOCK(cs);
    std::list<const CTxMemPoolEntry*> waitingOnDependants;
    for (indexed_transaction_set::const_iterator it = mapTx.begin(); it != mapTx.end(); it++) {
        unsigned int i = 0;
        checkTotal += it->GetTxSize();
        innerUsage += it->DynamicMemoryUsage();
        const CTransaction& tx = it->GetTx();
        txlinksMap::const_iterator linksiter = mapLinks.find(it);
        assert(linksiter != mapLinks.end());
        const TxLinks &links = linksiter->second;
        innerUsage += memusage::DynamicUsage(links.parents) + memusage::DynamicUsage(links.children);
        bool fDependsWait = false;
        setEntries setParentCheck;
        int64_t parentSizes = 0;
        int64_t parentSigOpCost = 0;
        for (const CTxIn &txin : tx.vin) {
            // Check that every mempool transaction's inputs refer to available coins, or other mempool tx's.
            indexed_transaction_set::const_iterator it2 = mapTx.find(txin.prevout.hash);
            if (it2 != mapTx.end()) {
                const CTransaction& tx2 = it2->GetTx();
                assert(tx2.vout.size() > txin.prevout.n && !tx2.vout[txin.prevout.n].IsNull());
                fDependsWait = true;
                if (setParentCheck.insert(it2).second) {
                    parentSizes += it2->GetTxSize();
                    parentSigOpCost += it2->GetSigOpCost();
                }
            } else {
                assert(pcoins->HaveCoin(txin.prevout));
            }
            // Check whether its inputs are marked in mapNextTx.
            auto it3 = mapNextTx.find(txin.prevout);
            assert(it3 != mapNextTx.end());
            assert(it3->first == &txin.prevout);
            assert(it3->second == &tx);
            i++;
        }
        assert(setParentCheck == GetMemPoolParents(it));
        // Verify ancestor state is correct.
        setEntries setAncestors;
        uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
        std::string dummy;
        CalculateMemPoolAncestors(*it, setAncestors, nNoLimit, nNoLimit, nNoLimit, nNoLimit, dummy);
        uint64_t nCountCheck = setAncestors.size() + 1;
        uint64_t nSizeCheck = it->GetTxSize();
        CAmount nFeesCheck = it->GetModifiedFee();
        int64_t nSigOpCheck = it->GetSigOpCost();

        for (txiter ancestorIt : setAncestors) {
            nSizeCheck += ancestorIt->GetTxSize();
            nFeesCheck += ancestorIt->GetModifiedFee();
            nSigOpCheck += ancestorIt->GetSigOpCost();
        }

        assert(it->GetCountWithAncestors() == nCountCheck);
        assert(it->GetSizeWithAncestors() == nSizeCheck);
        assert(it->GetSigOpCostWithAncestors() == nSigOpCheck);
        assert(it->GetModFeesWithAncestors() == nFeesCheck);

        // Check children against mapNextTx
        CTxMemPool::setEntries setChildrenCheck;
        auto iter = mapNextTx.lower_bound(COutPoint(it->GetTx().GetHash(), 0));
        int64_t childSizes = 0;
        for (; iter != mapNextTx.end() && iter->first->hash == it->GetTx().GetHash(); ++iter) {
            txiter childit = mapTx.find(iter->second->GetHash());
            assert(childit != mapTx.end()); // mapNextTx points to in-mempool transactions
            if (setChildrenCheck.insert(childit).second) {
                childSizes += childit->GetTxSize();
            }
        }
        assert(setChildrenCheck == GetMemPoolChildren(it));
        // Also check to make sure size is greater than sum with immediate children.
        // just a sanity check, not definitive that this calc is correct...
        assert(it->GetSizeWithDescendants() >= childSizes + it->GetTxSize());

        if (fDependsWait)
            waitingOnDependants.push_back(&(*it));
        else {
            CValidationState state;
            bool fCheckResult = tx.IsCoinBase() ||
                Consensus::CheckTxInputs(tx, state, mempoolDuplicate, nSpendHeight);
            assert(fCheckResult);
            UpdateCoins(tx, mempoolDuplicate, 1000000);
        }
    }
    unsigned int stepsSinceLastRemove = 0;
    while (!waitingOnDependants.empty()) {
        const CTxMemPoolEntry* entry = waitingOnDependants.front();
        waitingOnDependants.pop_front();
        CValidationState state;
        if (!mempoolDuplicate.HaveInputs(entry->GetTx())) {
            waitingOnDependants.push_back(entry);
            stepsSinceLastRemove++;
            assert(stepsSinceLastRemove < waitingOnDependants.size());
        } else {
            bool fCheckResult = entry->GetTx().IsCoinBase() ||
                Consensus::CheckTxInputs(entry->GetTx(), state, mempoolDuplicate, nSpendHeight);
            assert(fCheckResult);
            UpdateCoins(entry->GetTx(), mempoolDuplicate, 1000000);
            stepsSinceLastRemove = 0;
        }
    }
    for (auto it = mapNextTx.cbegin(); it != mapNextTx.cend(); it++) {
        uint256 hash = it->second->GetHash();
        indexed_transaction_set::const_iterator it2 = mapTx.find(hash);
        const CTransaction& tx = it2->GetTx();
        assert(it2 != mapTx.end());
        assert(&tx == it->second);
    }

    assert(totalTxSize == checkTotal);
    assert(innerUsage == cachedInnerUsage);
}

bool CTxMemPool::CompareDepthAndScore(const uint256& hasha, const uint256& hashb)
{
    LOCK(cs);
    indexed_transaction_set::const_iterator i = mapTx.find(hasha);
    if (i == mapTx.end()) return false;
    indexed_transaction_set::const_iterator j = mapTx.find(hashb);
    if (j == mapTx.end()) return true;
    uint64_t counta = i->GetCountWithAncestors();
    uint64_t countb = j->GetCountWithAncestors();
    if (counta == countb) {
        return CompareTxMemPoolEntryByScore()(*i, *j);
    }
    return counta < countb;
}

namespace {
class DepthAndScoreComparator
{
public:
    bool operator()(const CTxMemPool::indexed_transaction_set::const_iterator& a, const CTxMemPool::indexed_transaction_set::const_iterator& b)
    {
        uint64_t counta = a->GetCountWithAncestors();
        uint64_t countb = b->GetCountWithAncestors();
        if (counta == countb) {
            return CompareTxMemPoolEntryByScore()(*a, *b);
        }
        return counta < countb;
    }
};
} // namespace

std::vector<CTxMemPool::indexed_transaction_set::const_iterator> CTxMemPool::GetSortedDepthAndScore() const
{
    std::vector<indexed_transaction_set::const_iterator> iters;
    AssertLockHeld(cs);

    iters.reserve(mapTx.size());

    for (indexed_transaction_set::iterator mi = mapTx.begin(); mi != mapTx.end(); ++mi) {
        iters.push_back(mi);
    }
    std::sort(iters.begin(), iters.end(), DepthAndScoreComparator());
    return iters;
}

void CTxMemPool::queryHashes(std::vector<uint256>& vtxid)
{
    LOCK(cs);
    auto iters = GetSortedDepthAndScore();

    vtxid.clear();
    vtxid.reserve(mapTx.size());

    for (auto it : iters) {
        vtxid.push_back(it->GetTx().GetHash());
    }
}

static TxMempoolInfo GetInfo(CTxMemPool::indexed_transaction_set::const_iterator it) {
    return TxMempoolInfo{it->GetSharedTx(), it->GetTime(), CFeeRate(it->GetFee(), it->GetTxSize()), it->GetModifiedFee() - it->GetFee()};
}

std::vector<TxMempoolInfo> CTxMemPool::infoAll() const
{
    LOCK(cs);
    auto iters = GetSortedDepthAndScore();

    std::vector<TxMempoolInfo> ret;
    ret.reserve(mapTx.size());
    for (auto it : iters) {
        ret.push_back(GetInfo(it));
    }

    return ret;
}

CTransactionRef CTxMemPool::get(const uint256& hash) const
{
    LOCK(cs);
    indexed_transaction_set::const_iterator i = mapTx.find(hash);
    if (i == mapTx.end())
        return nullptr;
    return i->GetSharedTx();
}

TxMempoolInfo CTxMemPool::info(const uint256& hash) const
{
    LOCK(cs);
    indexed_transaction_set::const_iterator i = mapTx.find(hash);
    if (i == mapTx.end())
        return TxMempoolInfo();
    return GetInfo(i);
}

void CTxMemPool::PrioritiseTransaction(const uint256& hash, const CAmount& nFeeDelta)
{
    {
        LOCK(cs);
        CAmount &delta = mapDeltas[hash];
        delta += nFeeDelta;
        txiter it = mapTx.find(hash);
        if (it != mapTx.end()) {
            mapTx.modify(it, update_fee_delta(delta));
            // Now update all ancestors' modified fees with descendants
            setEntries setAncestors;
            uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
            std::string dummy;
            CalculateMemPoolAncestors(*it, setAncestors, nNoLimit, nNoLimit, nNoLimit, nNoLimit, dummy, false);
            for (txiter ancestorIt : setAncestors) {
                mapTx.modify(ancestorIt, update_descendant_state(0, nFeeDelta, 0));
            }
            // Now update all descendants' modified fees with ancestors
            setEntries setDescendants;
            CalculateDescendants(it, setDescendants);
            setDescendants.erase(it);
            for (txiter descendantIt : setDescendants) {
                mapTx.modify(descendantIt, update_ancestor_state(0, nFeeDelta, 0, 0));
            }
            ++nTransactionsUpdated;
        }
    }
    LogPrintf("PrioritiseTransaction: %s feerate += %s\n", hash.ToString(), FormatMoney(nFeeDelta));
}

void CTxMemPool::ApplyDelta(const uint256 hash, CAmount &nFeeDelta) const
{
    LOCK(cs);
    std::map<uint256, CAmount>::const_iterator pos = mapDeltas.find(hash);
    if (pos == mapDeltas.end())
        return;
    const CAmount &delta = pos->second;
    nFeeDelta += delta;
}

void CTxMemPool::ClearPrioritisation(const uint256 hash)
{
    LOCK(cs);
    mapDeltas.erase(hash);
}

bool CTxMemPool::HasNoInputsOf(const CTransaction &tx) const
{
    for (unsigned int i = 0; i < tx.vin.size(); i++)
        if (exists(tx.vin[i].prevout.hash))
            return false;
    return true;
}

CCoinsViewMemPool::CCoinsViewMemPool(CCoinsView* baseIn, const CTxMemPool& mempoolIn) : CCoinsViewBacked(baseIn), mempool(mempoolIn) { }

bool CCoinsViewMemPool::GetCoin(const COutPoint &outpoint, Coin &coin) const {
    // If an entry in the mempool exists, always return that one, as it's guaranteed to never
    // conflict with the underlying cache, and it cannot have pruned entries (as it contains full)
    // transactions. First checking the underlying cache risks returning a pruned entry instead.
    CTransactionRef ptx = mempool.get(outpoint.hash);
    if (ptx) {
        if (outpoint.n < ptx->vout.size()) {
            coin = Coin(ptx->vout[outpoint.n], MEMPOOL_HEIGHT, false);
            return true;
        } else {
            return false;
        }
    }
    return base->GetCoin(outpoint, coin);
}

size_t CTxMemPool::DynamicMemoryUsage() const {
    LOCK(cs);
    // Estimate the overhead of mapTx to be 15 pointers + an allocation, as no exact formula for boost::multi_index_contained is implemented.
    return memusage::MallocUsage(sizeof(CTxMemPoolEntry) + 15 * sizeof(void*)) * mapTx.size() + memusage::DynamicUsage(mapNextTx) + memusage::DynamicUsage(mapDeltas) + memusage::DynamicUsage(mapLinks) + memusage::DynamicUsage(vTxHashes) + cachedInnerUsage;
}

void CTxMemPool::RemoveStaged(setEntries &stage, bool updateDescendants, MemPoolRemovalReason reason) {
    AssertLockHeld(cs);
    UpdateForRemoveFromMempool(stage, updateDescendants);
    for (const txiter& it : stage) {
        removeUnchecked(it, reason);
    }
}

int CTxMemPool::Expire(int64_t time) {
    LOCK(cs);
    indexed_transaction_set::index<entry_time>::type::iterator it = mapTx.get<entry_time>().begin();
    setEntries toremove;
    while (it != mapTx.get<entry_time>().end() && it->GetTime() < time) {
        toremove.insert(mapTx.project<0>(it));
        it++;
    }
    setEntries stage;
    for (txiter removeit : toremove) {
        CalculateDescendants(removeit, stage);
    }
    RemoveStaged(stage, false, MemPoolRemovalReason::EXPIRY);
    return stage.size();
}

bool CTxMemPool::addUnchecked(const uint256&hash, const CTxMemPoolEntry &entry, bool validFeeEstimate)
{
    LOCK(cs);
    setEntries setAncestors;
    uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
    std::string dummy;
    CalculateMemPoolAncestors(entry, setAncestors, nNoLimit, nNoLimit, nNoLimit, nNoLimit, dummy);
    return addUnchecked(hash, entry, setAncestors, validFeeEstimate,true);
}

void CTxMemPool::UpdateChild(txiter entry, txiter child, bool add)
{
    setEntries s;
    if (add && mapLinks[entry].children.insert(child).second) {
        cachedInnerUsage += memusage::IncrementalDynamicUsage(s);
    } else if (!add && mapLinks[entry].children.erase(child)) {
        cachedInnerUsage -= memusage::IncrementalDynamicUsage(s);
    }
}

void CTxMemPool::UpdateParent(txiter entry, txiter parent, bool add)
{
    setEntries s;
    if (add && mapLinks[entry].parents.insert(parent).second) {
        cachedInnerUsage += memusage::IncrementalDynamicUsage(s);
    } else if (!add && mapLinks[entry].parents.erase(parent)) {
        cachedInnerUsage -= memusage::IncrementalDynamicUsage(s);
    }
}

const CTxMemPool::setEntries & CTxMemPool::GetMemPoolParents(txiter entry) const
{
    assert (entry != mapTx.end());
    txlinksMap::const_iterator it = mapLinks.find(entry);
    assert(it != mapLinks.end());
    return it->second.parents;
}

const CTxMemPool::setEntries & CTxMemPool::GetMemPoolChildren(txiter entry) const
{
    assert (entry != mapTx.end());
    txlinksMap::const_iterator it = mapLinks.find(entry);
    assert(it != mapLinks.end());
    return it->second.children;
}

CFeeRate CTxMemPool::GetMinFee(size_t sizelimit) const {
    LOCK(cs);
    if (!blockSinceLastRollingFeeBump || rollingMinimumFeeRate == 0)
        return CFeeRate(rollingMinimumFeeRate);

    int64_t time = GetTime();
    if (time > lastRollingFeeUpdate + 10) {
        double halflife = ROLLING_FEE_HALFLIFE;
        if (DynamicMemoryUsage() < sizelimit / 4)
            halflife /= 4;
        else if (DynamicMemoryUsage() < sizelimit / 2)
            halflife /= 2;

        rollingMinimumFeeRate = rollingMinimumFeeRate / pow(2.0, (time - lastRollingFeeUpdate) / halflife);
        lastRollingFeeUpdate = time;

        if (rollingMinimumFeeRate < (double)incrementalRelayFee.GetFeePerK() / 2) {
            rollingMinimumFeeRate = 0;
            return CFeeRate(0);
        }
    }
    return std::max(CFeeRate(rollingMinimumFeeRate), incrementalRelayFee);
}

void CTxMemPool::trackPackageRemoved(const CFeeRate& rate) {
    AssertLockHeld(cs);
    if (rate.GetFeePerK() > rollingMinimumFeeRate) {
        rollingMinimumFeeRate = rate.GetFeePerK();
        blockSinceLastRollingFeeBump = false;
    }
}

void CTxMemPool::TrimToSize(size_t sizelimit, std::vector<COutPoint>* pvNoSpendsRemaining) {
    LOCK(cs);

    unsigned nTxnRemoved = 0;
    CFeeRate maxFeeRateRemoved(0);
    while (!mapTx.empty() && DynamicMemoryUsage() > sizelimit) {
        indexed_transaction_set::index<descendant_score>::type::iterator it = mapTx.get<descendant_score>().begin();

        // We set the new mempool min fee to the feerate of the removed set, plus the
        // "minimum reasonable fee rate" (ie some value under which we consider txn
        // to have 0 fee). This way, we don't allow txn to enter mempool with feerate
        // equal to txn which were removed with no block in between.
        CFeeRate removed(it->GetModFeesWithDescendants(), it->GetSizeWithDescendants());
        removed += incrementalRelayFee;
        trackPackageRemoved(removed);
        maxFeeRateRemoved = std::max(maxFeeRateRemoved, removed);

        setEntries stage;
        CalculateDescendants(mapTx.project<0>(it), stage);
        nTxnRemoved += stage.size();

        std::vector<CTransaction> txn;
        if (pvNoSpendsRemaining) {
            txn.reserve(stage.size());
            for (txiter iter : stage)
                txn.push_back(iter->GetTx());
        }
        RemoveStaged(stage, false, MemPoolRemovalReason::SIZELIMIT);
        if (pvNoSpendsRemaining) {
            for (const CTransaction& tx : txn) {
                for (const CTxIn& txin : tx.vin) {
                    if (exists(txin.prevout.hash)) continue;
                    pvNoSpendsRemaining->push_back(txin.prevout);
                }
            }
        }
    }

    if (maxFeeRateRemoved > CFeeRate(0)) {
        LogPrint(BCLog::MEMPOOL, "Removed %u txn, rolling minimum fee bumped to %s\n", nTxnRemoved, maxFeeRateRemoved.ToString());
    }
}

bool CTxMemPool::TransactionWithinChainLimit(const uint256& txid, size_t chainLimit) const {
    LOCK(cs);
    auto it = mapTx.find(txid);
    return it == mapTx.end() || (it->GetCountWithAncestors() < chainLimit &&
       it->GetCountWithDescendants() < chainLimit);
}

SaltedTxidHasher::SaltedTxidHasher() : k0(GetRand(std::numeric_limits<uint64_t>::max())), k1(GetRand(std::numeric_limits<uint64_t>::max())) {}
