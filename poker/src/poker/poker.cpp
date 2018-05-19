#include "poker.h"

#ifdef WIN32
    #pragma comment(lib, "libcurl.lib")
#endif

tmcg::tmcg()
{
	assert(init_libTMCG());//检测运行环境
	// init curl
	curl_global_init(CURL_GLOBAL_ALL);

	tmcgOne = nullptr;
	vtmfOne = nullptr;
	vsshe 	= nullptr;
	vtmf1 	= nullptr;

	s.clear();
	flop.clear();
	selfip.clear();
	open_flop.clear();
	hand_flop.clear();
	open_hand.clear();
	private_hand.clear();
	PokerBalance.clear();
	TxTimeOutHash.clear();
	mMatchAddress.clear();
	vWinIndex.clear();
	vFlopCardMsg.clear();
	countRecv = 0;
	PublicIndex = 0;
	countVerify = 0;

	myindex = -1;
	lieIndex = -1;
	playersize = -1;
	TxChainHeight = -1;

	isOne = false;
	TimeOut = false;
	creaetpukey = false;
	IsOver = false;
}

tmcg::~tmcg()
{
	delete tmcgOne;
	delete vtmfOne;
	delete vsshe;
	delete vtmf1;
	s.clear();
	flop.clear();
	selfip.clear();
	open_flop.clear();
	hand_flop.clear();
	open_hand.clear();
	private_hand.clear();
	PokerBalance.clear();
	TxTimeOutHash.clear();
}
void tmcg::PublishGroup()//产生全局句柄(主动)
{
	vtmfOne = new BarnettSmartVTMF_dlog();
	tmcgOne = new SchindelhauerTMCG(64, playersize, 6);
	assert(vtmfOne->CheckGroup());
	vtmfOne->PublishGroup(vtmf_str);

}
const std::string tmcg::getVtmfHandle()//返回句柄(仅在主动产生情况下被调用)
{
	return vtmf_str.str();
}
void tmcg::PublishGroup(std::string &vtmf)//初始化全局句柄(被动)
{
	vtmf_str << vtmf;
}

bool tmcg::VTMF_dlog()
{
	tmcgOne = new SchindelhauerTMCG(64, playersize, 6);
	vtmfOne = new BarnettSmartVTMF_dlog(vtmf_str);
	return vtmfOne->CheckGroup();
}

void tmcg::createPublicKey(std::string &pubkey)
{
	if(creaetpukey){
		return;
	}
	std::stringstream pubkeystr;
	vtmfOne->KeyGenerationProtocol_GenerateKey();//创建公钥
	vtmfOne->KeyGenerationProtocol_PublishKey(pubkeystr);//导出
	pubkey = pubkeystr.str();
	creaetpukey = true;
}

bool tmcg::verifyPubKey(const std::string &pubkey)//验证公钥
{
	std::stringstream pubkeyVerify;
	pubkeyVerify << pubkey;
	return vtmfOne->KeyGenerationProtocol_UpdateKey(pubkeyVerify);
}

void tmcg::updatePubkey()//更新公钥
{
	vtmfOne->KeyGenerationProtocol_Finalize();
}

bool tmcg::createSshe()// 创建sshe(主动)
{
	vsshe = new GrothVSSHE(DECKSIZE, vtmfOne->p, vtmfOne->q, vtmfOne->k, vtmfOne->g, vtmfOne->h);
	return vsshe->CheckGroup();
}
void tmcg::createSshe(std::string &sshestr)// 创建sshe(被动)
{
	std::stringstream msgStream;
	msgStream << sshestr;
	vsshe = new GrothVSSHE(DECKSIZE, msgStream);
}
void tmcg::educeSshe(std::string &sshekey)//导出sshe(主动)
{
	std::stringstream sshestr;
	vsshe->PublishGroup(sshestr);
	sshekey = sshestr.str();
}

bool tmcg::verifySsheKey()// 验证sshe(被动)
{
	do
	{
		if (!vsshe->CheckGroup())
		{
			std::cout << "VSSHE instance was not correctly generated!" << std::endl;
			break;
		}

		if (mpz_cmp(vtmfOne->h, vsshe->com->h))
		{
			std::cout << "VSSHE: Common public key does not match!" << std::endl;
			break;
		}
		if (mpz_cmp(vtmfOne->q, vsshe->com->q))
		{
			std::cout << "VSSHE: Subgroup order does not match!" << std::endl;
			break;
		}
		if (mpz_cmp(vtmfOne->p, vsshe->p) || mpz_cmp(vtmfOne->q, vsshe->q) || mpz_cmp(vtmfOne->g, vsshe->g) || mpz_cmp(vtmfOne->h, vsshe->h))
		{
			std::cout << "VSSHE: Encryption scheme does not match!" << std::endl;
			break;
		}
		return true;
	}while(0);

	return false;
}

void tmcg::createCard()
{
	TMCG_OpenStack<VTMF_Card> deck;
	for (int type = 0; type < DECKSIZE; type++)
	{
		VTMF_Card c;
		tmcgOne->TMCG_CreateOpenCard(c, vtmfOne, type);
		deck.push(type, c);
	}
	s.push(deck);
}

std::string tmcg::shuffleCard()//洗牌(主动)
{
	std::stringstream cardMsg;
	TMCG_Stack<VTMF_Card> s2;
	TMCG_StackSecret<VTMF_CardSecret> ss;
	std::stringstream lej;
	tmcgOne->TMCG_CreateStackSecret(ss, false, s.size(), vtmfOne);
	tmcgOne->TMCG_MixStack(s, s2, ss, vtmfOne);
	tmcgOne->TMCG_ProveStackEquality_Groth_noninteractive(s, s2,ss, vtmfOne, vsshe, lej);

	cardMsg << s2 << std::endl;
	cardMsg << lej.str();

	s = s2;
	return cardMsg.str();
}

bool tmcg::verifyShuffleCard(std::string &shuffleCardMsg)//验证洗牌(被动)
{
	std::stringstream msgStream;
	msgStream << shuffleCardMsg;
	TMCG_Stack<VTMF_Card> s2;
	msgStream >> s2;
	bool ret = tmcgOne->TMCG_VerifyStackEquality_Groth_noninteractive(s, s2,vtmfOne, vsshe, msgStream);
	s = s2;
	return ret;
}
void tmcg::createHandCard()// 为每个人创建一副手牌
{
	for (int i = 0; i < playersize; i++)//选取手牌
	{
		for (int j = 0; j < HANDSIZE; j++)
		{
			VTMF_Card c;
			s.pop(c);
			hand[i].push(c);
			hand_flop.push(c);/////////////////////////// hand_flop
		}
	}
}
std::string tmcg::proveCardSecret(const int m,const int k)// 产生第m个人第k张手牌消息
{
	std::stringstream in, out;
	tmcgOne->TMCG_ProveCardSecret(hand[m][k], vtmfOne,in,out);
	return out.str();
}

void tmcg::selfCardSecret(const int m,const int k)
{
	tmcgOne->TMCG_SelfCardSecret(hand[m][k], vtmfOne);
}
void tmcg::selfFlopSecret(const int k)
{
	//std::cout << "k is " << k << std::endl;
	tmcgOne->TMCG_SelfCardSecret(flop[k], vtmfOne);
}
bool tmcg::verifyCardSecret(const int m,const int k,std::string& handmsg)// 验证手牌(仅验证自己的)
{
	std::stringstream in, out;
	in << handmsg;
	return tmcgOne->TMCG_VerifyCardSecret(hand[m][k], vtmfOne, in, out);
}

void tmcg::saveHandCard(const int m,const int k)//验证通过后保存手牌
{
	int type = tmcgOne->TMCG_TypeOfCard(hand[m][k], vtmfOne);
	if(!private_hand.find(type))
	{
		private_hand.push(type, hand[m][k]);
	}
}

void tmcg::createFlopCard()//创建公共牌
{
	for (int j = 0; j < FLOPSIZE; j++)
	{
		VTMF_Card c;
		s.pop(c);
		flop.push(c);
	}
}

std::string tmcg::proveFlopSecret(const int k)
{
	std::stringstream in, out;
	tmcgOne->TMCG_ProveCardSecret(flop[k], vtmfOne, in, out);
	return out.str();
}

///////////////////////////////////////////		hand_flop	start
std::string tmcg::proveHandFlopSecret(const int k)
{
	std::stringstream in, out;
	tmcgOne->TMCG_ProveCardSecret(hand_flop[k], vtmfOne, in, out);
	return out.str();
}
bool tmcg::verifyHandFlopSecret(const int k, std::string &msg)
{
	std::stringstream in, out;
	in << msg;
	return tmcgOne->TMCG_VerifyCardSecret(hand_flop[k], vtmfOne, in, out);
}
void tmcg::selfHandFlopSecret(const int k)
{
	tmcgOne->TMCG_SelfCardSecret(hand_flop[k], vtmfOne);
}
void tmcg::saveHandFlopCard(const int i)
{
	int type = tmcgOne->TMCG_TypeOfCard(hand_flop[i], vtmfOne);
	open_hand.push(type, hand_flop[i]);
	std::cout << "saveHandFlopCard type is " << type << std::endl;
}
///////////////////////////////////////////		hand_flop	end
bool tmcg::verifyFlopSecret(const int k, std::string &msg)
{
	std::stringstream in, out;
	in << msg;
	return tmcgOne->TMCG_VerifyCardSecret(flop[k], vtmfOne, in, out);
}

void tmcg::saveFlopCard(const int i)
{

	int type = tmcgOne->TMCG_TypeOfCard(flop[i], vtmfOne);
	open_flop.push(type, flop[i]);
}

void tmcg::showFlopCard()
{
	for(int i = 0;i < FLOPSIZE; ++i)
		std::cout << open_flop[i].first << " ";
	std::cout << std::endl;
}

bool tmcg::isRecvVerify()
{
	return countVerify == playersize -1;
}

void tmcg::zeroRecvVerify()
{
	countRecv = 0;
	countVerify = 0;
}


bool tmcg::IsFlopOpen(BetIpfsMsg& msg)
{
	if (vTxBetVerify.empty())
		return false;
	
	// TODO
	if (mPlayerIndex[msg.nextBetTxID] < myindex) {
		
		if (msg.maxBet == 0) {
			std::cout << "------------------------ IsFlopOpen: " << "全部让牌........." << std::endl;
			return true;
		}
		
		for(auto &it: msg.mHasBet)
		{
			if (msg.mPlayerStatus[mPlayerIndex[it.first]] == PS_DEFAULT && it.second == msg.maxBet)
				continue;

			if (msg.mPlayerStatus[mPlayerIndex[it.first]] == PS_ALLIN && it.second <= msg.maxBet)
				continue;

			if (msg.mPlayerStatus[mPlayerIndex[it.first]] == PS_DISCARD)
				continue;

			return false;
		}
		return true;
	}
	
	return false;
}


std::string tmcg::showPoker(int type){
	int color = type / 13 + 1;
	int number = type % 13 + 2;
	std::string res;

	switch(color){
		case 1:
			res = "方片";
			break;
		case 2:
			res = "梅花";
			break;
		case 3:
			res = "黑桃";
			break;
		case 4:
			res = "红心";
			break;
	}

	switch(number){
		case 14:
			res += "A";
			break;
		case 13:
			res += "K";
			break;
		case 12:
			res += "Q";
			break;
		case 11:
			res += "J";
			break;
		default:
			res += std::to_string(number);
			break;
	}
	return res;
}


int tmcg::showPokerNumber(int type){
	int color = type / 13 + 1;
	int number = type % 13 + 2;
	return color * 100 + number;
}


void tmcg::showPlayerInfo()
{
	std::cout << "\n******************************* 更新玩家状态 *******************************" << std::endl;
	for(auto &it: g_tmcg->gBetIpfsMsg.mBalance)
	{
		std::string status;
		int index = g_tmcg->mPlayerIndex[it.first];
		switch(g_tmcg->gBetIpfsMsg.mPlayerStatus[index])
		{
			case PS_DEFAULT :
				status = "等待下注";
				break;
			case PS_DISCARD :
				status = "弃牌";
				break;
			case PS_ALLIN :
				status = "已经全下";
				break;
		}
		if(g_tmcg->gBetIpfsMsg.nextBetTxID == it.first)
		{
			status = "将要下注";
		}
		std::cout << "玩家[" << index << "]" << "已经下了[" << g_tmcg->gBetIpfsMsg.mHasBet[it.first] << "]币 " << ", 还有[" << it.second << "]币" << ", 当前状态是: " << status << std::endl;
	}

	std::cout << "maxbet     :  " << g_tmcg->gBetIpfsMsg.maxBet << std::endl;
	std::cout << "jackpot	 :  " << g_tmcg->gBetIpfsMsg.jackpot << std::endl;
	std::cout << "nextplayer :  " << g_tmcg->mPlayerIndex[g_tmcg->gBetIpfsMsg.nextBetTxID] << std::endl;
	std::cout << "fFlopCard:    " << g_tmcg->gBetIpfsMsg.fFlopCard << std::endl;
	std::cout << "publicIndex:  " << g_tmcg->gBetIpfsMsg.publicIndex << std::endl;
	std::cout << "fGameOver:    " << g_tmcg->gBetIpfsMsg.fGameOver << std::endl;

	std::cout << "公共牌 : ";
	for(size_t k = 0; k < g_tmcg->open_flop.size(); k++)
	{
		std::cout << showPoker(g_tmcg->open_flop[k].first) << " ";
	}
	std::cout << std::endl;

	if(open_hand.empty())
	{
		if(!private_hand.empty())
		{
			std::cout << "手牌 : " ;
			for(size_t i = 0; i < private_hand.size(); ++i)
			{
				std::cout << showPoker(private_hand[i].first) << " ";
			}
			std::cout << std::endl;
		}
	}
	else
	{
		std::cout << "所有人的手牌 : " ;
		for(size_t i = 0;i < open_hand.size(); ++i)
		{
			std::cout << showPoker(open_hand[i].first) << " ";
		}
		std::cout << std::endl;
		std::cout << "*******************************  游戏结束 *******************************" << std::endl;
	}


	if (g_tmcg->gBetIpfsMsg.fGameOver && g_tmcg->open_flop.size() == 5 && open_hand.empty()) {
		std::cout << "*******************************  游戏结束, 公开手牌 *******************************" << std::endl;
	}
	else if (!g_tmcg->gBetIpfsMsg.fGameOver && g_tmcg->gBetIpfsMsg.fFlopCard) {
		std::cout << "--> 开始发第"  << g_tmcg->gBetIpfsMsg.publicIndex << "轮公共牌" << std::endl;
	}
	else {
		int ret = isGameOver();
		if (ret == -1)
		{
			if (open_flop.size() < 5) {
				std::cout << "**************************** 其它玩家都已经全下或弃牌, 发剩下的公共牌 ****************************" << std::endl;
			}
			else
			{
				std::cout << "**************************** 其它玩家都已经全下或弃牌, 游戏结束 ****************************" << std::endl;
			}
		}
		else if (ret > 0)
		{
			std::cout << "**************************** 其它玩家都已经全下或弃牌, 游戏结束 ****************************" << std::endl;
		}
	}

	std::cout << "**************************** 更新玩家状态 ****************************\n" << std::endl;
}


void tmcg::initBetIpfsMsg(BetIpfsMsg &msg)
{
	msg.curBetTxID = "";
	msg.curBet = 0;
	msg.maxBet = 0;
	msg.jackpot = 0;
	msg.publicIndex = 0;
	msg.fGameOver = false;
	msg.fFlopCard = false;

	for (auto &it: mPlayerIndex) {
		if (it.second == 0) {
			msg.nextBetTxID = it.first;
			nextBetTxID = it.first;
		}
		msg.mHasBet[it.first] = 0;
		msg.mPlayerStatus[it.second] = PlayerStatus::PS_DEFAULT;
	}

	msg.mBalance = mPokerBalance;
}


void tmcg::printBetIpfsMsg(BetIpfsMsg& msg)
{
	std::cout << "curBetTxID:  " << msg.curBetTxID << std::endl;
	std::cout << "nextBetTxID: " << msg.nextBetTxID << std::endl;
	std::cout << "curBet:      " << msg.curBet << std::endl;
	std::cout << "maxBet:      " << msg.maxBet << std::endl;
	std::cout << "jackpot:      " << msg.jackpot << std::endl;
	std::cout << "fFlopCard:   " << msg.fFlopCard << std::endl;
	std::cout << "publicIndex: " << msg.publicIndex << std::endl;
	std::cout << "fGameOver:   " << msg.fGameOver << std::endl;

	std::cout << "mHasBet:" << std::endl;
	for (auto &it: msg.mHasBet) {
		std::cout << "txid:    " << it.first << " -- hasbet:  " << it.second << std::endl;
	}
	std::cout << "mBalance:" << std::endl;
	for (auto &it: msg.mBalance) {
		std::cout << "txid:    " << it.first << " -- balance: " << it.second << std::endl;
	}
	std::cout << "mPlayerStatus:" << std::endl;
	for (auto &it: msg.mPlayerStatus) {
		std::cout << "txindex: " << it.first << "    -- status:  " << it.second << std::endl;
	}
}

void tmcg::clearPoker()
{
	for (int i = 0; i < playersize; i++) {
        hand[i].clear();
    }

	myindex = -1;
	playersize = 0;
	selfaddress.clear();
	pokeraddress.clear();
	matchTxID.clear();
	matchTableID.clear();
	fAllPubkeyVerify = false;
	fMyPubkeyVerify = false;
	mPlayerIndex.clear();
	mPlayerTxid.clear();
	mMatchAddress.clear();
	mPokerAddress.clear();
	mPokerBalance.clear();
	mPubkeyVerify.clear();
	mHandCardVerify.clear();
	mFlopCardVerify.clear();
	mOpenFlopVerify.clear();
	mPokerBalanceTx.clear();
	nextShuffleIndex = 0;
	nextBetTxID.clear();

	fPokerAddressVerify = false;
	fSendFlopCardTx = false;
	fPubkeyVerTx = false;
	fVerifySSHE = false;
	fHandCardTx = false;
	fOpenHandTx = false;
	fVerifyFlopCard = false;

	vWinIndex.clear();
	lieIndex = -1;
	IsOver = false;
	TimeOut = false;

	selfpubkey.clear();
	selfsshe.clear();
	selfshuffle.clear();
	vtmf_str.clear();
	vtmf1 = nullptr;
	tmcgOne = nullptr;
	vtmfOne = nullptr;
	vsshe = nullptr;
	s.clear();
	private_hand.clear();
	flop.clear();
	open_flop.clear();
	open_hand.clear();
	hand_flop.clear();
	isOne = false;
	countVerify = 0;

	gBetIpfsMsg.curBetTxID.clear();
	gBetIpfsMsg.nextBetTxID.clear();
	gBetIpfsMsg.curBet = 0;
	gBetIpfsMsg.maxBet = 0;
	gBetIpfsMsg.jackpot = 0;
	gBetIpfsMsg.fFlopCard = false;
	gBetIpfsMsg.publicIndex = 0;
	gBetIpfsMsg.fGameOver = false;
	
	// Egret
	vShuffleMsg.clear();  
	vHandCardMsg.clear();
	vFlopCardMsg.clear();
	mPokerTypes.clear();
	mBestGroups.clear();
	fDiscardMsg = false;
}

//回溯交易

int isGameOver()
{
	int betIndex = 0;
	int allIndex = 0;
	int betNum = 0;
	int allNum = 0;
	int disNum = 0;
	for (auto &it: g_tmcg->gBetIpfsMsg.mPlayerStatus) {
		if(it.second == PlayerStatus::PS_DEFAULT){
			betNum++;
			betIndex = it.first;
		}
		if(it.second == PlayerStatus::PS_DISCARD){
			disNum++;
		}

		if(it.second == PlayerStatus::PS_ALLIN){
			allNum++;
			allIndex = it.first;
		}
	}

	//其他人都弃牌,只剩一个人下注或全下
	if (disNum == g_tmcg->playersize - 1) {
		return betIndex > 0 ? betIndex : allIndex;
	}
	//有人全下,并且只剩一个人还可以下注
	else if (betNum == 1 && allNum > 0) {
		for (auto &it: g_tmcg->mPlayerIndex) {
			if (it.second == betIndex) {
				if (g_tmcg->gBetIpfsMsg.mHasBet[it.first] >= g_tmcg->gBetIpfsMsg.maxBet) {
					return -1;
				}
			}
		}
	}
	//所有人都全下或弃牌
	else if (betNum == 0 && allNum > 0) {
		return -1;
	}

	return -2;
}


int isGameOver(BetIpfsMsg msg)
{
	int betIndex = 0;
	int allIndex = 0;
	int betNum = 0;
	int allNum = 0;
	int disNum = 0;
	for (auto &it: msg.mPlayerStatus) {
		if(it.second == PlayerStatus::PS_DEFAULT){
			betNum++;
			betIndex = it.first;
		}
		if(it.second == PlayerStatus::PS_DISCARD){
			disNum++;
		}

		if(it.second == PlayerStatus::PS_ALLIN){
			allNum++;
			allIndex = it.first;
		}
	}

	//其他人都弃牌,只剩一个人下注或全下
	if (disNum == g_tmcg->playersize - 1) {
		return betIndex > 0 ? betIndex : allIndex;
	}
	//有人全下,并且只剩一个人还可以下注
	else if (betNum == 1 && allNum > 0) {
		for (auto &it: g_tmcg->mPlayerIndex) {
			if (it.second == betIndex) {
				if (msg.mHasBet[it.first] >= msg.maxBet) {
					return -1;
				}
			}
		}
	}
	//所有人都全下或弃牌
	else if (betNum == 0 && allNum > 0) {
		return -1;
	}

	return -2;
}


void ipfsCatFile(std::string & hash, std::string & getResponseStr)
{
	std::string url = "http://localhost:5001/api/v0/cat?arg=" + hash;
	std::cout << "url : " << url << std::endl;
	auto ret = curl_get_req(url, getResponseStr);
	if (ret != CURLE_OK)
	{
		std::cerr << "curl get failed: " + std::string(curl_easy_strerror(ret)) << std::endl;
	}
}

bool verifyBalcnceIpfs(const CScript &script, int& lieIndex)
{
	std::string msgHash(script.begin() + 68, script.end());
	std::string getResponseStr;
	ipfsCatFile(msgHash, getResponseStr);

	json jsonMsg = json::parse(getResponseStr);
	std::string txid = jsonMsg["txID"].get<std::string>();
	int balance = jsonMsg["balance"].get<int>();

	if (g_tmcg->mPokerBalance[txid] != balance) {
		lieIndex = g_tmcg->mPlayerIndex[txid];
		return false;
	}
	return true;
}

bool verifyBalcnce(int& lieIndex)
{
	for (auto &it: g_tmcg->mPokerBalanceTx)
	{
		for (auto voutit: it.second.vout)
		{
			auto script = voutit.scriptPubKey;
			if(script[0] != OP_RETURN )
				continue;

			if(!verifyBalcnceIpfs(script, lieIndex))
				return false;
		}
	}
	return true;
}

//验证这一笔和上一笔交易信息是否合理
bool verifyBetMsgNode(MsgNode& PreTxMsg, MsgNode& VerifyMsg)
{
	if(PreTxMsg.NextIndex != VerifyMsg.FromIndex)
	{
		std::cout << "verifyBetMsgNode NextIndex error: " << VerifyMsg.FromIndex << std::endl;
		return false;
	}

	for(auto & it : PreTxMsg.PlayerStatus)
	{
		int index = it.first;
		if(index == VerifyMsg.FromIndex)// 上个玩家有没有违反规则
		{
			if((PreTxMsg.Balance[index] - VerifyMsg.Balance[index]) == (VerifyMsg.HasBet[index] - PreTxMsg.HasBet[index]) && (
				   VerifyMsg.HasBet[index] - PreTxMsg.HasBet[index]) == VerifyMsg.CurBet){}//下注
			else
			{
				std::cout << "CurBet --> Someone is lying : GameOver " << std::endl;
				return false;
			}
			if(VerifyMsg.HasBet[index] >= PreTxMsg.MaxBet)//最大注
			{
				if(VerifyMsg.MaxBet != VerifyMsg.HasBet[index])
				{
					std::cout << "MaxBet --> Someone is lying : GameOver " << std::endl;
					return false;
				}
			}

			if(VerifyMsg.PlayerStatus[index] == PS_ALLIN)
			{
				if(PreTxMsg.Balance[index] != VerifyMsg.CurBet)
				{
					std::cout << "PS_ALLIN --> Someone is lying : GameOver " << std::endl;
					return false;
				}
			}
			else if(VerifyMsg.PlayerStatus[index] == PS_DISCARD)
			{
				if(PreTxMsg.Balance[index] != VerifyMsg.Balance[index])
				{
					std::cout << "PS_DISCARD --> Someone is lying : GameOver " << std::endl;
					return false;
				}
			}
		}
		else
		{
			if(VerifyMsg.PlayerStatus[index] != it.second)//验证状态
			{
				std::cout << "PlayerStatus --> Someone is lying : GameOver " << std::endl;
				return false;
			}
			if(VerifyMsg.Balance[index] != PreTxMsg.Balance[index])//余额
			{
				std::cout << "Balance --> Someone is lying : GameOver " << std::endl;
				return false;
			}
		}
	}
	return true;
}

int calculateResult(std::vector<int> pubcard, std::map<int, std::vector<int>> handcard)
{
	g_tmcg->vWinIndex.clear();
	CCardType ct;
	long long max = 0;
	std::map<int, long long> resultMap;

	for(auto &it: handcard){
		ct.calculateResult(pubcard, it.second);
		long long bv = ct.getBestValue();
		
		// Egret
		g_tmcg->mPokerTypes[it.first] = ct.getBestType();
		g_tmcg->mBestGroups[it.first] = ct.getBestGroup();
		
		resultMap.insert(std::make_pair(it.first, bv));

		if(max < bv)
			max = bv;
	}

	for(auto &it: resultMap){
		if(it.second == max) {
			g_tmcg->vWinIndex.push_back(it.first);
			break;
		}
	}

	return g_tmcg->vWinIndex.size();
}


void saveTimeOutMsg(const std::string &ip,const std::string &txid)
{
	if( g_tmcg->nodeIndexMap.count(ip) == 0)return ;
	MsgTimeOut msg;
	msg.Ip = ip;
	msg.Txid = txid;
	msg.NextIndex = g_tmcg->nodeIndexMap[ip];
	vMsgTimeOut.push_back(msg);
}


//只适用于发公共牌的时候
int getNextIndex(MsgNode &betMsg)
{

	for(auto &it: betMsg.PlayerStatus){
		if(it.second == PS_DEFAULT)
			return it.first;
	}
	return 0;
}


int getBetNum(MsgNode &betMsg)
{
	int number = 0;
	for(auto &it : betMsg.PlayerStatus)
	{
		if(it.second == PS_DEFAULT)
		{
			++number;
		}
	}
	return number;
}


bool checkBetMsg(MsgNode &VerifyMsg,MsgNode &PreTxMsg)
{
	if(PreTxMsg.PublicIndex + 1 == VerifyMsg.PublicIndex)// 发完一轮公共牌后
	{
		std::cout <<  g_tmcg->RecvMsg.count(std::string(32,g_tmcg->PublicIndex + 48)) << std::endl;
		PreTxMsg = g_tmcg->RecvMsg[std::string(32,g_tmcg->PublicIndex + 48)];
		std::cout << "~~~~~~~~~~~~~~~~~~~~~~~~PUBLIC~~~~~MSG~~~~~~~~~~~~~~~~~~~~~~~~~~~~ " << std::endl;
	}

	if(PreTxMsg.NextIndex != VerifyMsg.FromIndex)
	{
		std::cout << "NextIndex --> Someone is lying : GameOver " << PreTxMsg.NextIndex << "  PublicIndex  " << g_tmcg->PublicIndex  << std::endl;
		return false;
	}

	for(auto & it : PreTxMsg.PlayerStatus)
	{
		int index = it.first;
		if(index == VerifyMsg.FromIndex)// 上个玩家有没有违反规则
		{
			if((PreTxMsg.Balance[index] - VerifyMsg.Balance[index]) == (VerifyMsg.HasBet[index] - PreTxMsg.HasBet[index]) && (
																		VerifyMsg.HasBet[index] - PreTxMsg.HasBet[index]) == VerifyMsg.CurBet){}//下注
			else
			{
				std::cout << "CurBet --> Someone is lying : GameOver " << std::endl;
				return false;
			}

			if(it.second != PS_ALLIN)
			{
				if(VerifyMsg.HasBet[index] >= PreTxMsg.MaxBet)//最大注
				{
					if(VerifyMsg.MaxBet != VerifyMsg.HasBet[index])// 没有更新最大注的话
					{
						std::cout << "MaxBet --> Someone is lying : GameOver " << std::endl;
						return false;
					}
				}
				else
				{
					if(VerifyMsg.MaxBet != PreTxMsg.MaxBet)//
					{
						std::cout << "VerifyMsg.MaxBet != PreTxMsg.MaxBet --> Someone is lying : GameOver " << std::endl;
						return false;
					}
				}
			}
			else
			{
				// allin
			}

			if(VerifyMsg.PlayerStatus[index] == PS_ALLIN)
			{
				if(PreTxMsg.Balance[index] != VerifyMsg.CurBet)
				{
					std::cout << "PS_ALLIN --> Someone is lying : GameOver "<< index << std::endl;
					return false;
				}
			}
			else if(VerifyMsg.PlayerStatus[index] == PS_DISCARD)
			{
				if(PreTxMsg.Balance[index] != VerifyMsg.Balance[index])
				{
					std::cout << "PS_DISCARD --> Someone is lying : GameOver " << index << std::endl;
					return false;
				}
			}
			//continue;
		}
		else
		{
			if(VerifyMsg.PlayerStatus[index] != it.second)//验证状态
			{
				std::cout << "PlayerStatus --> Someone is lying : GameOver " << std::endl;
				return false;
			}
			if(VerifyMsg.Balance[index] != PreTxMsg.Balance[index])//余额
			{
				std::cout << "Balance --> Someone is lying : GameOver " << std::endl;
				return false;
			}
		}
	}

	return true;
}

void getPokerBetData(const json &jsonMsg, BetIpfsMsg &curBetMsg)
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

BetIpfsMsg getBetMsgFromTx(const CTransaction &ctx)
{
	BetIpfsMsg resBetMsg;
	for (auto it: ctx.vout) {
		auto script = it.scriptPubKey;
		if(script[0] != OP_RETURN )
			continue;

		std::string msgHash(script.begin() + 68, script.end());
		std::string getResponseStr;
		ipfsCatFile(msgHash, getResponseStr);
		json jsonMsg = json::parse(getResponseStr);
		getPokerBetData(jsonMsg, resBetMsg);
		break;
	}
	return resBetMsg;
}

bool verifyBetIpfsMsg(BetIpfsMsg& preBetMsg, BetIpfsMsg& curBetMsg, std::string &error)
{
	// 发过公共牌
	if (preBetMsg.fFlopCard && !curBetMsg.fFlopCard)
	{
		preBetMsg.curBet = 0;
		preBetMsg.maxBet = 0;
		std::map<std::string, int> m = preBetMsg.mHasBet;
		for (auto &it: m) {
			it.second = 0;
		}
		std::swap(m,preBetMsg.mHasBet);
	}

	if (preBetMsg.nextBetTxID != curBetMsg.curBetTxID)
	{
		error = "verifyBetMsg NextIndex error. preBetMsg.nextBetTxID : " + preBetMsg.nextBetTxID + "  curBetMsg.curBetTxID : " + curBetMsg.curBetTxID;
		return false;
	}

	std::cout << "--> verifyBetMsg nextBetTxID ok" << std::endl;

	for (auto & it : preBetMsg.mPlayerStatus)
	{
		int index = it.first;
		int fromIndex = g_tmcg->mPlayerIndex[curBetMsg.curBetTxID];

		std::string txid = g_tmcg->mPlayerTxid[index];

		if(index == fromIndex)// 上个玩家有没有违反规则
		{
			if((preBetMsg.mBalance[txid] - curBetMsg.mBalance[txid]) == (curBetMsg.mHasBet[txid] - preBetMsg.mHasBet[txid]) && (
				   curBetMsg.mHasBet[txid] - preBetMsg.mHasBet[txid]) == curBetMsg.curBet){}//下注
			else
			{
				error =  " CurBet --> Someone is lying : GameOver " ;
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
					error =  " PS_ALLIN --> Someone is lying : GameOver " ;
					return false;
				}

				std::cout << "--> verifyBetMsg index == fromIndex PS_ALLIN ok" << std::endl;
			}

			else if (curBetMsg.mPlayerStatus[index] == PS_DISCARD)
			{
				if (preBetMsg.mBalance[txid] != curBetMsg.mBalance[txid])
				{
					std::cout << "preBetMsg.mBalance[txid] is : " << preBetMsg.mBalance[txid] << std::endl;
					std::cout << "curBetMsg.mBalance[txid] is : " << curBetMsg.mBalance[txid] << std::endl;
					error =  " PS_DISCARD --> Someone is lying : GameOver ";
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
				error = " PlayerStatus --> Someone is lying : GameOver ";
				return false;
			}

			std::cout << "--> verifyBetMsg  mPlayerStatus ok" << std::endl;

			if(curBetMsg.mBalance[txid] != preBetMsg.mBalance[txid])//余额
			{
				std::cout << "curBetMsg.mBalance[txid]  is : " << curBetMsg.mBalance[txid]  << std::endl;
				std::cout << "preBetMsg.mBalance[txid]  is : " << preBetMsg.mBalance[txid] << std::endl;
				error = " Balance --> Someone is lying : GameOver ";
				return false;
			}

			std::cout << "--> verifyBetMsg  mBalance ok" << std::endl;
		}

	}

	if(g_tmcg->IsFlopOpen(curBetMsg) != curBetMsg.fFlopCard)
	{
		error = "IsFlopOpen --> Someone is lying : GameOver ";
	}

	std::cout << "--> verifyBetMsg  ok" << std::endl;

	return true;
}

bool verifyBet(int& lieIndex)
{
	for (size_t i= 0; i < vTxBetVerify.size(); i++)
	{
		auto &ct = vTxBetVerify.at(i);			    //找到需要验证的交易
		BetIpfsMsg msg = getBetMsgFromTx(ct); 	    //找到交易对应的消息

		int curIndex = g_tmcg->mPlayerIndex[msg.curBetTxID];
		int nextIndex = g_tmcg->mPlayerIndex[msg.nextBetTxID];

		if (msg.mPlayerStatus[curIndex] != PS_DISCARD && ct.GetValueOut(true) / COIN != msg.curBet )	//验证交易数据和消息数据
		{
			lieIndex = curIndex;
			std::cout << "index " << lieIndex <<  " GetValueOut error. " << std::endl;
			return false;
		}

		BetIpfsMsg preMsg;
		if (i == 0)
		{
			g_tmcg->initBetIpfsMsg(preMsg);
		}
		else
		{
			auto &prect = vTxBetVerify.at(i - 1);			    //找到需要验证的交易
			preMsg = getBetMsgFromTx(prect);
		}

		std::string error;
		if (!verifyBetIpfsMsg(preMsg, msg, error))
		{
			lieIndex = curIndex;
			std::cout << "lieIndex: " << lieIndex << error << std::endl;
			return false;
		}

		if (i == vTxBetVerify.size()-1)
		{
			if (g_tmcg->TimeOut)
			{
				lieIndex = nextIndex;
				std::cout << "time out. " << lieIndex << std::endl;
				return false;
			}

			if (!msg.fGameOver)
			{
				std::cout << "game is not over. " << std::endl;
				return false;
			}
		}
	}

	return true;
}

/*
 * 0: OK -- 游戏还没开始
 * 1: OK -- verifyBalcnce失败,无惩罚
 * 2: OK -- verifyDeposit失败,押金没交完
 * 3: ERROR -- 洗牌超时,有人作弊,平分押金
 * 4: OK -- 还没开始下注
 * 5: OK -- 下注正常,游戏还没结束
 * 6: ERROR -- 有人作弊,平分押金和注码
 * 7: OK -- 正常结算
 * 8: OK -- 除了一个人,其它人全都弃牌,并且奖池为空,游戏结束,没人赢钱
 */
int pokerhistory(int& index, int& amount)
{
	std::cout << "-------- pokerhistory start --------" << std::endl;

	if(g_tmcg->gBetIpfsMsg.mBalance.size() < (size_t) g_tmcg->playersize)
	{
		return 0;
	}

	if(!verifyBalcnce(index))
	{
		return 1;
	}

	//3 TODO DepositVerify
	// return 2;

	if(vTxBetVerify.empty()){
		std::cout <<  "game is not beting. " << std::endl;
		return 4;
	}

	CTransaction lastTx = vTxBetVerify.at(vTxBetVerify.size()-1);
	BetIpfsMsg lastMsg = getBetMsgFromTx(lastTx);

	//检测超时
	if(g_tmcg->TimeOut)
	{
		index = g_tmcg->mPlayerIndex[lastMsg.nextBetTxID];
		std::cout << "time out. " << index << std::endl;
		return 6;
	}

	if(!verifyBet(index)) {
		if(index == -1)
    {
			std::cout << "history is ok, game is not over. " << std::endl;
			return 5;
		}
		std::cout << "lie is " << index << " , get your money. ";
		return 6;
	}

	//只剩一个玩家还可以下注
	int betIndex = isGameOver();
	if(betIndex > -1)
	{
		g_tmcg->vWinIndex.push_back(betIndex);
		amount = lastMsg.jackpot;
		if(amount)
		{
			std::cout << "winner is " << g_tmcg->vWinIndex.at(0) << " , others DISCARD, amount is " << amount << std::endl;
			return 7;
		}

		std::cout << "no one bet, all DISCARD, game over, no winner. " << std::endl;
		return 8;
	}

	std::vector<int> pubcard;
	for(size_t j=0; j < g_tmcg->open_flop.size(); j++)
	{
		pubcard.push_back(g_tmcg->open_flop[j].first);
	}
	std::map<int, std::vector<int>> handcard;

	if(pubcard.size()!= 5)
		throw std::runtime_error("pokerhistory error, pubcard.size()!= 5 \n");
	if(g_tmcg->open_hand.size()!= (size_t)g_tmcg->playersize * 2)
		throw std::runtime_error("pokerhistory error, handcard.size()!= playersize * 2 \n");

	int k =0;
	for (int i=0; i<g_tmcg->playersize; i++) {
		if (lastMsg.mPlayerStatus[i] == PS_DISCARD) {
			k += 2;
			continue;
		}
		std::vector<int> vec;
		vec.push_back(g_tmcg->open_hand[k++].first);
		vec.push_back(g_tmcg->open_hand[k++].first);
		handcard[i] = vec;
	}

	int winNum = calculateResult(pubcard, handcard);
	amount = lastMsg.jackpot;

	if (winNum == 1)
	{
		std::cout << "winner is " << g_tmcg->vWinIndex.at(0) << " , amount is " << amount << std::endl;
	}
	else
	{
		std::cout << winNum << " winners, they are: ";
		for (auto &it: g_tmcg->vWinIndex)
		{
			std::cout << it << " ";
		}
		std::cout << ". amount is " << amount / winNum << std::endl;
	}

	std::cout << "-------- pokerhistory end --------" << std::endl;
	return 7;
}


// reply of the requery
size_t req_reply(void *ptr, size_t size, size_t nmemb, void *stream)
{
	std::string *str = (std::string*)stream;
	(*str).append((char*)ptr, size*nmemb);
	return size * nmemb;
}

// HTTP GET
CURLcode curl_get_req(const std::string &url, std::string &response)
{
	// init curl
	CURL *curl = curl_easy_init();
	// res code
	CURLcode res;
	if (curl)
	{
		// set params
		curl_easy_setopt(curl, CURLOPT_URL, url.c_str()); // url
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false); // if want to use https
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, false); // set peer and host verify false
		curl_easy_setopt(curl, CURLOPT_READFUNCTION, NULL);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, req_reply);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
		curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 20); // set transport and time out time
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 20);
		// start req
		res = curl_easy_perform(curl);
	}
	// release curl
	curl_easy_cleanup(curl);
	return res;
}

// HTTP POST
CURLcode curl_post_req(const std::string &url, const std::string &postParams, std::string &filepath, std::string &response)
{
	// init curl
	CURL *curl = curl_easy_init();
	// res code
	CURLcode res;
	if (curl)
	{
		// set params
		curl_easy_setopt(curl, CURLOPT_POST, 1); // post req
		curl_easy_setopt(curl, CURLOPT_URL, url.c_str()); // url
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postParams.c_str()); // params
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false); // if want to use https
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, false); // set peer and host verify false
		curl_easy_setopt(curl, CURLOPT_READFUNCTION, NULL);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, req_reply);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
		curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 20);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 20);

		if (!filepath.empty()) {
			struct curl_httppost* post = NULL;
			struct curl_httppost* last = NULL;
			curl_formadd(&post, &last, CURLFORM_COPYNAME, "uploadfile", CURLFORM_FILE, filepath.c_str(), CURLFORM_END);
			curl_easy_setopt(curl, CURLOPT_HTTPPOST, post);
		}

		// start req
		res = curl_easy_perform(curl);
	}
	// release curl
	curl_easy_cleanup(curl);
	return res;
}


CURLcode curl_bitcoin_req(const char *data, std::string &response, bool frespon)
{
	CURL *curl = curl_easy_init();
	struct curl_slist *headers = NULL;
	CURLcode res;

	const std::string url = "http://127.0.0.1:8332";

	if (curl) {
		// const char *data =
		// "{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", \"method\": \"addnode\", \"params\": [\"192.168.1.88\", \"add\"] }";

		headers = curl_slist_append(headers, "content-type: text/plain;");
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long) strlen(data));
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
		if(frespon) {
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, req_reply);
			curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
		}
		curl_easy_setopt(curl, CURLOPT_USERPWD, "hello:helloworld");
		curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_TRY);
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 20);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 20);
		res = curl_easy_perform(curl);
	}
	curl_easy_cleanup(curl);

	return res;
}


void rpcGetNewAddress()
{
	const char *data = "{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", \"method\": \"getnewaddress\", \"params\": [] }";
	std::string rpcReponse;
	auto res = curl_bitcoin_req(data, rpcReponse, false);
	if (res != CURLE_OK)
		std::cerr << "curl rpcGetNewAddress failed: " + std::string(curl_easy_strerror(res)) << std::endl;
}

void rpcPokerIpfs(const int pokercode, const std::string& ipfsHash)
{
	std::string rpcData = "{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", \"method\": \"pokermatchfinish\", \"params\": [\"" + ipfsHash + "\"] }";
	const char *data = rpcData.c_str();
	std::string rpcReponse;
	auto res = curl_bitcoin_req(data, rpcReponse, true);
	if (res != CURLE_OK)
		std::cerr << "curl rpcPokerIpfs failed: " + std::string(curl_easy_strerror(res)) << std::endl;
	else {
		std::cout << "rpcPokerIpfs success: " << pokercode << "\n" << rpcReponse << std::endl;
	}
}
