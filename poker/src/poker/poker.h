#ifndef POKER_H
#define POKER_H
#include <iostream>
#include <libTMCG.hh>

#include "addrdb.h"
#include "addrman.h"
#include "amount.h"
#include "bloom.h"
#include "compat.h"
#include "hash.h"
#include "limitedmap.h"
#include "netaddress.h"
#include "policy/feerate.h"
#include "protocol.h"
#include "random.h"
#include "streams.h"
#include "sync.h"
#include "uint256.h"
#include "threadinterrupt.h"
#include "cardtype.h"
#include "script/script.h"
#include "primitives/transaction.h"
#include "utilstrencodings.h"
#include "net.h"
#include "json.hpp"
#include "curl/curl.h"

#include <memory>

using json = nlohmann::json;
class tmcg;

extern std::unique_ptr<tmcg> g_tmcg;
extern std::map<std::string, std::string> gMapAddress;
typedef std::pair<int,int> IndexBalance;
#define HANDCARDSIZE 2
#define FLOPCARDSIZE 5

enum PokerCode
{
	PC_NODE_INDEX = 38,
	PC_POKER_MATCH_FINISH = 39,
	PC_POKER_MATCH = 40,
	PC_NEW_ADDRESS = 41,
	PC_CREATE_ADDRESS = 42,
	PC_POKER_ADDRESS = 43,
	PC_POKER_BALANCE = 44,
	PC_POKER_HANDLE = 45,
	PC_POKER_PUBKEY = 46,
	PC_POKER_PUBKEY_VERIFY = 47,
	PC_POKER_SSH = 48,
	PC_POKER_SHUFFLE = 49,
	PC_POKER_HAND_CARD = 50,
	PC_POKER_FLOP_CARD = 51,
	PC_POKER_OPEN_HAND = 52,

	PC_POKER_DEPOSIT = 70,
	PC_POKER_BET = 80,
	PC_POKER_HISTORY = 90,
};


enum PlayerStatus
{
	PS_DEFAULT = 0,
	PS_DISCARD = 1,//弃牌
	PS_ALLIN = 2,//全下
	PS_WINER = 3,//赢家
	PS_LIE = 4,//作弊
};

struct MsgNode
{
	MsgNode():MaxBet(0),CurBet(0),NextIndex(-1),Jackot(0),FromIndex(0),PublicIndex(0), FromIp(std::string()),PreTxid(std::string())
	{
		Balance.clear();
		PlayerStatus.clear();
		HasBet.clear();
		PublicCard.clear();
		IsOver =false;
	}
	int MaxBet,CurBet,NextIndex,Jackot;
	int FromIndex,PublicIndex;
	std::map<int,int> Balance;
	std::map<int,int> PlayerStatus;
	std::map<int,int> HasBet;
	std::vector<int> PublicCard;
	std::string FromIp,PreTxid;
	bool IsOver;
};


struct MsgTimeOut
{
	MsgTimeOut():Ip(std::string()),Txid(std::string()), NextIndex(-1){}
	std::string Ip;
	std::string Txid;
	int NextIndex;
};


//ipfs
struct BetIpfsMsg
{
	std::string curBetTxID;
	std::string nextBetTxID;
	int curBet;
	int maxBet;
	int jackpot;
	int publicIndex;
	bool fGameOver;
	bool fFlopCard;
	std::map<std::string, int> mHasBet;
	std::map<std::string, int> mBalance;
	std::map<int, int> mPlayerStatus;
};


//Portgas
extern const int DECKSIZE; //牌
extern const int FLOPSIZE; //公共牌
extern const int HANDSIZE; //手牌
extern std::vector< CTransaction> vTxIpVerify;
extern std::vector< CTransaction> vTxNewAddressVerify;
extern std::vector< CTransaction> vTxPublicAddressVerify;
extern std::vector< CTransaction> vTxPokerBalanceVerify;
extern std::vector< CTransaction> vTxPokerHandleVerify; //44
extern std::vector< CTransaction> vTxPokerDlogVerify; //45
extern std::vector< CTransaction> vTxPokerPubkeyVerify; //46
extern std::vector< CTransaction> vTxPokerSshVerify; //47
extern std::vector< CTransaction> vTxPokerShuffleVerify; //48
extern std::vector< CTransaction> vTxPokerHandleCardVerify; //51
extern std::vector< CTransaction> vTxPokerFlopCardVerify; //53
extern std::vector< CTransaction> vTxPokerOpenHandVerify; //55
extern std::vector< CTransaction> vTxDepositVerify; //70

//ipfs
extern std::vector<CTransaction> vTxBetVerify; 				  //保存所有下注交易
extern std::multimap<std::string, CTransaction> vTxBetPlayer; //保存每个人的下注交易


extern std::vector< CTransaction> vTxTimeOut; //
extern std::vector< MsgTimeOut > vMsgTimeOut; //

extern std::map<std::string, CTransaction> vTxDepositPlayer;

extern std::vector< CTransaction > vTxMatchPlayer;

bool verifyBalcnce(std::string& res, int& lieIndex);

bool verifyBetScript(MsgNode& VerifyMsg, CTransaction& ct);

bool verifyBetMsgNode(MsgNode& PreTxMsg, MsgNode& VerifyMsg);

bool verifyBet(std::string& res, int& lieIndex);

int pokerhistory(int& index, int& amount);

int calculateResult(std::vector<int> pubcard, std::map<int, std::vector<int>> handcard);

void saveTimeOutMsg(const std::string &ip,const std::string &txid);

bool checkBetMsg(MsgNode &VerifyMsg,MsgNode &PreTxMsg);

int getBetNum(MsgNode &betMsg);

int getNextIndex(MsgNode &betMsg);

// curl
size_t req_reply(void *ptr, size_t size, size_t nmemb, void *stream);
CURLcode curl_get_req(const std::string &url, std::string &response);
CURLcode curl_post_req(const std::string &url, const std::string &postParams, std::string &filepath, std::string &response);
CURLcode curl_bitcoin_req(const char *data, std::string &response);
void rpcGetNewAddress();
void rpcPokerIpfs(const int pokercode, const std::string& ipfsHash);
void ipfsCatFile(std::string & hash, std::string & getResponseStr);
int isGameOver();
int isGameOver(BetIpfsMsg curBetMsg);
void getPokerBetData(const json &jsonMsg, BetIpfsMsg &curBetMsg);
bool verifyBetIpfsMsg(BetIpfsMsg& preBetMsg, BetIpfsMsg& curBetMsg, std::string &error);

class tmcg
{

public:
	tmcg();

	~tmcg();

	void PublishGroup();//产生全局句柄(主动)

	const std::string getVtmfHandle();//返回句柄(仅在主动产生情况下被调用)

	void PublishGroup(std::string &vtmf);//初始化全局句柄(被动)

	bool VTMF_dlog();

	void createPublicKey(std::string &pubkey);

	bool verifyPubKey(const std::string &pubkey);//验证公钥

	void updatePubkey();//更新公钥

	bool createSshe();// 创建sshe(主动)

	void createSshe(std::string &sshestr);// 创建sshe(被动)

	void educeSshe(std::string &sshekey);//导出sshe(主动)

	bool verifySsheKey();// 验证sshe(被动)

	void createCard();

	std::string shuffleCard();//洗牌(主动)

	bool verifyShuffleCard(std::string &shuffleCardMsg);//验证洗牌(被动)

	void createHandCard();// 为每个人创建一副手牌

	std::string proveCardSecret(const int m,const int k);// 产生第m个人第k张手牌消息

	void selfCardSecret(const int m,const int k);

	void selfFlopSecret(const int k);

	bool verifyCardSecret(const int m,const int k,std::string& handmsg);// 验证手牌(仅验证自己的)

	void saveHandCard(const int m,const int k);//验证通过后保存手牌

	void createFlopCard();//创建公共牌

	std::string proveFlopSecret(const int k) ;

///////////////////////////////////////////		hand_flop	start
	std::string proveHandFlopSecret(const int k) ;

	bool verifyHandFlopSecret(const int k, std::string &msg);

	void selfHandFlopSecret(const int k);

	void saveHandFlopCard(const int i);

///////////////////////////////////////////		hand_flop	end
	bool verifyFlopSecret(const int k, std::string &msg);

	void saveFlopCard(const int i);

	void showFlopCard();

	bool isRecvVerify();

	void zeroRecvVerify();


	std::string showPoker(int type);
	int showPokerNumber(int type);
	void showPlayerInfo();
	void initBetIpfsMsg(BetIpfsMsg &msg);
	void printBetIpfsMsg(BetIpfsMsg& msg);
	bool IsFlopOpen(BetIpfsMsg& msg);
	void clearPoker();

public:

	std::stringstream 		vtmf_str;
	BarnettSmartVTMF_dlog 	*vtmf1;
	SchindelhauerTMCG 		*tmcgOne;
	BarnettSmartVTMF_dlog 	*vtmfOne;
	GrothVSSHE *vsshe;
	TMCG_Stack<VTMF_Card> s;
	TMCG_Stack<VTMF_Card> hand[7];
	TMCG_OpenStack<VTMF_Card> private_hand;
	TMCG_Stack<VTMF_Card> flop;
	TMCG_OpenStack<VTMF_Card> open_flop;
	TMCG_OpenStack<VTMF_Card> open_hand;
	TMCG_Stack<VTMF_Card> hand_flop;
	bool isOne;
	int countVerify;
	int countRecv;

	bool creaetpukey;
	std::string selfip;
	std::map<std::string, int> nodeIndexMap;

	std::map<int, std::vector<std::string>> selfhandcard;
	std::vector<std::string> selfflopcard;
	std::vector<std::string> selfopenhand;

	std::map<std::string,MsgNode> RecvMsg;
	std::map<std::string,IndexBalance>PokerBalance;// init balance  // desroty
	MsgNode CurMsg;
	std::string FromIp;
	int PublicIndex;
	bool IsOver;
	bool TimeOut;
	int TxChainHeight;
	std::string TxTimeOutHash;


	int myindex;
	int playersize;
	std::string selfaddress;
	std::string pokeraddress;
	std::string matchTxID;   	// 匹配txid
	std::string matchTableID;	// tableid
	bool fMatchNode = false; 	// 是否匹配节点
	std::string nextMatchNode = "120.27.232.146"; // 下一个匹配节点

	std::string selfpubkey;
	std::string selfsshe;
	std::string selfshuffle;

	bool fAllPubkeyVerify = false;         // 是否验证其它人公钥成功
	bool fMyPubkeyVerify = false;     	   // 是否其它人验证我的公钥成功
	std::map<std::string, int> mPlayerIndex;	 // txid index
	std::map<int, std::string> mPlayerTxid;		 // index txid
	std::map<std::string, std::string> mMatchAddress;     // 所有玩家的地址
	std::map<std::string, std::string> mPokerAddress;     // 所有玩家的poker地址
	std::map<std::string, int> mPokerBalance;             // 所有玩家的初始余额
	std::map<std::string, std::string> mPubkeyVerify;     // 保存其它玩家公钥

	typedef std::map<int, std::string> handCardMsg;       // hand card
	typedef std::vector<std::string> VerifyCardMsg;       // flop card
	std::map<std::string, handCardMsg> mHandCardVerify;   // 保存我的手牌消息
	std::map<std::string, VerifyCardMsg> mFlopCardVerify; // 保存公共牌消息
	std::map<std::string, VerifyCardMsg> mOpenFlopVerify; // 保存所有玩家手牌消息

	std::map<std::string, CTransaction> mPokerBalanceTx;  // 保存所有玩家初始余额交易

	int nextShuffleIndex = 0;   // 下个洗牌的人
	std::string nextBetTxID;    // 下一个下注的人
	BetIpfsMsg gBetIpfsMsg;     // 保存最新的下注消息内容
	bool fPokerAddressVerify = false; // 是否验证所有人pokeraddress通过
	bool fSendFlopCardTx = false; // 我是否发送过公共牌的交易: 当需要发公共牌是置为true, 发过交易后置为false
	bool fPubkeyVerTx = false;    // 是否已经发送过PC_POKER_PUBKEY_VERIFY交易
	bool fVerifySSHE = false;     // 是否验证过sshe
	bool fHandCardTx = false;     // 是否已经发送过PC_POKER_HAND_CARD交易
	bool fOpenHandTx = false;     // 是否已经发送过PC_POKER_OPEN_HAND交易
	bool fVerifyFlopCard = false; // 是否验证过公共牌交易

	std::vector<int> vWinIndex; // 赢家
	int lieIndex;               // 作弊的人
	
	// Egret
	std::vector<std::string> vShuffleMsg;  // 洗牌交易比sshe先到达
	std::vector<std::string> vHandCardMsg; // 手牌交易比最后一次洗牌交易先到达
	std::vector<std::string> vFlopCardMsg; // 公共牌交易比下注交易先到达
	
	bool fDiscardMsg = false;
	
	std::map<int, int> mPokerTypes;
	std::map<int, std::vector<int>> mBestGroups;
};

#endif
