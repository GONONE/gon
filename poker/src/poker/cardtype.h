#ifndef CARD_TYPE_H
#define CARD_TYPE_H

#include <vector>
#include <algorithm>

enum Card_Type
{
		HIGH_CARD,
		ONE_PAIR,
		TWO_PAIR,
		THREE_OF_A_KIND,
		STRAIGHT,
		FLUSH,
		FULLHOUSE,
		FOUR_OF_A_KIND,
		STRAIGHT_FLUSH,
		ROYAL_FLUSH	
};

class CCardType
{
public:
        CCardType();
        ~CCardType();
        
        // 初始化7张牌
        void initCardsGroup(std::vector<int> comm_cards, std::vector<int> hole_cards);
        // 从7张牌中选5张的所有组合并排序
        void toFiveGroups();
        // 计算牌组类型
        Card_Type getCardType(std::vector<int> group);
        // 计算牌组的值
        long long getCardGroupValue(Card_Type type, std::vector<int>& group);
        // 把第一张牌放到最后
        void putFrontCardToBack(std::vector<int>& group);
        // 获取出现次数最多的牌点数(三条或一对才调用)
        int getMostShowNumber(std::vector<int> group);
        // 把一对放到最前面
        void putPairToFront(std::vector<int>& group);
        // 把一对放到最后面
        void putPairToBack(std::vector<int>& group);
        // 处理两对的排序
        void handleTwoPair(std::vector<int>& group);
        // 计算结果
        void calculateResult(std::vector<int> comm_cards, std::vector<int> hole_cards);
        // 仅计算两张手牌
        void calHoleCards(std::vector<int>& hc);

        Card_Type getBestType();
        long long getBestValue();
        std::vector<int> getBestGroup();

private:
        std::vector<int> cards;
        std::vector<std::vector<int>> all_groups;
        
        Card_Type best_card_type;
        long long best_cards_value;
        std::vector<int> best_card_group;
};



#endif
