#include <iostream>
#include "cardtype.h"

CCardType::CCardType()
{
}

CCardType::~CCardType()
{
}

void CCardType::initCardsGroup(std::vector<int> comm_cards, std::vector<int> hole_cards)
{
        for (int cc: comm_cards) 
		{
                cards.push_back(cc);
        }
        for (int hc: hole_cards) 
		{
                cards.push_back(hc);
        }
}

/*
 * 返回花色
 */
int getColor(int card)
{
		return card / 13 + 1;
}

/*
 * 返回点数
 */
int getNumber(int card)
{
		return card % 13 + 2;
}

/*
 * 按照点数从大到小排序
 */
bool card_comp(const int& a,const int& b)
{
        return getNumber(a) > getNumber(b);
}

void CCardType::toFiveGroups()
{
        std::sort(cards.begin(), cards.end(), card_comp); 
        
        int size = cards.size();
        if (size == 5) 
		{
                all_groups.push_back(cards);
                return;
        }

        if (size == 6) 
		{
                for (int i=0; i<size; i++) 
				{
                        std::vector<int> elem;
                        for (int j=0; j<size; j++) 
						{
                                if (j!=i) 
								{
                                        elem.push_back(cards[j]);   
                                }
                        }
                        all_groups.push_back(elem);
                }
                return;
        }

        for (int a=0; a < size-4; ++a) 
		{
                for (int b=a+1; b < size-3; ++b) 
				{
                        for (int c=b+1; c < size-2; ++c) 
						{
                                for (int d=c+1; d < size-1; ++d) 
								{
                                        for (int e=d+1; e < size; ++e) 
										{
                                                std::vector<int> elem;
                                                elem.push_back(cards[a]);
                                                elem.push_back(cards[b]);
                                                elem.push_back(cards[c]);
                                                elem.push_back(cards[d]);
                                                elem.push_back(cards[e]);
                                                all_groups.push_back(elem);
                                        } 
                                } 
                        } 
                } 
        }

}
         
Card_Type CCardType::getCardType(std::vector<int> group)
{
        int flag = 0;    //重复牌数
        int straight = 0;//是否顺子
        int flush = 0;   //是否同花
        Card_Type type = Card_Type::HIGH_CARD;
        
        int size = group.size();
        for (int i = 0; i < size; ++i) 
		{
                for(int j=i+1; j < size; ++j)
				{
                        if (getNumber(group[i]) == getNumber(group[j])) 
						{
                                flag++;         
                        } 
                }
                if (i < size-1 && getColor(group[i]) == getColor(group[i+1])) 
				{
                        flush++;
                }
                if (i < size-1 && getNumber(group[i]) == getNumber(group[i+1]) + 1) 
				{
                        straight++;
                }
        }
                
        if (flush == 4 && straight != 4) 
		{
                flag = 7;
        } else if (flush != 4 && straight == 4) 
		{
                flag = 8;
        } else if (flush == 4 && straight == 4 && getNumber(group[0]) != 14) 
		{
                flag = 9;
        } else if (flush == 4 && straight == 4 && getNumber(group[0]) == 14) 
		{
                flag = 10;
        }

        //A,5,4,3,2
        if (straight == 3 && getNumber(group[0]) == 14 && getNumber(group[1]) == 5) 
		{
                flag = (flush == 4) ? 9 : 8;
        }

        switch (flag) 
		{
			case 10:
					type = Card_Type::ROYAL_FLUSH;
			break;
			case 9:
					type = Card_Type::STRAIGHT_FLUSH;
			break;
			case 8:
					type = Card_Type::STRAIGHT;
			break;
			case 7:
					type = Card_Type::FLUSH;
			break;
			case 6:
					type = Card_Type::FOUR_OF_A_KIND;
			break;
			case 4:
					type = Card_Type::FULLHOUSE;
			break;
			case 3:
					type = Card_Type::THREE_OF_A_KIND;
			break;
			case 2:
					type = Card_Type::TWO_PAIR;
			break;
			case 1:
					type = Card_Type::ONE_PAIR;
			break;
			case 0:
					type = Card_Type::HIGH_CARD;
			break;
        }
        return type;
}
 
int CCardType::getMostShowNumber(std::vector<int> group)
{
        for (size_t i=0; i<group.size(); ++i) 
		{
                if (getNumber(group[i]) == getNumber(group[i+1])) 
				{
                        return getNumber(group[i]);
                }
        }
        return group[0];
}

void CCardType::putPairToFront(std::vector<int>& group)
{
        int number = getMostShowNumber(group);
        std::vector<int> va;
        std::vector<int> vb;
        for (size_t i=0; i<group.size(); ++i) 
		{
                if (getNumber(group[i]) != number)
				{
                        va.push_back(group[i]);
                } 
				else 
				{
                        vb.push_back(group[i]);
                }
        }
        int size = vb.size();
        for (int i=0; i<size; ++i) 
		{
                group[i] = vb[i];
        }      
        for (size_t j=0; j<va.size(); ++j) 
		{
                group[size+j] = va[j];
        }      
}

void CCardType::putFrontCardToBack(std::vector<int>& group)
{
        int temp = group[0];
        for (size_t i=0; i<group.size(); ++i)
		{
                group[i] = group[i+1];
        }
        group[group.size()-1] = temp;
}

void CCardType::putPairToBack(std::vector<int>& group)
{
        int temp1 = group[0];
        int temp2 = group[1];
        for (size_t i=0; i<group.size()-2; ++i) 
		{
                group[i] = group[i+2];
        }
        group[group.size()-2] = temp1;
        group[group.size()-1] = temp2;
}

void CCardType::handleTwoPair(std::vector<int>& group)
{
        //大对子放在前面
        if (getNumber(group[0]) != getNumber(group[1])) 
		{
                putFrontCardToBack(group);
        } 
		else if (getNumber(group[1]) != getNumber(group[2]) && getNumber(group[2]) != getNumber(group[3])) 
		{
                int temp = group[2];
                for (size_t i=2; i<group.size(); ++i) 
				{
                        group[i] = group[i+1];
                }
                group[group.size()-1] = temp;
        }
}

long long getValue(Card_Type type, std::vector<int> group)
{
        long long value = 10000000000;
        long long res = 0;
        for (size_t i=0; i<group.size(); ++i) 
		{ 
                if(i == group.size()-1){
                        res += getNumber(group[i]);
                } 
				else 
				{
                        res = (res + getNumber(group[i])) * 100;
                }
        }

        res += type * value;
        return res;
}

long long CCardType::getCardGroupValue(Card_Type type, std::vector<int>& group)
{
        switch (type) 
		{
			case Card_Type::STRAIGHT:
					//A,5,4,3,2
					if (getNumber(group[0]) == 14 && getNumber(group[1]) == 5) 
					{
							putFrontCardToBack(group);
					}
			break;
			case Card_Type::FOUR_OF_A_KIND:
					//4条放前面
					if (getNumber(group[0]) != getNumber(group[1])){
							putFrontCardToBack(group);
					}   
			break;
			case Card_Type::FULLHOUSE:
					//3条放前面,1对放后面
					if (getNumber(group[0]) == getNumber(group[1]) && getNumber(group[1]) != getNumber(group[2]))
					{
							putPairToBack(group);
					}   
			break;
			case Card_Type::ONE_PAIR:
			case Card_Type::THREE_OF_A_KIND:
					putPairToFront(group);
			break;
			case Card_Type::TWO_PAIR:
					handleTwoPair(group);
			break;
			case Card_Type::STRAIGHT_FLUSH:
			case Card_Type::ROYAL_FLUSH:
			case Card_Type::FLUSH:
			case Card_Type::HIGH_CARD:
			break;
        }
        return getValue(type, group);
}

void CCardType::calculateResult(std::vector<int> comm_cards, std::vector<int> hole_cards)
{
        all_groups.clear();
		cards.clear();
	    best_card_type = Card_Type::HIGH_CARD;
		best_cards_value = -1;
		best_card_group.clear();

        if (comm_cards.size() == 0) 
		{
                calHoleCards(hole_cards);
                return;
        }

        initCardsGroup(comm_cards, hole_cards);
        toFiveGroups();
        
        Card_Type type = Card_Type::HIGH_CARD;
        long long value = 0;
        
        for (std::vector<int> group : all_groups) 
		{
                type = getCardType(group);
                value = getCardGroupValue(type, group);
                if(best_cards_value < value)
				{
                        best_card_type = type;
                        best_cards_value = value;
                        best_card_group = group;
                }
        }
}

void CCardType::calHoleCards(std::vector<int>& hc)
{
	    best_card_type = Card_Type::HIGH_CARD;
		best_cards_value = -1;
		best_card_group.clear();
        
        std::sort(hc.begin(), hc.end(), card_comp); 
        int c1 = hc[0];
        int c2 = hc[1];
        if (getNumber(c1) == getNumber(c2) )
		{
                best_card_type = Card_Type::ONE_PAIR;
        }

        best_cards_value = best_card_type * 10000 + getNumber(c1)*100 + getNumber(c2);
        best_card_group.swap(hc);
        std::cout << "CCardType::calHoleCards::" << best_cards_value << std::endl;
}

Card_Type CCardType::getBestType()
{
        return best_card_type;
}

long long CCardType::getBestValue()
{
        return best_cards_value;
}

std::vector<int> CCardType::getBestGroup()
{   
        return best_card_group;
}

