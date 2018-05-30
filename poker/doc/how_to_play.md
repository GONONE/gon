How to Play
====================

下面以两个玩家为例,演示如何利用终端玩扑克游戏.

玩游戏前请确保
1. 开启ipfs
2. 钱包余额足够
3. 游戏节点互相连接

游戏中的所有指令都遵循以下格式:

  ./poker-cli  <command>  <params> 

如下注10筹码对应的指令为:

  ./poker-cli pokerbet 10

注意,游戏过程中以下指令请按照顺序执行



 步骤 | 指令                     | 作用
 -----|--------------------------|----------------------------------------------
 1    | getnewaddress            | 产生新地址,如果你获胜,所有筹码都将转入该地址
 2    | pokermatch               | 匹配游戏
 3    | pokeripfs 44 <balance>   | 公开余额,balance为你在游戏中投入的筹码
 -----|--------------------------|---------------------------------------------
 4    | pokeripfs 45             | 发起洗牌,只有第一位玩家可以键入该指令
 5    | pokeripfs 46             | 洗牌:交换公钥
 6    | pokeripfs 47             | 洗牌:验证公钥
 7    | pokeripfs 48             | 洗牌:SSHE,只有第一位玩家可以键入该指令
 8    | pokeripfs 49             | 轮流洗牌
 9    | pokeripfs 50             | 发手牌,每个玩家只能得到自己的手牌
 -----|--------------------------|---------------------------------------------
 10   | pokerbet <stake>         | 下注,stake表示当前下注的筹码
 11   | pokerbet -1              | 弃牌 
 12   | pokercheck               | 让牌,即下注为0
 13   | pokeripfs 51             | 发公共牌,共3轮,第一轮发3张,后两轮每轮1张
 14   | pokeripfs 52             | 公开手牌,游戏结束时使用
 -----|--------------------------|---------------------------------------------
 15   | pokerhistory             | 计算游戏结果
 16   | pokersign <hex>          | 签名交易,只有赢家才能调用,hex为 pokerhistory 的结果
 17   | sendrawtransaction <hex> | 广播交易,只有赢家才能调用,hex为 pokersign 的结果



以下为玩家A,B两人的一局游戏过程

    玩家A            | 玩家B                  
 --------------------|--------------------
  getnewaddress      | getnewaddress           
  pokermatch         | pokermatch           
          
         匹配成功,假设游戏顺序是A,B
         
  pokeripfs 44 100   | pokeripfs 44 200

         A公开100筹码,B公开200筹码
              下面开始洗牌   

  pokeripfs 45       | 
  pokeripfs 46       | pokeripfs 46
  pokeripfs 47       | pokeripfs 47
  pokeripfs 48       |
  pokeripfs 49       | 
                     | pokeripfs 49

             洗牌完毕,发手牌  

  pokeripfs 50       | pokeripfs 50
          
            玩家获得手牌,开始下注
         
  pokerbet 10        | 
                     | pokerbet 10
  pokeripfs 51       | pokeripfs 51
  
           两人各下10, 发第一轮公共牌

  pokerbet 20        | 
                     | pokerbet 20
  pokeripfs 51       | pokeripfs 51

                第二轮公共牌
  
  pokerbet 5         | 
                     | pokerbet 10
  pokerbet 10        | 
                     | pokerbet 5
  pokeripfs 51       | pokeripfs 51

                第三轮公共牌

  pokerbet 10        | 
                     | pokerbet 10

               游戏结束,公开手牌  

  pokeripfs 52       | pokeripfs 52

                  计算结果

  pokerhistory       | pokerhistory
  
                 假如玩家A胜利
 
  pokersign          |
  sendrawtransaction |





